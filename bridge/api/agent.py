"""Agent API `/v1` (bearer keys). Every POST needs an Idempotency-Key. Errors are problem+json."""
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response

from ..domain import approvals, artifacts, inbox, messages, statemachine as sm, tasks
from ..domain.common import message_dict, task_dict  # noqa: F401
from ..errors import Problem
from ..safety import content_disposition
from ..util import Budget, iso, now_ms
from . import schemas as S
from .deps import Principal, WriteCtx, bridge, require, write_ctx

router = APIRouter(prefix="/v1", responses={"default": {"model": S.ProblemOut, "description": "problem+json error"}})

TasksRead = Annotated[Principal, Depends(require("tasks:read"))]
TasksWrite = Annotated[WriteCtx, Depends(write_ctx("tasks:write"))]
InboxRead = Annotated[Principal, Depends(require("inbox:read"))]
InboxWrite = Annotated[WriteCtx, Depends(write_ctx("inbox:read"))]
ApprRead = Annotated[Principal, Depends(require("approvals:request"))]
ApprWrite = Annotated[WriteCtx, Depends(write_ctx("approvals:request"))]


def _posted(ctx: WriteCtx, res: dict):
    out = {"message": message_dict(res["message"]), "task": task_dict(res["task"]), "deduplicated": res["deduplicated"]}
    if res["deduplicated"]:
        return out, 200, {"Bridge-Deduplicated": "true"}
    return out, 201, {}


def _post(ctx: WriteCtx, task_id: str, mtype: str, body: S.Body, in_reply_to: str | None = None):
    limits = ctx.b.settings.limits
    return ctx.run(lambda c: _posted(ctx, messages.post_message(c, ctx.actor, task_id, mtype, body.model_dump(),
                                                                 in_reply_to, limits)))


@router.get("/health", tags=["meta"])
def health(request: Request) -> dict:
    with bridge(request).db.read() as conn:
        conn.execute("SELECT 1").fetchone()
    return {"ok": True}


@router.get("/me", tags=["meta"], response_model=S.MeOut)
def me(request: Request, p: Annotated[Principal, Depends(require("tasks:read"))]):
    lim = bridge(request).settings.limits
    return {"agent_id": p.actor.id, "party_id": p.actor.party_id, "key_id": p.key_id, "scopes": sorted(p.scopes),
            "paused": p.paused, "poll_after_s": bridge(request).settings.poll_after_s,
            "limits": {"per_key_per_min": lim.per_key_per_min, "per_key_writes_per_min": lim.per_key_writes_per_min,
                       "max_body_bytes": lim.max_body_bytes, "artifact_max_bytes": lim.artifact_max_bytes,
                       "max_clarification_rounds": lim.max_clarification_rounds},
            "server_time": iso(now_ms())}


# ---- tasks ----

@router.post("/tasks", status_code=201, response_model=S.TaskCreatedOut, tags=["tasks"])
def create_task(body: S.TaskCreate, ctx: TasksWrite):
    data = body.model_dump()
    data["refs"] = [r for r in data["refs"]]
    return ctx.run(lambda c: tasks.create(c, ctx.actor, data, ctx.b.settings.limits), status=201)


@router.get("/tasks", response_model=S.TaskListOut, tags=["tasks"])
def list_tasks(request: Request, p: TasksRead,
               role: Annotated[str | None, Query(pattern="^(originator|responsible)$")] = None,
               state: S.State | None = None, category: str | None = Query(None, max_length=40),
               project: str | None = Query(None, max_length=100), q: str | None = Query(None, max_length=200),
               updated_since_ms: int | None = Query(None, ge=0),
               limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=100000)):
    b = bridge(request)
    budget = Budget(b.settings.limits.max_response_bytes)
    with b.db.read() as conn:
        rows = tasks.list_tasks(conn, p.actor, role=role, state=state, category=category, project=project,
                                q=q, updated_since=updated_since_ms, limit=limit, offset=offset, budget=budget)
    return _task_page(rows, offset, budget)


def _task_page(rows: list, offset: int, budget: Budget) -> dict:
    """`next_offset` is set when the page stopped at the byte cap; fetch again from there."""
    return {"tasks": rows, "truncated": budget.truncated,
            "next_offset": offset + len(rows) if budget.truncated else None}


@router.get("/tasks/search", response_model=S.TaskListOut, tags=["tasks"])
def search_tasks(request: Request, p: TasksRead, q: str = Query(min_length=2, max_length=200),
                 state: S.State | None = None, limit: int = Query(50, ge=1, le=100),
                 offset: int = Query(0, ge=0, le=1000)):
    """Search tasks by title and description, and by message text within the most recently updated tasks
    (`limits.search_scan_tasks`, default 500). Offset is capped at 1000."""
    b = bridge(request)
    budget = Budget(b.settings.limits.max_response_bytes)
    with b.db.read() as conn:
        rows = tasks.list_tasks(conn, p.actor, q=q, state=state, limit=limit, offset=offset, search_messages=True,
                                budget=budget, scan_tasks=b.settings.limits.search_scan_tasks)
    return _task_page(rows, offset, budget)


@router.get("/tasks/{task_id}", response_model=S.TaskDetailOut, tags=["tasks"])
def get_task(request: Request, task_id: str, p: TasksRead):
    """Up to the last 50 messages; fewer if the response would pass ~1 MiB (`messages_truncated`)."""
    b = bridge(request)
    with b.db.read() as conn:
        return tasks.get_detail(conn, p.actor, task_id, max_bytes=b.settings.limits.max_response_bytes)


@router.get("/tasks/{task_id}/history", response_model=S.HistoryOut, tags=["tasks"])
def get_history(request: Request, task_id: str, p: TasksRead, after_seq: int = Query(0, ge=0),
                limit: int = Query(200, ge=1, le=500), include_bodies: bool = False):
    """Timeline page. Messages appear without `body` (with `body_bytes`) unless `include_bodies=true`.
    A page stops at ~1 MiB: while `has_more`, continue with `after_seq=next_after_seq`."""
    b = bridge(request)
    with b.db.read() as conn:
        return tasks.history(conn, p.actor, task_id, after_seq, limit, include_bodies=include_bodies,
                             max_bytes=b.settings.limits.max_response_bytes)


@router.post("/tasks/{task_id}/accept", status_code=201, response_model=S.MessagePostedOut, tags=["tasks"])
def accept_task(task_id: str, body: S.AcceptIn, ctx: TasksWrite):
    """Responsible agent accepts (TASK_ACCEPTED; proposed -> accepted)."""
    return _post(ctx, task_id, "TASK_ACCEPTED", body.body)


@router.post("/tasks/{task_id}/reject", status_code=201, response_model=S.MessagePostedOut, tags=["tasks"])
def reject_task(task_id: str, body: S.ReasonIn, ctx: TasksWrite):
    """Responsible agent rejects (TASK_REJECTED; -> rejected)."""
    return _post(ctx, task_id, "TASK_REJECTED", body.body.model_copy(update={"text": body.reason}))


@router.post("/tasks/{task_id}/decision-request", status_code=201, response_model=S.MessagePostedOut, tags=["tasks"])
def request_decision(task_id: str, body: S.ReasonIn, ctx: TasksWrite):
    """Escalate to the humans (DECISION_REQUEST; -> needs_human)."""
    return _post(ctx, task_id, "DECISION_REQUEST", body.body.model_copy(update={"text": body.reason}))


@router.post("/tasks/{task_id}/messages", status_code=201, response_model=S.MessagePostedOut, tags=["messages"])
def post_message(task_id: str, body: S.MessageIn, ctx: TasksWrite):
    """Post any agent message type. 200 + `Bridge-Deduplicated: true` returns the original of a duplicate."""
    return _post(ctx, task_id, body.type, body.body, body.in_reply_to)


@router.get("/tasks/{task_id}/messages", response_model=S.MessagePageOut, tags=["messages"])
def list_messages(request: Request, task_id: str, p: TasksRead, after_seq: int = Query(0, ge=0),
                  limit: int = Query(100, ge=1, le=200)):
    """Messages with bodies, oldest first. A page stops at ~1 MiB: while `has_more`, continue from `next_after_seq`."""
    b = bridge(request)
    with b.db.read() as conn:
        return tasks.messages_page(conn, p.actor, task_id, after_seq, limit, b.settings.limits.max_response_bytes)


@router.post("/tasks/{task_id}/transition", response_model=S.TaskStateOut, tags=["tasks"])
def transition(task_id: str, body: S.TransitionIn, ctx: TasksWrite):
    def fn(c):
        t = tasks.writable_task(c, ctx.actor, task_id)
        return {"task": task_dict(sm.apply(c, ctx.actor, t, body.to, tasks.role_of(t, ctx.actor), body.reason,
                                           body.expected_version))}
    return ctx.run(fn)


# ---- artifacts ----

@router.post("/tasks/{task_id}/artifacts", status_code=201, response_model=S.ArtifactCreatedOut, tags=["artifacts"],
             openapi_extra={"requestBody": {"required": True, "content": {
                 t: {"schema": {"type": "string", "format": "binary"}} for t in sorted(artifacts.ALLOWED_TYPES)}}})
def upload_artifact(task_id: str, request: Request, ctx: TasksWrite,
                    filename: str = Query(min_length=1, max_length=200), note: str = Query("", max_length=2000)):
    """Raw request body = file bytes; Content-Type = the artifact type. Also posts ARTIFACT_SUBMITTED."""
    ctype = request.headers.get("content-type", "")
    return ctx.run(lambda c: artifacts.upload(c, ctx.actor, task_id, filename, ctype, ctx.raw_body, note,
                                              ctx.b.settings.limits), status=201)


@router.get("/tasks/{task_id}/artifacts", tags=["artifacts"])
def list_artifacts(request: Request, task_id: str, p: TasksRead) -> dict:
    with bridge(request).db.read() as conn:
        return {"artifacts": artifacts.list_for_task(conn, p.actor, task_id)}


@router.get("/artifacts/{artifact_id}", tags=["artifacts"],
            responses={200: {"content": {"application/octet-stream": {}}, "description": "file bytes (attachment)"}})
def download_artifact(request: Request, artifact_id: str, p: TasksRead):
    with bridge(request).db.read() as conn:
        a = artifacts.download(conn, p.actor, artifact_id)
    return attachment_response(a)


def attachment_response(a) -> Response:
    return Response(bytes(a["data"]), media_type=a["content_type"], headers={
        "Content-Disposition": content_disposition(a["filename"]), "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "sandbox; default-src 'none'", "X-Artifact-Sha256": a["sha256"]})


# ---- inbox ----

@router.get("/inbox", response_model=S.InboxOut, tags=["inbox"])
def get_inbox(request: Request, p: InboxRead, cursor: int | None = Query(None, ge=0),
              limit: int = Query(50, ge=1, le=100)):
    """Events after `cursor` (default: your acked cursor) plus your pending-approval count, in one request.
    Honour `poll_after_s`; ack only non-empty pages. A page also stops at ~1 MiB (`has_more` = fetch again now)."""
    b = bridge(request)
    with b.db.read() as conn:
        page = inbox.fetch(conn, p.actor.id, cursor, limit, b.settings.poll_after_s,
                           b.settings.limits.max_response_bytes)
    with b.db.write() as conn:
        inbox.record_poll(conn, p.actor.id)
    return JSONResponse(page)


@router.post("/inbox/ack", response_model=S.AckOut, tags=["inbox"])
def ack_inbox(body: S.AckIn, ctx: InboxWrite):
    return ctx.run(lambda c: {"acked_seq": inbox.ack(c, ctx.actor.id, body.cursor)})


# ---- approvals ----

def _apr(ctx_or_req, a) -> dict:
    return {"approval": approvals.approval_dict(a, ctx_or_req.settings.public_origin)}


@router.post("/tasks/{task_id}/approvals", status_code=201, response_model=S.ApprovalWrapOut, tags=["approvals"])
def request_approval(task_id: str, body: S.ApprovalIn, ctx: ApprWrite):
    """Ask your own human for a decision on an exact action payload. You can never decide it yourself."""
    return ctx.run(lambda c: _apr(ctx.b, approvals.request(c, ctx.actor, task_id, body.kind, body.summary, body.action,
                                                         body.expires_in_s, ctx.b.settings.limits)), status=201)


@router.get("/approvals", response_model=S.ApprovalListOut, tags=["approvals"])
def list_approvals(request: Request, p: ApprRead, state: str | None = Query(None, max_length=20),
                   task_id: str | None = Query(None, max_length=64)):
    b = bridge(request)
    budget = Budget(b.settings.limits.max_response_bytes)
    with b.db.read() as conn:
        rows = approvals.list_own(conn, p.actor, state, task_id, budget, b.settings.public_origin)
    return {"approvals": rows, "truncated": budget.truncated}


@router.get("/approvals/{approval_id}", response_model=S.ApprovalWrapOut, tags=["approvals"])
def get_approval(request: Request, approval_id: str, p: ApprRead):
    b = bridge(request)
    with b.db.read() as conn:
        return _apr(b, approvals.get_own(conn, p.actor, approval_id))


@router.post("/approvals/{approval_id}/consume", response_model=S.ApprovalWrapOut, tags=["approvals"])
def consume_approval(approval_id: str, body: S.ConsumeIn, ctx: ApprWrite):
    """Claim an approved approval exactly once, immediately before acting. 409 otherwise."""
    return ctx.run(lambda c: _apr(ctx.b, approvals.consume(c, ctx.actor, approval_id, body.action_sha256)))


@router.post("/approvals/{approval_id}/cancel", response_model=S.ApprovalWrapOut, tags=["approvals"])
def cancel_approval(approval_id: str, ctx: ApprWrite):
    return ctx.run(lambda c: _apr(ctx.b, approvals.cancel(c, ctx.actor, approval_id)))


__all__ = ["router", "attachment_response", "Problem"]
