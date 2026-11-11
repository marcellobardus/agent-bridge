"""Artifacts: small files stored as SQLite BLOBs, type allowlist, magic-byte checks, size and quota limits."""
import json

from ..errors import Problem, not_found
from ..safety import sanitize_filename
from ..util import iso, new_id, now_ms, sha256_hex
from .common import Actor, audit, log_task
from .tasks import visible_task, writable_task

ALLOWED_TYPES = {
    "text/plain", "text/markdown", "text/csv", "text/x-diff", "application/json",
    "application/pdf", "image/png", "image/jpeg", "application/zip", "application/gzip",
}
_MAGIC = {"application/pdf": b"%PDF-", "image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff",
          "application/zip": b"PK\x03\x04", "application/gzip": b"\x1f\x8b"}


def artifact_meta(a) -> dict:
    return {"id": a["id"], "filename": a["filename"], "content_type": a["content_type"], "size": a["size"],
            "sha256": a["sha256"], "uploaded_by": {"kind": a["uploader_kind"], "id": a["uploader_id"]},
            "created_at": iso(a["created_at"])}


def validate_content(content_type: str, data: bytes, limits) -> str:
    ctype = (content_type or "").split(";")[0].strip().lower()
    if ctype not in ALLOWED_TYPES:
        raise Problem(415, "unsupported_media_type", f"allowed types: {', '.join(sorted(ALLOWED_TYPES))}")
    if not data:
        raise Problem(422, "empty_artifact", "artifact is empty")
    if len(data) > limits.artifact_max_bytes:
        raise Problem(413, "artifact_too_large", f"max {limits.artifact_max_bytes} bytes per artifact")
    magic = _MAGIC.get(ctype)
    if magic and not data.startswith(magic):
        raise Problem(422, "content_mismatch", f"content does not look like {ctype}")
    if ctype.startswith("text/") or ctype == "application/json":
        try:
            text = data.decode("utf-8")
            if ctype == "application/json":
                json.loads(text)
        except ValueError:
            raise Problem(422, "content_mismatch", f"content is not valid {ctype}") from None
    return ctype


def upload(conn, actor: Actor, task_id: str, filename: str, content_type: str, data: bytes, note: str, limits) -> dict:
    """Store the artifact and post the matching ARTIFACT_SUBMITTED message in the same transaction.
    Every message check and loop guard runs before the blob is inserted, so a refused upload stores nothing."""
    from .messages import finish, prepare
    writable_task(conn, actor, task_id)
    ctype = validate_content(content_type, data, limits)
    used_task = conn.execute("SELECT coalesce(sum(size),0) FROM artifacts WHERE task_id=?", (task_id,)).fetchone()[0]
    if used_task + len(data) > limits.artifact_task_quota_bytes:
        raise Problem(413, "artifact_quota_exceeded", "per-task artifact quota exceeded")
    used_agent = conn.execute("SELECT coalesce(sum(size),0) FROM artifacts WHERE uploader_id=?",
                              (actor.id,)).fetchone()[0]
    if used_agent + len(data) > limits.artifact_agent_quota_bytes:
        raise Problem(413, "artifact_quota_exceeded", "per-agent artifact quota exceeded")
    used_all = conn.execute("SELECT coalesce(sum(size),0) FROM artifacts").fetchone()[0]
    if used_all + len(data) > limits.artifact_global_quota_bytes:
        raise Problem(413, "artifact_quota_exceeded", "global artifact quota exceeded")
    prep = prepare(conn, actor, task_id, "ARTIFACT_SUBMITTED", {"text": note, "data": {}, "refs": []}, None, limits,
                   pending_artifact=True)
    aid, digest, name = new_id("art"), sha256_hex(data), sanitize_filename(filename)
    conn.execute("INSERT INTO artifacts (id, task_id, uploader_kind, uploader_id, filename, content_type, size, sha256,"
                 " data, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (aid, task_id, actor.kind, actor.id, name, ctype, len(data), digest, data, now_ms()))
    log_task(conn, task_id, actor, "artifact", detail={"artifact_id": aid, "sha256": digest, "size": len(data)})
    audit(conn, actor, "artifact.upload", "artifact", aid, {"task_id": task_id, "sha256": digest, "size": len(data)})
    a = conn.execute("SELECT id, filename, content_type, size, sha256, uploader_kind, uploader_id, created_at"
                     " FROM artifacts WHERE id=?", (aid,)).fetchone()
    body = {"text": note, "data": {"artifact_ids": [aid], "artifacts": [artifact_meta(a)]}, "refs": []}
    res = finish(conn, actor, prep, body)
    return {"artifact": artifact_meta(a), "message_id": res["message"]["id"]}


def download(conn, actor: Actor, artifact_id: str):
    a = conn.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
    if a is None:
        raise not_found("artifact")
    visible_task(conn, actor, a["task_id"])  # 404 for non-participants
    return a


def list_for_task(conn, actor: Actor, task_id: str) -> list[dict]:
    visible_task(conn, actor, task_id)
    rows = conn.execute("SELECT id, filename, content_type, size, sha256, uploader_kind, uploader_id, created_at"
                        " FROM artifacts WHERE task_id=? ORDER BY created_at", (task_id,))
    return [artifact_meta(a) for a in rows]
