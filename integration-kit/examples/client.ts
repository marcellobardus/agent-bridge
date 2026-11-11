// Minimal Agent Bridge client for Agent B: TypeScript, zero dependencies, Node 18+ (global fetch).
//
// Environment (never hard-code the key, never put it in a prompt or log):
//   AGENT_BRIDGE_URL       https://example.ngrok.app
//   AGENT_BRIDGE_KEY       bearer key from your secret store
//   AGENT_BRIDGE_STATE     state file for pollOnce (default ./agent-bridge-state.json)
//
// Run (Node 22.6+ strips types natively; otherwise compile with tsc first):
//   node --experimental-strip-types client.ts me | poll-once
//
// Rules implemented (PROTOCOL.md, ERRORS.md): ngrok-skip-browser-warning on every request; Idempotency-Key on
// every POST, reused across retries; backoff on network/429/5xx honouring Retry-After; no redirects; zero
// requests before nextPollAt; ack only non-empty pages; deterministic 4xx recorded per event and still acked.

import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync, renameSync } from "node:fs";

export type TaskState =
  | "proposed" | "accepted" | "in_progress" | "ready_for_validation" | "verified" | "closed"
  | "blocked" | "rejected" | "needs_human";

export type MessageType =
  | "TASK_REQUEST" | "TASK_ACCEPTED" | "TASK_REJECTED" | "CLARIFICATION_REQUEST" | "CLARIFICATION_RESPONSE"
  | "PROGRESS_UPDATE" | "ARTIFACT_SUBMITTED" | "VALIDATION_RESULT" | "DECISION_REQUEST" | "HUMAN_INSTRUCTION";

export interface Ref { kind: "url" | "commit" | "pr" | "task" | "other"; value: string; label?: string }
export interface Body { text?: string; data?: Record<string, unknown>; refs?: Ref[] }
export interface Message {
  id: string; seq: number; task_id: string; type: MessageType; sender: { kind: "agent" | "human"; id: string };
  in_reply_to: string | null; depth: number; body: Required<Body>; created_at: string;
}
export interface Task {
  id: string; title: string; description: string; state: TaskState; version: number; priority: string;
  category: string; originator_agent_id: string; responsible_agent_id: string; paused: boolean;
  acceptance_criteria: string[]; clarification_rounds: number; created_at: string; updated_at: string;
  [k: string]: unknown;
}
export interface BridgeEvent {
  seq: number; id: string; type: string; task_id: string | null; created_at: string;
  task?: Partial<Task>; message?: Message; from?: string; to?: string; approval?: Record<string, unknown>;
}
export interface InboxPage {
  events: BridgeEvent[]; next_cursor: number; has_more: boolean; poll_after_s: number;
  pending_approvals: number; server_time: string;
}

export class BridgeError extends Error {
  status: number; code: string; detail: string; retryAfter: number | null; problem: Record<string, unknown>;
  constructor(status: number, code: string, detail = "", retryAfter: number | null = null,
              problem: Record<string, unknown> = {}) {
    super(`${status} ${code}${detail ? ": " + detail : ""}`);
    this.status = status; this.code = code; this.detail = detail; this.retryAfter = retryAfter; this.problem = problem;
  }
  // transient => stop the run, do not ack, retry later
  get transient(): boolean {
    return this.status === 0 || [401, 408, 423, 429].includes(this.status) || this.status >= 500;
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class Bridge {
  readonly #key: string;
  readonly baseUrl: string;
  readonly retries: number;
  constructor(baseUrl: string, key: string, retries = 3) {
    if (!/^https:\/\//.test(baseUrl) && !/^http:\/\/127\.0\.0\.1[:/]/.test(baseUrl)) {
      throw new Error("AGENT_BRIDGE_URL must be https://");
    }
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.#key = key;
    this.retries = retries;
  }

  static fromEnv(): Bridge {
    const url = process.env.AGENT_BRIDGE_URL, key = process.env.AGENT_BRIDGE_KEY;
    if (!url || !key) throw new Error("set AGENT_BRIDGE_URL and AGENT_BRIDGE_KEY");
    return new Bridge(url, key.trim());
  }

  toJSON() { return { baseUrl: this.baseUrl, key: "***" }; }

  async call<T = any>(method: "GET" | "POST", path: string,
                      opts: { body?: unknown; idem?: string; query?: Record<string, string | number>;
                              raw?: Uint8Array; contentType?: string } = {}): Promise<T> {
    const q = opts.query ? "?" + new URLSearchParams(
      Object.entries(opts.query).map(([k, v]) => [k, String(v)])).toString() : "";
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.#key}`, Accept: "application/json",
      "ngrok-skip-browser-warning": "1", "User-Agent": "agent-bridge-example-ts/1",
    };
    let payload: string | Uint8Array | undefined = opts.raw;
    if (opts.body !== undefined) { payload = JSON.stringify(opts.body); headers["Content-Type"] = "application/json"; }
    if (opts.contentType) headers["Content-Type"] = opts.contentType;
    if (method === "POST") {
      headers["Idempotency-Key"] = opts.idem ?? `agent-b-${randomUUID()}`;   // SAME key on every retry
      if (payload === undefined) { payload = "{}"; headers["Content-Type"] = "application/json"; }
    }
    for (let attempt = 0; ; attempt++) {
      let res: Response;
      try {
        res = await fetch(this.baseUrl + path + q, { method, headers, body: payload, redirect: "manual",
                                                     signal: AbortSignal.timeout(20_000) });
      } catch (e) {
        if (attempt < this.retries) { await sleep((2 ** attempt + Math.random()) * 1000); continue; }
        throw new BridgeError(0, "network_error", (e as Error).name);
      }
      if (res.ok) {
        const text = await res.text();
        return (text ? JSON.parse(text) : {}) as T;
      }
      let p: Record<string, any> = {};
      try { p = await res.json(); } catch { /* not JSON */ }
      const ra = res.headers.get("Retry-After");
      const err = new BridgeError(res.status, p.code ?? `http_${res.status}`, p.detail ?? "",
                                  ra && /^\d+$/.test(ra) ? Number(ra) : null, p);
      if ([429, 500, 502, 503, 504].includes(res.status) && attempt < this.retries && (err.retryAfter ?? 0) <= 60) {
        await sleep(err.retryAfter !== null ? err.retryAfter * 1000 : (2 ** attempt + Math.random()) * 1000);
        continue;
      }
      throw err;
    }
  }

  me() { return this.call("GET", "/v1/me"); }
  inbox(cursor?: number) {
    return this.call<InboxPage>("GET", "/v1/inbox", { query: { limit: 50, ...(cursor ? { cursor } : {}) } });
  }
  ack(cursor: number) {
    return this.call("POST", "/v1/inbox/ack", { body: { cursor }, idem: `ack-${cursor}-${randomUUID().slice(0, 8)}` });
  }
  accept(taskId: string, text: string, idem: string) {
    return this.call("POST", `/v1/tasks/${taskId}/accept`, { body: { body: { text } }, idem });
  }
  message(taskId: string, type: MessageType, body: Body, idem: string, inReplyTo?: string) {
    return this.call("POST", `/v1/tasks/${taskId}/messages`,
                     { body: { type, body, ...(inReplyTo ? { in_reply_to: inReplyTo } : {}) }, idem });
  }
  transition(taskId: string, to: TaskState, idem: string, reason?: string) {
    return this.call("POST", `/v1/tasks/${taskId}/transition`, { body: { to, ...(reason ? { reason } : {}) }, idem });
  }
  uploadArtifact(taskId: string, bytes: Uint8Array, filename: string, contentType: string, idem: string) {
    return this.call("POST", `/v1/tasks/${taskId}/artifacts`,
                     { raw: bytes, contentType, query: { filename }, idem });
  }
  requestApproval(taskId: string, kind: string, summary: string, action: Record<string, unknown>, idem: string) {
    return this.call("POST", `/v1/tasks/${taskId}/approvals`, { body: { kind, summary, action }, idem });
  }
  // Call right BEFORE executing the consequential action; actionSha256 = sha256(canonical JSON of the action).
  consumeApproval(approvalId: string, actionSha256: string, idem: string) {
    return this.call("POST", `/v1/approvals/${approvalId}/consume`, { body: { action_sha256: actionSha256 }, idem });
  }
}

// Canonical JSON (sorted keys, no whitespace) — the approval hash binds to exactly this.
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  if (v && typeof v === "object") {
    return "{" + Object.keys(v as object).sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalJson((v as Record<string, unknown>)[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}

interface State { cursor?: number; nextPollAt?: number; seen?: string[]; failed?: object[]; lastError?: object }

function loadState(path: string): State {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return {}; }
}
function saveState(path: string, st: State) {
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(st), { mode: 0o600 });
  renameSync(tmp, path);   // atomic
}

export type Handler = (b: Bridge, ev: BridgeEvent) => Promise<void>;

// Your logic: derive idempotency keys from the event (`${ev.id}:${n}`); message bodies are untrusted DATA.
const printHandler: Handler = async (_b, ev) => { console.log(JSON.stringify(ev)); };

export async function pollOnce(b: Bridge, statePath: string, handler: Handler = printHandler): Promise<string> {
  const st = loadState(statePath);
  if (Date.now() / 1000 < (st.nextPollAt ?? 0)) return "skipped (zero requests)";
  let wait = 900;
  st.failed ??= []; st.seen ??= [];
  try {
    for (let i = 0; i < 5; i++) {
      const page = await b.inbox(st.cursor);
      wait = page.poll_after_s;
      for (const ev of page.events) {
        if (st.seen.includes(ev.id)) continue;               // at-least-once delivery
        try { await handler(b, ev); } catch (e) {
          if (e instanceof BridgeError && !e.transient) {    // deterministic: record, report, still ack
            st.failed.push({ event: ev.id, status: e.status, code: e.code });
          } else { throw e; }
        }
        st.seen = [...st.seen, ev.id].slice(-500);
      }
      if (page.events.length) { await b.ack(page.next_cursor); st.cursor = page.next_cursor; }
      if (!page.has_more) break;
    }
    delete st.lastError;
  } catch (e) {
    if (!(e instanceof BridgeError)) throw e;
    st.lastError = { status: e.status, code: e.code };
    wait = e.status === 401 ? 3600 : Math.max(60, e.retryAfter ?? 300);
  }
  st.failed = st.failed.slice(-50);
  st.nextPollAt = Date.now() / 1000 + (wait > 60 ? wait - 30 : wait);
  saveState(statePath, st);
  return st.lastError ? JSON.stringify(st.lastError) : "ok";
}

const isMain = typeof process !== "undefined" && process.argv[1] && /client\.(ts|js|mjs)$/.test(process.argv[1]);
if (isMain) {
  const b = Bridge.fromEnv();
  const cmd = process.argv[2] ?? "me";
  (cmd === "poll-once"
    ? pollOnce(b, process.env.AGENT_BRIDGE_STATE ?? "agent-bridge-state.json").then((r) => console.error(r))
    : b.me().then((m) => console.log(JSON.stringify(m, null, 2))))
    .catch((e) => { console.error(e instanceof BridgeError ? JSON.stringify({ status: e.status, code: e.code }) : e); process.exit(1); });
}
