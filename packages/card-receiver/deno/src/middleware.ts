// @opnli/card-receiver — Request Handler Helper (Deno/TypeScript)
// Validates CARD session tokens for Deno HTTP handlers
// (e.g., Supabase Edge Functions).
// ============================================================
//
// The Node SDK exposes `cardReceiverMiddleware()` for Express. Deno
// HTTP handlers (and Supabase Edge Functions) do not use Express — they
// receive a `Request` and return a `Response`. This file provides the
// same five validation steps in a Deno-shaped API:
//
//   1. Extract token from Authorization header or request body
//   2. Look up session via lookupSession callback
//   3. Check expiration
//   4. Check revocation
//   5. Check allowed_ops against requested operation
//
// On any failure, returns a Response with an appropriate status code.
// On success, returns { session, auditAction } so the handler can
// proceed and call auditAccess().
// ============================================================

import { auditAccess } from "./card-set-validator.ts";
import type { AuditAccessOptions, AuditAction } from "./card-set-validator.ts";

export interface SessionLookupRecord {
  token?: string;
  session_token?: string;
  expires_at?: string | null;
  revoked_at?: string | null;
  allowed_ops?: string[];
  agent_id?: string;
  agent_name?: string;
  user_id?: string;
  principal_id?: string;
  [k: string]: unknown;
}

export interface CardReceiverHelperConfig {
  /** Look up a session by token. Return null if not found. */
  lookupSession: (token: string) => Promise<SessionLookupRecord | null>;
  /** Optional audit options forwarded to auditAccess(). */
  auditOptions?: AuditAccessOptions;
  /** Optional override for inferring the audit action from the request. */
  extractAction?: (req: Request) => Promise<AuditAction> | AuditAction;
}

export interface CardReceiverSuccess {
  ok: true;
  session: SessionLookupRecord;
  token: string;
}

export interface CardReceiverFailure {
  ok: false;
  response: Response;
}

export type CardReceiverResult = CardReceiverSuccess | CardReceiverFailure;

/**
 * Validate a session token-bearing request for a Deno HTTP handler.
 *
 * Usage in a Supabase Edge Function:
 *
 *   const result = await cardReceiverHandle(req, {
 *     lookupSession: (token) => supabase
 *       .from('agent_sessions').select('*').eq('session_token', token).maybeSingle()
 *       .then(({ data }) => data),
 *     auditOptions: { persistAudit: writeToAuditEvents }
 *   });
 *   if (!result.ok) return result.response;
 *   // ... proceed with result.session ...
 */
export async function cardReceiverHandle(
  req: Request,
  config: CardReceiverHelperConfig,
): Promise<CardReceiverResult> {
  if (!config.lookupSession) {
    throw new Error("cardReceiverHandle requires a lookupSession function");
  }

  // ── Extract token from request ──────────────────────────────
  let token: string | null = null;
  let bodyClone: unknown = null;

  // Authorization: Bearer <token>
  const authHeader = req.headers.get("authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.slice(7);
  }

  // Fall back to JSON body { session_token: ... }
  if (!token) {
    try {
      // Clone the request because reading the body consumes it,
      // and downstream handlers may also want to read it.
      const reqClone = req.clone();
      const ct = req.headers.get("content-type") ?? "";
      if (ct.includes("application/json")) {
        bodyClone = await reqClone.json();
        if (
          typeof bodyClone === "object" &&
          bodyClone !== null &&
          typeof (bodyClone as Record<string, unknown>).session_token ===
            "string"
        ) {
          token = (bodyClone as Record<string, string>).session_token;
        }
      }
    } catch {
      // Body parsing failed — fall through to "no token"
    }
  }

  if (!token) {
    return {
      ok: false,
      response: jsonResponse(401, {
        error: "Missing session token",
        hint:
          "Provide a CARD session token via Authorization header or session_token in request body",
      }),
    };
  }

  // ── Look up session ──────────────────────────────────────────
  let session: SessionLookupRecord | null;
  try {
    session = await config.lookupSession(token);
  } catch {
    // INV-FC: fail-closed on lookup error
    return {
      ok: false,
      response: jsonResponse(500, { error: "Session lookup failed" }),
    };
  }

  if (!session) {
    return {
      ok: false,
      response: jsonResponse(401, {
        error: "Invalid or expired session token",
      }),
    };
  }

  // ── Check expiration ─────────────────────────────────────────
  if (session.expires_at && new Date(session.expires_at) < new Date()) {
    return {
      ok: false,
      response: jsonResponse(401, { error: "Session token expired" }),
    };
  }

  // ── Check revocation ─────────────────────────────────────────
  if (session.revoked_at) {
    return {
      ok: false,
      response: jsonResponse(401, { error: "Session token revoked" }),
    };
  }

  // ── Check allowed_ops against request ────────────────────────
  const requestedOp = inferOperation(req);
  if (
    session.allowed_ops &&
    Array.isArray(session.allowed_ops) &&
    !session.allowed_ops.includes(requestedOp)
  ) {
    return {
      ok: false,
      response: jsonResponse(403, {
        error: "Operation not permitted",
        requested: requestedOp,
        allowed: session.allowed_ops,
      }),
    };
  }

  // ── Audit the access (INV-CA-5: no content) ──────────────────
  let actionInfo: AuditAction;
  if (config.extractAction) {
    actionInfo = await config.extractAction(req);
  } else {
    const url = new URL(req.url);
    actionInfo = {
      action: req.method.toLowerCase() + ":" + url.pathname,
      target_type: "api_endpoint",
      target_id: url.pathname,
    };
  }
  try {
    await auditAccess(token, actionInfo, config.auditOptions ?? {});
  } catch (e) {
    // Audit failure does not block the request, but is logged
    const msg = e instanceof Error ? e.message : String(e);
    console.error("[card-receiver] Audit error:", msg);
  }

  return { ok: true, session, token };
}

/**
 * Infer the operation type from an HTTP request.
 * Maps HTTP methods to CARD access levels.
 */
export function inferOperation(req: Request): string {
  const method = req.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
    return "read";
  }
  if (method === "POST") {
    // POST can be read (query) or write (create) — default to read for
    // API query patterns (agent-records-list, agent-records-detail).
    return "read";
  }
  if (method === "PUT" || method === "PATCH") return "write";
  if (method === "DELETE") return "delete";
  return "read";
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
