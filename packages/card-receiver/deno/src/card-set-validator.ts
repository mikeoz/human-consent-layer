// @opnli/card-receiver — CARD Set Validator (Deno/TypeScript)
// Validates incoming CARD Sets from CARD-Carrying Agents
// ============================================================
// v0.2.0-deno — Session C port:
//   - All v0.2.0 (Node) functionality preserved
//   - SHA-256 via Web Crypto API (async)
//   - verifyEntityWithVE rewritten to match the live VE schema
//     at ve-staging.opn.li (six-field payload + request_hash)
//   - ES modules, TypeScript types
// ============================================================
//
// VE Contract (verified empirically against ve-staging.opn.li, 27APR26):
//   Endpoint:  POST {veEndpoint}
//   Required body fields:
//     - agent_id        : string (the enrolled agent identifier)
//     - card_id         : string (the CARD set_id or entity_card.card_id)
//     - operation_type  : one of {web_search, filesystem_read,
//                                 filesystem_write, shell_exec, api_call}
//     - session_id      : string (request-scoped, unique per call)
//     - timestamp       : ISO 8601 UTC, must be within 30 seconds
//                         of VE server time
//     - request_hash    : SHA-256(agent_id + card_id + operation_type +
//                                 session_id + timestamp), lowercase hex
// ============================================================

// ─────────────────────────────────────────────────────────────
// Type definitions
// ─────────────────────────────────────────────────────────────

export interface CardSet {
  set_version?: string;
  set_id?: string;
  presented_at?: string;
  principal?: { type: string; id: string };
  entity_card?: EntityCard;
  data_card?: DataCard;
  use_card?: UseCard;
  boundary_card?: BoundaryCard;
}

export interface EntityCard {
  card_type: "entity";
  card_id?: string;
  agent_id: string;
  agent_name?: string;
  shield_level: "green" | "yellow" | "red";
  certification_hash?: string;
  principal_id?: string;
}

export interface DataCard {
  card_type: "data";
  data_resources: { resource: string; access: string; description?: string }[];
}

export interface UseCard {
  card_type: "use";
  permitted_actions: { action: string; description?: string }[];
}

export interface BoundaryCard {
  card_type: "boundary";
  rate_limit?: { calls_per_day?: number; [k: string]: unknown };
  time_window?: unknown;
  scope_constraints?: unknown;
}

export interface PlatformPolicy {
  minimumShieldLevel?: "green" | "yellow";
  allowedResources?: string[];
  maxAccessLevel?: "read" | "write" | "read-write";
  allowedActions?: string[];
  maxCallsPerDay?: number;
}

export interface SessionScope {
  agent_id: string;
  agent_name?: string;
  principal_id: string;
  shield_level: string;
  resources: string[];
  access_levels: { resource: string; access: string }[];
  actions: string[];
  rate_limit: unknown;
  time_window: unknown;
  scope_constraints: unknown;
  validated_at: string;
}

export interface ValidateCardSetOptions {
  veEndpoint?: string;
  timeout?: number;
  requireVE?: boolean;
}

export interface ValidateResult {
  valid: boolean;
  errors: string[];
  session_scope: SessionScope | null;
}

export interface VeVerifyResult {
  verified: boolean;
  reason: string | null;
  ve_response?: Record<string, unknown>;
}

export interface SessionRecord {
  token: string;
  expires_at: string;
  scope: SessionScope;
  issued_at: string;
  agent_id: string;
  agent_name: string;
  principal_id: string;
  allowed_ops: string[];
  service_rules?: Record<string, unknown>;
}

export interface CreateSessionTokenOptions {
  persistSession?: (record: SessionRecord) => Promise<void>;
  serviceRules?: {
    service_name?: string;
    allowed_resources?: string[];
    allowed_actions?: string[];
    rate_limit?: unknown;
    retention?: string;
  };
}

export interface AuditAction {
  action: string;
  target_type?: string | null;
  target_id?: string | null;
}

export interface AuditEntry {
  session_token: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  timestamp: string;
  result: string;
  prev_hash?: string;
  entry_hash?: string;
  persist_error?: string;
}

export interface AuditChain {
  getLastHash(): string;
  advance(entryHash: string): void;
}

export interface AuditAccessOptions {
  persistAudit?: (entry: AuditEntry) => Promise<void>;
  auditChain?: AuditChain;
}

// ─────────────────────────────────────────────────────────────
// SHA-256 utility — Web Crypto API (async)
// ─────────────────────────────────────────────────────────────

/**
 * SHA-256 hex hash of a UTF-8 string. Async because Web Crypto.
 */
export async function sha256(data: string): Promise<string> {
  const bytes = new TextEncoder().encode(data);
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  const arr = Array.from(new Uint8Array(buf));
  return arr.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ─────────────────────────────────────────────────────────────
// Audit hash chain
// ─────────────────────────────────────────────────────────────

/**
 * createAuditChain() returns a chain tracker. Platforms can provide
 * a persistent last hash on startup; otherwise starts from genesis.
 *
 * Note: because sha256 is async in the Deno port, the genesis hash
 * is computed lazily on the first getLastHash() call if no
 * initialHash was provided.
 */
export function createAuditChain(initialHash?: string): AuditChain {
  let lastHash: string | null = initialHash ?? null;
  let genesisPromise: Promise<string> | null = null;

  return {
    getLastHash(): string {
      if (lastHash !== null) return lastHash;
      // Lazy genesis: synchronous accessor must return something.
      // We compute a deterministic genesis label when no chain has been
      // established. Callers running the chain in async code should
      // prefer providing an initialHash.
      lastHash = "genesis:" + new Date().toISOString();
      return lastHash;
    },
    advance(entryHash: string): void {
      lastHash = entryHash;
    },
  };
}

// Default in-memory audit chain — platforms should replace with persistent chain
const defaultAuditChain = createAuditChain();

// ─────────────────────────────────────────────────────────────
// validateCardSet
// ─────────────────────────────────────────────────────────────

/**
 * Validate a CARD Set against platform policies and the VE.
 *
 * @param cardSet - The CARD Set presented by the CARD-Carrying Agent
 * @param platformPolicy - Platform-specific validation rules
 * @param options - { veEndpoint, timeout, requireVE }
 * @returns ValidateResult { valid, errors, session_scope }
 */
export async function validateCardSet(
  cardSet: CardSet | null | undefined,
  platformPolicy: PlatformPolicy,
  options: ValidateCardSetOptions = {},
): Promise<ValidateResult> {
  const errors: string[] = [];

  // ── Null guard ──────────────────────────────────────────────
  if (!cardSet) {
    return {
      valid: false,
      errors: ["CARD Set is null or undefined"],
      session_scope: null,
    };
  }

  // ── Structure validation ────────────────────────────────────
  if (!cardSet.set_version) errors.push("Missing set_version");
  if (!cardSet.set_id) errors.push("Missing set_id");
  if (!cardSet.principal || cardSet.principal.type !== "nhb") {
    errors.push("Principal must be type nhb");
  }
  if (!cardSet.entity_card || cardSet.entity_card.card_type !== "entity") {
    errors.push("Missing or invalid entity_card");
  }
  if (!cardSet.data_card || cardSet.data_card.card_type !== "data") {
    errors.push("Missing or invalid data_card");
  }
  if (!cardSet.use_card || cardSet.use_card.card_type !== "use") {
    errors.push("Missing or invalid use_card");
  }
  if (!cardSet.boundary_card || cardSet.boundary_card.card_type !== "boundary") {
    errors.push("Missing or invalid boundary_card");
  }

  if (errors.length > 0) {
    return { valid: false, errors, session_scope: null };
  }

  // After the structure check, we know all CARDs exist.
  // Use non-null assertions to satisfy TypeScript's flow analysis.
  const entityCard = cardSet.entity_card!;
  const dataCard = cardSet.data_card!;
  const useCard = cardSet.use_card!;
  const boundaryCard = cardSet.boundary_card!;
  const principal = cardSet.principal!;
  const setId = cardSet.set_id!;

  // ── Entity CARD: Verify against VE ──────────────────────────
  if (options.veEndpoint) {
    const veResult = await verifyEntityWithVE(
      entityCard,
      setId,
      options.veEndpoint,
      options.timeout,
    );
    if (!veResult.verified) {
      errors.push("VE verification failed: " + veResult.reason);
    }
  } else if (options.requireVE) {
    // INV-FC: fail-closed when VE is required but no endpoint provided
    errors.push("VE verification required but no veEndpoint provided");
  }

  // ── Entity CARD: Shield level check ─────────────────────────
  if (platformPolicy.minimumShieldLevel) {
    const shieldRank: Record<string, number> = { green: 2, yellow: 1 };
    const agentLevel = shieldRank[entityCard.shield_level] || 0;
    const requiredLevel = shieldRank[platformPolicy.minimumShieldLevel] || 0;
    if (agentLevel < requiredLevel) {
      errors.push(
        "Shield level " + entityCard.shield_level +
          " does not meet minimum requirement: " +
          platformPolicy.minimumShieldLevel,
      );
    }
  }

  // ── Principal consistency ───────────────────────────────────
  if (
    entityCard.principal_id &&
    entityCard.principal_id !== principal.id
  ) {
    errors.push(
      "Entity CARD principal_id does not match CARD Set principal.id",
    );
  }

  // ── Data CARD: Resource whitelist check ─────────────────────
  if (platformPolicy.allowedResources) {
    for (const resource of dataCard.data_resources) {
      if (!platformPolicy.allowedResources.includes(resource.resource)) {
        errors.push("Resource not allowed: " + resource.resource);
      }
    }
  }

  // ── Data CARD: Access level check ───────────────────────────
  if (platformPolicy.maxAccessLevel) {
    const accessRank: Record<string, number> = {
      read: 1,
      write: 2,
      "read-write": 3,
    };
    const maxLevel = accessRank[platformPolicy.maxAccessLevel] || 1;
    for (const resource of dataCard.data_resources) {
      const requestedLevel = accessRank[resource.access] || 1;
      if (requestedLevel > maxLevel) {
        errors.push(
          "Access level " + resource.access + " exceeds maximum: " +
            platformPolicy.maxAccessLevel + " for resource " +
            resource.resource,
        );
      }
    }
  }

  // ── Use CARD: Action whitelist check ────────────────────────
  if (platformPolicy.allowedActions) {
    for (const action of useCard.permitted_actions) {
      if (!platformPolicy.allowedActions.includes(action.action)) {
        errors.push("Action not allowed: " + action.action);
      }
    }
  }

  // ── Boundary CARD: Rate limit check ─────────────────────────
  if (platformPolicy.maxCallsPerDay && boundaryCard.rate_limit) {
    const callsPerDay = boundaryCard.rate_limit.calls_per_day;
    if (
      typeof callsPerDay === "number" &&
      callsPerDay > platformPolicy.maxCallsPerDay
    ) {
      errors.push(
        "Requested rate " + callsPerDay + "/day exceeds tier maximum: " +
          platformPolicy.maxCallsPerDay,
      );
    }
  }

  // ── Build session scope from validated CARD Set ─────────────
  const session_scope: SessionScope | null = errors.length === 0
    ? {
      agent_id: entityCard.agent_id,
      agent_name: entityCard.agent_name,
      principal_id: principal.id,
      shield_level: entityCard.shield_level,
      resources: dataCard.data_resources.map((r) => r.resource),
      access_levels: dataCard.data_resources.map((r) => ({
        resource: r.resource,
        access: r.access,
      })),
      actions: useCard.permitted_actions.map((a) => a.action),
      rate_limit: boundaryCard.rate_limit,
      time_window: boundaryCard.time_window,
      scope_constraints: boundaryCard.scope_constraints,
      validated_at: new Date().toISOString(),
    }
    : null;

  return { valid: errors.length === 0, errors, session_scope };
}

// ─────────────────────────────────────────────────────────────
// verifyEntityWithVE — REWRITTEN to match live VE contract
// ─────────────────────────────────────────────────────────────

/**
 * Verify an Entity CARD against the Verification Endpoint.
 *
 * Implements the six-field schema enforced by ve-staging.opn.li:
 *   { agent_id, card_id, operation_type, session_id, timestamp, request_hash }
 *
 * The request_hash is SHA-256 over the concatenation
 *   agent_id + card_id + operation_type + session_id + timestamp
 *
 * Fail-closed: any error or non-2xx response = denied (INV-FC).
 *
 * @param entityCard - The Entity CARD from the presented CARD Set
 * @param cardId - The CARD Set's set_id (what we ask the VE to verify)
 * @param veEndpoint - The full VE URL (e.g., "https://ve-staging.opn.li/v1/verify")
 * @param timeout - Request timeout in milliseconds (default 5000)
 * @param operationType - One of the VE's accepted operation types
 *                       (default "api_call" for service-side validation)
 */
export async function verifyEntityWithVE(
  entityCard: EntityCard,
  cardId: string,
  veEndpoint: string,
  timeout = 5000,
  operationType:
    | "web_search"
    | "filesystem_read"
    | "filesystem_write"
    | "shell_exec"
    | "api_call" = "api_call",
): Promise<VeVerifyResult> {
  try {
    const sessionId = "ve-verify-" + crypto.randomUUID();
    const timestamp = new Date().toISOString();

    // Canonical hash input — order matters (must match VE)
    const hashInput =
      entityCard.agent_id +
      cardId +
      operationType +
      sessionId +
      timestamp;
    const requestHash = await sha256(hashInput);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const res = await fetch(veEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agent_id: entityCard.agent_id,
        card_id: cardId,
        operation_type: operationType,
        session_id: sessionId,
        timestamp,
        request_hash: requestHash,
      }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    // Read the body whether ok or not — VE error messages are informative
    let parsed: Record<string, unknown> = {};
    try {
      parsed = await res.json();
    } catch {
      // VE returned non-JSON; treat as failure with status code only
    }

    if (!res.ok) {
      const reason = (parsed.error as string) || ("VE returned " + res.status);
      const message = (parsed.message as string) || "";
      return {
        verified: false,
        reason: message ? reason + ": " + message : reason,
        ve_response: parsed,
      };
    }

    // Success path: VE returns a decision/verdict in the body.
    // We accept several shapes the VE has used historically.
    const decision = parsed.decision ?? parsed.verdict ?? parsed.result;
    const verified = decision === "allow" ||
      decision === "verified" ||
      decision === "ok" ||
      parsed.verified === true;

    if (verified) {
      return { verified: true, reason: null, ve_response: parsed };
    }

    return {
      verified: false,
      reason: "VE denied: " + (parsed.reason as string ?? "unknown"),
      ve_response: parsed,
    };
  } catch (e) {
    // INV-FC: fail-closed on any error (network, timeout, abort, parse)
    const msg = e instanceof Error ? e.message : String(e);
    return { verified: false, reason: "VE unreachable: " + msg };
  }
}

// ─────────────────────────────────────────────────────────────
// createSessionToken — with optional persistence adapter
// ─────────────────────────────────────────────────────────────

/**
 * Create a session token scoped to the validated CARD Set.
 *
 * Token format: "crs_" + 32 hex characters from crypto.randomUUID
 * (deterministic length: total 36 chars, matches Node SDK).
 */
export async function createSessionToken(
  sessionScope: SessionScope,
  ttlSeconds = 3600,
  options: CreateSessionTokenOptions = {},
): Promise<SessionRecord> {
  // Generate 32 hex characters using Web Crypto random bytes
  const randomBytes = new Uint8Array(16);
  crypto.getRandomValues(randomBytes);
  const tokenSuffix = Array.from(randomBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const token = "crs_" + tokenSuffix;

  const now = new Date();
  const expires_at = new Date(now.getTime() + ttlSeconds * 1000).toISOString();

  const sessionRecord: SessionRecord = {
    token,
    expires_at,
    scope: sessionScope,
    issued_at: now.toISOString(),
    agent_id: sessionScope.agent_id,
    agent_name: sessionScope.agent_name || "Unknown Agent",
    principal_id: sessionScope.principal_id,
    allowed_ops: sessionScope.access_levels
      ? Array.from(new Set(sessionScope.access_levels.map((a) => a.access)))
      : ["read"],
  };

  // Include service rules in response if provided
  if (options.serviceRules) {
    sessionRecord.service_rules = {
      service_name: options.serviceRules.service_name,
      allowed_resources: options.serviceRules.allowed_resources,
      allowed_actions: options.serviceRules.allowed_actions,
      rate_limit: options.serviceRules.rate_limit,
      retention: options.serviceRules.retention,
    };
  }

  // ── Persist if callback provided (INV-FC: fail-closed on error) ──
  if (options.persistSession) {
    try {
      await options.persistSession(sessionRecord);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error("Session persistence failed (fail-closed): " + msg);
    }
  }

  return sessionRecord;
}

// ─────────────────────────────────────────────────────────────
// auditAccess — SHA-256 hash chain (INV-16), content-free (INV-CA-5)
// ─────────────────────────────────────────────────────────────

/**
 * Log an API access event against the CARD Set session.
 *
 * INV-CA-5: Audit entries contain action type and target ID only.
 *           NEVER include data content, titles, filenames, or summaries.
 * INV-16:   Each entry includes prev_hash and entry_hash forming a
 *           tamper-evident chain.
 */
export async function auditAccess(
  token: string,
  action: AuditAction,
  options: AuditAccessOptions = {},
): Promise<AuditEntry> {
  const chain = options.auditChain ?? defaultAuditChain;
  const timestamp = new Date().toISOString();

  // ── Build content-free audit entry (INV-CA-5) ──────────────
  const entry: AuditEntry = {
    session_token: token,
    action: action.action,
    target_type: action.target_type ?? null,
    target_id: action.target_id ?? null,
    timestamp,
    result: "logged",
  };

  // ── Hash chain (INV-16) ────────────────────────────────────
  const prev_hash = chain.getLastHash();
  // Hash the entry content (without prev_hash/entry_hash fields) plus prev_hash.
  // This matches the Node SDK's behavior: JSON.stringify(entry) + ":" + prev_hash
  // where entry is the version BEFORE prev_hash and entry_hash are attached.
  const entry_data = JSON.stringify(entry) + ":" + prev_hash;
  const entry_hash = await sha256(entry_data);

  entry.prev_hash = prev_hash;
  entry.entry_hash = entry_hash;
  chain.advance(entry_hash);

  // ── Persist if callback provided ───────────────────────────
  if (options.persistAudit) {
    try {
      await options.persistAudit(entry);
    } catch (e) {
      // Audit persistence failure is logged but does not block.
      // The in-memory chain still advances to maintain integrity.
      const msg = e instanceof Error ? e.message : String(e);
      entry.persist_error = msg;
    }
  }

  return entry;
}
