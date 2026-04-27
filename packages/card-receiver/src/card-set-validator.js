// @opnli/card-receiver — CARD Set Validator
// Validates incoming CARD Sets from CARD-Carrying Agents
// ============================================================
// v0.2.0 — Session B enhancements:
//   - createSessionToken: optional persistSession callback for platform storage
//   - auditAccess: SHA-256 hash chain (INV-16), content-free enforcement (INV-CA-5)
//   - validateCardSet: fail-closed on VE timeout (INV-FC), improved error context
// All v0.1.0 call signatures remain backward-compatible.
// ============================================================

const crypto = require('crypto');

// ── Audit hash chain ────────────────────────────────────────────
// createAuditChain() returns a chain tracker. Platforms can provide
// a persistent last hash on startup; otherwise starts from genesis.

function sha256(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

function createAuditChain(initialHash) {
  let lastHash = initialHash || sha256('genesis:' + new Date().toISOString());
  return {
    getLastHash() { return lastHash; },
    advance(entryHash) { lastHash = entryHash; }
  };
}

// Default in-memory audit chain — platforms should replace with persistent chain
const defaultAuditChain = createAuditChain();

// ============================================================
// validateCardSet
// ============================================================

/**
 * Validate a CARD Set against platform policies and the VE.
 * 
 * @param {object} cardSet - The CARD Set presented by the CCA
 * @param {object} platformPolicy - Platform-specific validation rules
 * @param {object} [options] - { veEndpoint, timeout, requireVE }
 * @param {string} [options.veEndpoint] - VE URL for entity verification
 * @param {number} [options.timeout=5000] - VE request timeout in ms
 * @param {boolean} [options.requireVE=false] - If true, VE is mandatory (fail-closed)
 * @returns {Promise<{valid: boolean, errors: string[], session_scope: object|null}>}
 */
async function validateCardSet(cardSet, platformPolicy, options = {}) {
  const errors = [];

  // ── Null guard ──────────────────────────────────────────────
  if (!cardSet) {
    return { valid: false, errors: ['CARD Set is null or undefined'], session_scope: null };
  }

  // ── Structure validation ────────────────────────────────────
  if (!cardSet.set_version) errors.push('Missing set_version');
  if (!cardSet.set_id) errors.push('Missing set_id');
  if (!cardSet.principal || cardSet.principal.type !== 'nhb') errors.push('Principal must be type nhb');
  if (!cardSet.entity_card || cardSet.entity_card.card_type !== 'entity') errors.push('Missing or invalid entity_card');
  if (!cardSet.data_card || cardSet.data_card.card_type !== 'data') errors.push('Missing or invalid data_card');
  if (!cardSet.use_card || cardSet.use_card.card_type !== 'use') errors.push('Missing or invalid use_card');
  if (!cardSet.boundary_card || cardSet.boundary_card.card_type !== 'boundary') errors.push('Missing or invalid boundary_card');

  if (errors.length > 0) {
    return { valid: false, errors, session_scope: null };
  }

  // ── Entity CARD: Verify against VE ──────────────────────────
  if (options.veEndpoint) {
    const veResult = await verifyEntityWithVE(cardSet.entity_card, cardSet.set_id, options.veEndpoint, options.timeout);
    if (!veResult.verified) {
      errors.push('VE verification failed: ' + veResult.reason);
    }
  } else if (options.requireVE) {
    // INV-FC: fail-closed when VE is required but no endpoint provided
    errors.push('VE verification required but no veEndpoint provided');
  }

  // ── Entity CARD: Shield level check ─────────────────────────
  if (platformPolicy.minimumShieldLevel) {
    const shieldRank = { green: 2, yellow: 1 };
    const agentLevel = shieldRank[cardSet.entity_card.shield_level] || 0;
    const requiredLevel = shieldRank[platformPolicy.minimumShieldLevel] || 0;
    if (agentLevel < requiredLevel) {
      errors.push('Shield level ' + cardSet.entity_card.shield_level + ' does not meet minimum requirement: ' + platformPolicy.minimumShieldLevel);
    }
  }

  // ── Principal consistency ───────────────────────────────────
  if (cardSet.entity_card.principal_id && cardSet.entity_card.principal_id !== cardSet.principal.id) {
    errors.push('Entity CARD principal_id does not match CARD Set principal.id');
  }

  // ── Data CARD: Resource whitelist check ─────────────────────
  if (platformPolicy.allowedResources) {
    for (const resource of cardSet.data_card.data_resources) {
      if (!platformPolicy.allowedResources.includes(resource.resource)) {
        errors.push('Resource not allowed: ' + resource.resource);
      }
    }
  }

  // ── Data CARD: Access level check ───────────────────────────
  if (platformPolicy.maxAccessLevel) {
    const accessRank = { read: 1, write: 2, 'read-write': 3 };
    const maxLevel = accessRank[platformPolicy.maxAccessLevel] || 1;
    for (const resource of cardSet.data_card.data_resources) {
      const requestedLevel = accessRank[resource.access] || 1;
      if (requestedLevel > maxLevel) {
        errors.push('Access level ' + resource.access + ' exceeds maximum: ' + platformPolicy.maxAccessLevel + ' for resource ' + resource.resource);
      }
    }
  }

  // ── Use CARD: Action whitelist check ────────────────────────
  if (platformPolicy.allowedActions) {
    for (const action of cardSet.use_card.permitted_actions) {
      if (!platformPolicy.allowedActions.includes(action.action)) {
        errors.push('Action not allowed: ' + action.action);
      }
    }
  }

  // ── Boundary CARD: Rate limit check ─────────────────────────
  if (platformPolicy.maxCallsPerDay && cardSet.boundary_card.rate_limit) {
    if (cardSet.boundary_card.rate_limit.calls_per_day > platformPolicy.maxCallsPerDay) {
      errors.push('Requested rate ' + cardSet.boundary_card.rate_limit.calls_per_day + '/day exceeds tier maximum: ' + platformPolicy.maxCallsPerDay);
    }
  }

  // ── Build session scope from validated CARD Set ──────────────
  const session_scope = errors.length === 0 ? {
    agent_id: cardSet.entity_card.agent_id,
    agent_name: cardSet.entity_card.agent_name,
    principal_id: cardSet.principal.id,
    shield_level: cardSet.entity_card.shield_level,
    resources: cardSet.data_card.data_resources.map(r => r.resource),
    access_levels: cardSet.data_card.data_resources.map(r => ({ resource: r.resource, access: r.access })),
    actions: cardSet.use_card.permitted_actions.map(a => a.action),
    rate_limit: cardSet.boundary_card.rate_limit,
    time_window: cardSet.boundary_card.time_window,
    scope_constraints: cardSet.boundary_card.scope_constraints,
    validated_at: new Date().toISOString()
  } : null;

  return { valid: errors.length === 0, errors, session_scope };
}

// ============================================================
// verifyEntityWithVE
// ============================================================

/**
 * Verify an Entity CARD against the Verification Endpoint.
 *
 * Implements the six-field schema enforced by ve-staging.opn.li:
 *   { agent_id, card_id, operation_type, session_id, timestamp, request_hash }
 *
 * The request_hash is SHA-256 over the canonical concatenation:
 *   agent_id + card_id + operation_type + session_id + timestamp
 *
 * Fail-closed: any error or non-2xx response = denied (INV-FC).
 *
 * @param {object} entityCard - The Entity CARD from the CARD Set
 * @param {string} cardId - The CARD Set's set_id (passed by validateCardSet)
 * @param {string} veEndpoint - VE URL (e.g., 'https://ve-staging.opn.li/v1/verify')
 * @param {number} [timeout=5000] - Request timeout in milliseconds
 * @param {string} [operationType='api_call'] - One of the VE's accepted operation types
 * @returns {Promise<{verified: boolean, reason: string|null, ve_response?: object}>}
 */
async function verifyEntityWithVE(entityCard, cardId, veEndpoint, timeout = 5000, operationType = 'api_call') {
  try {
    const sessionId = 've-verify-' + crypto.randomUUID();
    const timestamp = new Date().toISOString();

    // Canonical hash input — order matters (must match VE)
    const hashInput = entityCard.agent_id + cardId + operationType + sessionId + timestamp;
    const requestHash = sha256(hashInput);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const res = await fetch(veEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agent_id: entityCard.agent_id,
        card_id: cardId,
        operation_type: operationType,
        session_id: sessionId,
        timestamp,
        request_hash: requestHash
      }),
      signal: controller.signal
    });

    clearTimeout(timer);

    let parsed = {};
    try {
      parsed = await res.json();
    } catch (_) {
      // VE returned non-JSON; treat as failure with status code only
    }

    if (!res.ok) {
      const reason = parsed.error || ('VE returned ' + res.status);
      const message = parsed.message || '';
      return {
        verified: false,
        reason: message ? reason + ': ' + message : reason,
        ve_response: parsed
      };
    }

    // Success path: VE returns a decision/verdict in the body.
    // We accept several shapes the VE has used historically.
    const decision = parsed.decision || parsed.verdict || parsed.result;
    const verified = decision === 'allow' || decision === 'verified' || decision === 'ok' || parsed.verified === true;

    if (verified) {
      return { verified: true, reason: null, ve_response: parsed };
    }

    return {
      verified: false,
      reason: 'VE denied: ' + (parsed.reason || 'unknown'),
      ve_response: parsed
    };
  } catch (e) {
    // INV-FC: fail-closed on any error
    return { verified: false, reason: 'VE unreachable: ' + e.message };
  }
}

// ============================================================
// createSessionToken — enhanced with persistence adapter
// ============================================================

/**
 * Create a session token scoped to the validated CARD Set.
 * 
 * @param {object} sessionScope - The session_scope from validateCardSet
 * @param {number} [ttlSeconds=3600] - Session duration in seconds
 * @param {object} [options] - Optional configuration
 * @param {function} [options.persistSession] - async (sessionRecord) => void
 *   Callback to persist the session to the platform's storage (e.g., Supabase).
 *   If the callback throws, the session is NOT issued (fail-closed per INV-FC).
 * @param {object} [options.serviceRules] - The cardStack from defineServiceRules()
 * @returns {Promise<{token: string, expires_at: string, scope: object, issued_at: string}>}
 */
async function createSessionToken(sessionScope, ttlSeconds = 3600, options = {}) {
  const token = 'crs_' + Array.from({ length: 32 }, () => 
    '0123456789abcdef'[Math.floor(Math.random() * 16)]
  ).join('');
  
  const now = new Date();
  const expires_at = new Date(now.getTime() + ttlSeconds * 1000).toISOString();

  const sessionRecord = {
    token,
    expires_at,
    scope: sessionScope,
    issued_at: now.toISOString(),
    agent_id: sessionScope.agent_id,
    agent_name: sessionScope.agent_name || 'Unknown Agent',
    principal_id: sessionScope.principal_id,
    allowed_ops: sessionScope.access_levels
      ? [...new Set(sessionScope.access_levels.map(a => a.access))]
      : ['read']
  };

  // Include service rules in response if provided
  if (options.serviceRules) {
    sessionRecord.service_rules = {
      service_name: options.serviceRules.service_name,
      allowed_resources: options.serviceRules.allowed_resources,
      allowed_actions: options.serviceRules.allowed_actions,
      rate_limit: options.serviceRules.rate_limit,
      retention: options.serviceRules.retention
    };
  }

  // ── Persist if callback provided (INV-FC: fail-closed on error) ──
  if (options.persistSession) {
    try {
      await options.persistSession(sessionRecord);
    } catch (e) {
      throw new Error('Session persistence failed (fail-closed): ' + e.message);
    }
  }

  return sessionRecord;
}

// ============================================================
// auditAccess — enhanced with SHA-256 hash chain
// ============================================================

/**
 * Log an API access event against the CARD Set session.
 * 
 * INV-CA-5: Audit entries contain action type and target ID only.
 *           NEVER include data content, titles, filenames, or summaries.
 * INV-16:   Each entry includes prev_hash and entry_hash forming a
 *           tamper-evident chain.
 * 
 * @param {string} token - The session token
 * @param {object} action - { action, target_type, target_id }
 * @param {object} [options] - Optional configuration
 * @param {function} [options.persistAudit] - async (auditEntry) => void
 * @param {object} [options.auditChain] - Custom audit chain from createAuditChain()
 * @returns {Promise<object>} Audit entry with hash chain fields
 */
async function auditAccess(token, action, options = {}) {
  const chain = (options && options.auditChain) || defaultAuditChain;
  const timestamp = new Date().toISOString();

  // ── Build content-free audit entry (INV-CA-5) ──────────────
  const entry = {
    session_token: token,
    action: action.action,
    target_type: action.target_type || null,
    target_id: action.target_id || null,
    timestamp,
    result: 'logged'
  };

  // ── Hash chain (INV-16) ────────────────────────────────────
  const prev_hash = chain.getLastHash();
  const entry_data = JSON.stringify(entry) + ':' + prev_hash;
  const entry_hash = sha256(entry_data);

  entry.prev_hash = prev_hash;
  entry.entry_hash = entry_hash;
  chain.advance(entry_hash);

  // ── Persist if callback provided ───────────────────────────
  if (options && options.persistAudit) {
    try {
      await options.persistAudit(entry);
    } catch (e) {
      // Audit persistence failure is logged but does not block.
      // The in-memory chain still advances to maintain integrity.
      entry.persist_error = e.message;
    }
  }

  return entry;
}

// ============================================================
// Exports
// ============================================================

module.exports = {
  validateCardSet,
  verifyEntityWithVE,
  createSessionToken,
  auditAccess,
  createAuditChain,
  sha256
};
