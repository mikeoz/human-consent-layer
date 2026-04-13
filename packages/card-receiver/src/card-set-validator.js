// @opnli/card-receiver — CARD Set Validator
// Validates incoming CARD Sets from CARD-Carrying Agents
// ============================================================

/**
 * Validate a CARD Set against platform policies and the VE.
 * 
 * @param {object} cardSet - The CARD Set presented by the CCA
 * @param {object} platformPolicy - Platform-specific validation rules
 * @param {object} options - { veEndpoint, timeout }
 * @returns {object} { valid, errors, session_scope }
 */
async function validateCardSet(cardSet, platformPolicy, options = {}) {
  const errors = [];

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
    const veResult = await verifyEntityWithVE(cardSet.entity_card, options.veEndpoint, options.timeout);
    if (!veResult.verified) {
      errors.push('VE verification failed: ' + veResult.reason);
    }
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
    principal_id: cardSet.principal.id,
    shield_level: cardSet.entity_card.shield_level,
    resources: cardSet.data_card.data_resources.map(r => r.resource),
    actions: cardSet.use_card.permitted_actions.map(a => a.action),
    rate_limit: cardSet.boundary_card.rate_limit,
    time_window: cardSet.boundary_card.time_window,
    scope_constraints: cardSet.boundary_card.scope_constraints,
    validated_at: new Date().toISOString()
  } : null;

  return { valid: errors.length === 0, errors, session_scope };
}

/**
 * Verify an Entity CARD against the Verification Endpoint.
 */
async function verifyEntityWithVE(entityCard, veEndpoint, timeout = 5000) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const res = await fetch(veEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        operation: 'verify',
        agent_id: entityCard.agent_id,
        shield_level: entityCard.shield_level,
        certification_hash: entityCard.certification_hash
      }),
      signal: controller.signal
    });

    clearTimeout(timer);

    if (!res.ok) {
      return { verified: false, reason: 'VE returned ' + res.status };
    }

    const data = await res.json();
    return {
      verified: data.decision === 'allow' || data.decision === 'verified',
      reason: data.decision === 'allow' || data.decision === 'verified' ? null : 'VE denied: ' + (data.reason || 'unknown')
    };
  } catch (e) {
    return { verified: false, reason: 'VE unreachable: ' + e.message };
  }
}

/**
 * Create a session token scoped to the validated CARD Set.
 * 
 * @param {object} sessionScope - The session_scope from validateCardSet
 * @param {number} ttlSeconds - Session duration in seconds (default: 3600)
 * @returns {object} { token, expires_at, scope }
 */
function createSessionToken(sessionScope, ttlSeconds = 3600) {
  const token = 'crs_' + Array.from({ length: 32 }, () => 
    '0123456789abcdef'[Math.floor(Math.random() * 16)]
  ).join('');
  
  const expires_at = new Date(Date.now() + ttlSeconds * 1000).toISOString();

  return {
    token,
    expires_at,
    scope: sessionScope,
    issued_at: new Date().toISOString()
  };
}

/**
 * Log an API access event against the CARD Set session.
 * 
 * @param {string} token - The session token
 * @param {object} action - { resource, action, timestamp }
 * @returns {object} Audit entry
 */
function auditAccess(token, action) {
  return {
    session_token: token,
    resource: action.resource,
    action: action.action,
    timestamp: action.timestamp || new Date().toISOString(),
    result: 'logged'
  };
}

module.exports = { validateCardSet, verifyEntityWithVE, createSessionToken, auditAccess };
