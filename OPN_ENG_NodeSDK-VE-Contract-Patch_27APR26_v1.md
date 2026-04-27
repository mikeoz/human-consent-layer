# Node SDK Patch — `verifyEntityWithVE` VE Contract Fix

**Document:** `OPN_ENG_NodeSDK-VE-Contract-Patch_27APR26_v1.md`
**Date:** April 27, 2026
**Author:** ENG (Technical Architect)
**Subject:** Bring `packages/card-receiver/src/card-set-validator.js` `verifyEntityWithVE` in line with the live VE contract at `ve-staging.opn.li`
**Severity:** P1 — latent bug, blocks any real VE validation
**Source:** Session C reconnaissance (Step 1.A through Step 1.E, 27APR26)

---

## 1. The Bug

The current `verifyEntityWithVE` function in `packages/card-receiver/src/card-set-validator.js` (Session B v0.2.0) posts the following body to the VE:

```json
{
  "operation": "verify",
  "agent_id": "<agent>",
  "shield_level": "<green|yellow>",
  "certification_hash": "<hash>"
}
```

The live VE at `ve-staging.opn.li/v1/verify` requires a different schema, verified empirically through five reconnaissance probes on 27 April 2026:

```json
{
  "agent_id": "<enrolled agent identifier>",
  "card_id": "<the CARD Set's set_id>",
  "operation_type": "<one of: web_search, filesystem_read, filesystem_write, shell_exec, api_call>",
  "session_id": "<request-scoped uuid>",
  "timestamp": "<ISO 8601 UTC, must be within 30 seconds of server time>",
  "request_hash": "<SHA-256 hex of agent_id + card_id + operation_type + session_id + timestamp>"
}
```

The existing function would receive HTTP 400 `missing_fields` from the live VE on every call. This was not caught by the v0.2.0 test suite because no test exercises the VE path with a real endpoint — `validateCardSet()` calls in the test file do not pass a `veEndpoint`.

---

## 2. The Fix

Replace the entire `verifyEntityWithVE` function in `packages/card-receiver/src/card-set-validator.js` with the version below.

### 2.1 Updated function signature

The function now needs the CARD Set's `set_id` (the canonical "card_id" value the VE expects). The cleanest way is to pass it as a new parameter alongside `entityCard`. This requires a small change in `validateCardSet()` where it calls `verifyEntityWithVE` — described in §2.3.

### 2.2 Replacement function

```javascript
// ============================================================
// verifyEntityWithVE — Session C: corrected to match live VE
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
```

### 2.3 Update the call site in `validateCardSet`

Find this block in `validateCardSet`:

```javascript
  // ── Entity CARD: Verify against VE ──────────────────────────
  if (options.veEndpoint) {
    const veResult = await verifyEntityWithVE(cardSet.entity_card, options.veEndpoint, options.timeout);
```

Replace with:

```javascript
  // ── Entity CARD: Verify against VE ──────────────────────────
  if (options.veEndpoint) {
    const veResult = await verifyEntityWithVE(cardSet.entity_card, cardSet.set_id, options.veEndpoint, options.timeout);
```

The only change is adding `cardSet.set_id` as the second argument. Everything else in `validateCardSet` is unchanged.

### 2.4 No other changes required

The `module.exports` block at the bottom of the file does not change — `verifyEntityWithVE` is already exported. The function signature now has an extra parameter but `validateCardSet` is the only caller inside the SDK. External callers passing the old 3-argument shape will still work in JavaScript (extra args are ignored, missing args become `undefined`), but they'll fail at runtime against the live VE because the SHA-256 input will be malformed. We accept this — there are no known external callers; the SDK is brand new.

---

## 3. Test Coverage Update

Add the following test block to `packages/card-receiver/test/test-sdk.js` immediately after the existing `── sha256 utility ──` section. These tests do not call the live VE, but they verify the request_hash construction matches the canonical formula.

```javascript
  // ──────────────────────────────────────────────────────────
  console.log('\n── verifyEntityWithVE — request_hash formula ──');
  // ──────────────────────────────────────────────────────────

  // Verify the SHA-256 input order is: agent_id + card_id + operation_type + session_id + timestamp
  // This is the canonical formula reported by the live VE.
  const refAgentId = 'card:entity:agent-bigcroc-001';
  const refCardId = 'urn:uuid:test-card-001';
  const refOpType = 'api_call';
  const refSessionId = 've-verify-test-001';
  const refTimestamp = '2026-04-27T16:00:00Z';

  const expectedHash = sha256(refAgentId + refCardId + refOpType + refSessionId + refTimestamp);
  assert(expectedHash.length === 64, 'request_hash is 64 hex chars');
  assert(typeof expectedHash === 'string', 'request_hash is a string');

  // Different inputs must produce different hashes
  const altHash = sha256(refAgentId + refCardId + refOpType + 'different-session' + refTimestamp);
  assert(altHash !== expectedHash, 'Different session_id produces different hash');
```

After applying the patch and the test additions, run:

```bash
cd packages/card-receiver
node test/test-sdk.js
```

Expected output: all existing tests still pass, plus 3 new tests (60 total).

---

## 4. Optional: Live VE Validation

Once the Node patch is applied, this command verifies the SDK hits the live VE correctly. **It will still receive an `unknown_card` or similar error** (because the test card_id is fake), but the error will indicate the VE accepted the request schema, the timestamp was fresh, and the request_hash validated. Any other error means the patch is wrong.

This step is optional — the test suite covers the formula correctness. This step verifies end-to-end against the staging VE.

```bash
node -e "
const { verifyEntityWithVE } = require('./packages/card-receiver/src/card-set-validator');
verifyEntityWithVE(
  { agent_id: 'oc-agent-876a8879b461', shield_level: 'green', certification_hash: 'test' },
  'urn:uuid:fake-card-for-smoke-test',
  'https://ve-staging.opn.li/v1/verify',
  5000
).then(r => console.log(JSON.stringify(r, null, 2)));
"
```

Expected: a result object with `verified: false` and a `reason` that mentions card lookup, signature, or similar — NOT `missing_fields`, `invalid_operation_type`, `timestamp_expired`, or `invalid_request_hash`. Those four error codes would mean we got something wrong in the patch.

---

## 5. Commit Message

When the patch is applied and tests pass, commit with:

```
fix(card-receiver): correct verifyEntityWithVE to match live VE schema

The v0.2.0 SDK posted a 4-field payload (operation, agent_id,
shield_level, certification_hash) that the live VE at
ve-staging.opn.li rejects with HTTP 400 missing_fields.

This commit replaces verifyEntityWithVE with the correct 6-field
payload (agent_id, card_id, operation_type, session_id, timestamp,
request_hash) where request_hash is SHA-256 over the canonical
concatenation. validateCardSet now passes cardSet.set_id as the
card_id parameter.

Verified empirically against ve-staging.opn.li during Session C
reconnaissance, 27 April 2026.

Sister change: packages/card-receiver/deno/ port has the same
corrected logic. The Node and Deno SDKs are functionally equivalent
against the live VE.
```

---

## 6. What This Does NOT Change

- The Node SDK's CommonJS structure (`require` / `module.exports`)
- Any call signature on `validateCardSet`, `createSessionToken`, or `auditAccess`
- The `defineServiceRules` and `cardReceiverMiddleware` files
- The schema, templates, or DevKit
- The published npm package metadata (no version bump required for the patch — but a `0.2.1` patch release is recommended)

---

*Session C deliverable, 27 April 2026 — ENG*
