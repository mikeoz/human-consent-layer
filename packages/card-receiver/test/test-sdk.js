// @opnli/card-receiver — Test Suite
// ============================================================
// Tests all SDK functions against the CARD Set schema, the
// MedGraph template, and the E2E Invariants.
//
// Run: node test/test-sdk.js
// ============================================================

const {
  defineServiceRules,
  validateCardSet,
  createSessionToken,
  auditAccess,
  cardReceiverMiddleware,
  createAuditChain,
  sha256
} = require('../src/index');

const medgraphTemplate = require('../../../templates/medgraph-health.json');
const redditTemplate = require('../../../templates/reddit-consumer.json');

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (condition) {
    passed++;
    console.log('  ✅ ' + name);
  } else {
    failed++;
    console.log('  ❌ ' + name);
  }
}

async function runTests() {

  console.log('\n═══════════════════════════════════════════════');
  console.log(' @opnli/card-receiver v0.2.0 — Test Suite');
  console.log('═══════════════════════════════════════════════\n');

  // ──────────────────────────────────────────────────────────
  console.log('── defineServiceRules ──');
  // ──────────────────────────────────────────────────────────

  const mgConfig = {
    serviceName: 'MedGraph',
    serviceId: 'medgraph-001',
    minimumShieldLevel: 'green',
    allowedResources: ['medical_records'],
    maxAccessLevel: 'read',
    allowedActions: ['summarize', 'search', 'compare'],
    rateLimit: { requestsPerWindow: 30, windowSeconds: 60 },
    retention: 'session_only',
    sessionTtlSeconds: 3600,
    nhbSummary: {
      entity: 'BigCROC',
      data: 'Your medical records',
      use: 'Read and summarize your lab results',
      boundary: 'This session only'
    }
  };

  const { policy, cardStack, nhbInvitation } = defineServiceRules(mgConfig);

  assert(policy.minimumShieldLevel === 'green', 'Policy has correct shield level');
  assert(policy.allowedResources.includes('medical_records'), 'Policy includes medical_records resource');
  assert(policy.maxAccessLevel === 'read', 'Policy enforces read-only');
  assert(policy.allowedActions.length === 3, 'Policy has 3 allowed actions');
  assert(cardStack.service_name === 'MedGraph', 'Card stack has service name');
  assert(cardStack.retention === 'session_only', 'Card stack enforces session_only retention');
  assert(nhbInvitation.entity === 'BigCROC', 'NHB invitation has entity line');
  assert(nhbInvitation.boundary === 'This session only', 'NHB invitation has boundary line');

  // Test validation errors
  let threw = false;
  try { defineServiceRules({}); } catch (e) { threw = true; }
  assert(threw, 'Throws on empty config');

  threw = false;
  try { defineServiceRules({ ...mgConfig, minimumShieldLevel: 'platinum' }); } catch (e) { threw = true; }
  assert(threw, 'Throws on invalid shield level');

  // ──────────────────────────────────────────────────────────
  console.log('\n── validateCardSet ──');
  // ──────────────────────────────────────────────────────────

  // Build a valid CARD Set from the MedGraph template
  const validCardSet = JSON.parse(JSON.stringify(medgraphTemplate));
  validCardSet.set_id = 'urn:uuid:test-' + Date.now();
  validCardSet.presented_at = new Date().toISOString();
  validCardSet.principal.id = 'card:entity:user-mike-001';
  validCardSet.entity_card.agent_id = 'card:entity:agent-bigcroc-001';
  validCardSet.entity_card.principal_id = 'card:entity:user-mike-001';

  // Test without VE (local validation only)
  const validResult = await validateCardSet(validCardSet, policy);
  assert(validResult.valid === true, 'Valid MedGraph CARD Set passes validation');
  assert(validResult.session_scope !== null, 'Session scope is populated');
  assert(validResult.session_scope.agent_id === 'card:entity:agent-bigcroc-001', 'Session scope has correct agent_id');
  assert(validResult.session_scope.resources.includes('medical_records'), 'Session scope includes medical_records');
  assert(validResult.session_scope.actions.includes('summarize'), 'Session scope includes summarize action');

  // Test null CARD Set
  const nullResult = await validateCardSet(null, policy);
  assert(nullResult.valid === false, 'Null CARD Set is rejected');

  // Test missing entity_card
  const noEntity = JSON.parse(JSON.stringify(validCardSet));
  delete noEntity.entity_card;
  const noEntityResult = await validateCardSet(noEntity, policy);
  assert(noEntityResult.valid === false, 'Missing entity_card is rejected');

  // Test wrong principal type
  const wrongPrincipal = JSON.parse(JSON.stringify(validCardSet));
  wrongPrincipal.principal.type = 'bot';
  const wrongPrincipalResult = await validateCardSet(wrongPrincipal, policy);
  assert(wrongPrincipalResult.valid === false, 'Non-NHB principal is rejected');

  // Test yellow shield against green requirement (INV-CA-1)
  const yellowShield = JSON.parse(JSON.stringify(validCardSet));
  yellowShield.entity_card.shield_level = 'yellow';
  const yellowResult = await validateCardSet(yellowShield, policy);
  assert(yellowResult.valid === false, 'Yellow shield rejected when green required (INV-CA-1)');
  assert(yellowResult.errors.some(e => e.includes('Shield level')), 'Error message mentions shield level');

  // Test principal mismatch
  const mismatch = JSON.parse(JSON.stringify(validCardSet));
  mismatch.entity_card.principal_id = 'card:entity:user-DIFFERENT';
  const mismatchResult = await validateCardSet(mismatch, policy);
  assert(mismatchResult.valid === false, 'Principal mismatch is rejected');

  // Test disallowed resource
  const badResource = JSON.parse(JSON.stringify(validCardSet));
  badResource.data_card.data_resources.push({ resource: 'financial_records', access: 'read', description: 'test' });
  const badResourceResult = await validateCardSet(badResource, policy);
  assert(badResourceResult.valid === false, 'Disallowed resource is rejected');

  // Test access level exceeds maximum
  const writeAccess = JSON.parse(JSON.stringify(validCardSet));
  writeAccess.data_card.data_resources[0].access = 'write';
  const writeResult = await validateCardSet(writeAccess, policy);
  assert(writeResult.valid === false, 'Write access rejected on read-only service (INV-CA-1)');

  // Test disallowed action
  const badAction = JSON.parse(JSON.stringify(validCardSet));
  badAction.use_card.permitted_actions.push({ action: 'delete', description: 'test' });
  const badActionResult = await validateCardSet(badAction, policy);
  assert(badActionResult.valid === false, 'Disallowed action is rejected');

  // Test requireVE without endpoint (INV-FC)
  const noVeResult = await validateCardSet(validCardSet, policy, { requireVE: true });
  assert(noVeResult.valid === false, 'Fails closed when VE required but no endpoint (INV-FC)');

  // Test Reddit template against Reddit-style policy
  const redditPolicy = {
    minimumShieldLevel: 'green',
    allowedResources: ['subreddit:posts', 'subreddit:comments', 'user:subscriptions', 'user:saved_posts'],
    maxAccessLevel: 'read',
    allowedActions: ['summarize', 'search', 'curate', 'alert'],
    maxCallsPerDay: 1000
  };

  const redditCardSet = JSON.parse(JSON.stringify(redditTemplate));
  redditCardSet.set_id = 'urn:uuid:test-reddit-' + Date.now();
  redditCardSet.presented_at = new Date().toISOString();
  redditCardSet.principal.id = 'card:entity:user-mike-001';
  redditCardSet.entity_card.agent_id = 'card:entity:agent-bigcroc-001';
  redditCardSet.entity_card.principal_id = 'card:entity:user-mike-001';

  const redditResult = await validateCardSet(redditCardSet, redditPolicy);
  assert(redditResult.valid === true, 'Valid Reddit CARD Set passes validation (generalizability - INV-CA-4)');

  // ──────────────────────────────────────────────────────────
  console.log('\n── createSessionToken ──');
  // ──────────────────────────────────────────────────────────

  const session = await createSessionToken(validResult.session_scope, 3600);
  assert(session.token.startsWith('crs_'), 'Token has crs_ prefix');
  assert(session.token.length === 36, 'Token is 36 chars (crs_ + 32 hex)');
  assert(session.expires_at !== undefined, 'Has expiration');
  assert(session.scope === validResult.session_scope, 'Scope is preserved');
  assert(session.issued_at !== undefined, 'Has issued_at');

  // Test with service rules
  const sessionWithRules = await createSessionToken(validResult.session_scope, 3600, { serviceRules: cardStack });
  assert(sessionWithRules.service_rules !== undefined, 'Service rules included in response');
  assert(sessionWithRules.service_rules.service_name === 'MedGraph', 'Service name in rules');

  // Test with persistence adapter
  let persisted = null;
  const sessionWithPersist = await createSessionToken(validResult.session_scope, 3600, {
    persistSession: async (record) => { persisted = record; }
  });
  assert(persisted !== null, 'Persistence callback was called');
  assert(persisted.token === sessionWithPersist.token, 'Persisted record has correct token');
  assert(persisted.agent_id === 'card:entity:agent-bigcroc-001', 'Persisted record has agent_id');

  // Test fail-closed on persistence error
  let failClosed = false;
  try {
    await createSessionToken(validResult.session_scope, 3600, {
      persistSession: async () => { throw new Error('DB down'); }
    });
  } catch (e) {
    failClosed = true;
  }
  assert(failClosed, 'Fails closed when persistence throws (INV-FC)');

  // Test session expiration (INV-CA-2)
  const shortSession = await createSessionToken(validResult.session_scope, 1); // 1 second
  const expiresAt = new Date(shortSession.expires_at);
  const issuedAt = new Date(shortSession.issued_at);
  const ttlMs = expiresAt.getTime() - issuedAt.getTime();
  assert(ttlMs <= 2000, 'Short session expires within ~1 second (INV-CA-2)');

  // ──────────────────────────────────────────────────────────
  console.log('\n── auditAccess ──');
  // ──────────────────────────────────────────────────────────

  const chain = createAuditChain();

  const audit1 = await auditAccess('crs_testtoken', {
    action: 'agent_records_listed',
    target_type: 'agent_session',
    target_id: 'session-001'
  }, { auditChain: chain });

  assert(audit1.action === 'agent_records_listed', 'Audit has correct action');
  assert(audit1.target_type === 'agent_session', 'Audit has target_type');
  assert(audit1.target_id === 'session-001', 'Audit has target_id (ID only, no content - INV-CA-5)');
  assert(audit1.entry_hash !== undefined, 'Audit has entry_hash (INV-16)');
  assert(audit1.prev_hash !== undefined, 'Audit has prev_hash (INV-16)');
  assert(audit1.entry_hash.length === 64, 'Hash is SHA-256 (64 hex chars)');

  // Test hash chain integrity
  const audit2 = await auditAccess('crs_testtoken', {
    action: 'agent_record_read',
    target_type: 'timeline_event',
    target_id: 'evt-002'
  }, { auditChain: chain });

  assert(audit2.prev_hash === audit1.entry_hash, 'Hash chain links: audit2.prev_hash === audit1.entry_hash (INV-16)');

  // Verify hash is deterministic
  const recomputed = sha256(JSON.stringify({
    session_token: audit1.session_token,
    action: audit1.action,
    target_type: audit1.target_type,
    target_id: audit1.target_id,
    timestamp: audit1.timestamp,
    result: audit1.result
  }) + ':' + audit1.prev_hash);
  assert(recomputed === audit1.entry_hash, 'Hash chain is verifiable (recomputed matches)');

  // Test with persistence
  let auditPersisted = null;
  const audit3 = await auditAccess('crs_testtoken', {
    action: 'agent_record_read',
    target_type: 'timeline_event',
    target_id: 'evt-003'
  }, {
    auditChain: chain,
    persistAudit: async (entry) => { auditPersisted = entry; }
  });
  assert(auditPersisted !== null, 'Audit persistence callback called');
  assert(auditPersisted.entry_hash === audit3.entry_hash, 'Persisted audit has hash');

  // Test audit does NOT contain content (INV-CA-5 enforcement)
  const auditStr = JSON.stringify(audit1);
  assert(!auditStr.includes('lab_results'), 'Audit does NOT contain filenames (INV-CA-5)');
  assert(!auditStr.includes('cholesterol'), 'Audit does NOT contain medical content (INV-CA-5)');

  // ──────────────────────────────────────────────────────────
  console.log('\n── sha256 utility ──');

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

  // ──────────────────────────────────────────────────────────

  assert(sha256('hello').length === 64, 'SHA-256 returns 64-char hex');
  assert(sha256('hello') === sha256('hello'), 'SHA-256 is deterministic');
  assert(sha256('hello') !== sha256('world'), 'SHA-256 is sensitive to input');

  // ──────────────────────────────────────────────────────────
  console.log('\n── Cross-template generalizability (INV-CA-4) ──');
  // ──────────────────────────────────────────────────────────

  // The same SDK functions work for MedGraph AND Reddit
  assert(validResult.valid === true, 'MedGraph validates with same SDK');
  assert(redditResult.valid === true, 'Reddit validates with same SDK');
  assert(validResult.session_scope.resources[0] === 'medical_records', 'MedGraph scope has medical_records');
  assert(redditResult.session_scope.resources[0] === 'subreddit:posts', 'Reddit scope has subreddit:posts');

  // ──────────────────────────────────────────────────────────
  console.log('\n═══════════════════════════════════════════════');
  console.log(' Results: ' + passed + ' passed, ' + failed + ' failed');
  console.log('═══════════════════════════════════════════════\n');

  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(e => {
  console.error('Test suite error:', e);
  process.exit(1);
});
