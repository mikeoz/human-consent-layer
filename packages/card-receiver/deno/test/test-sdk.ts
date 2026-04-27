// @opnli/card-receiver — Test Suite (Deno/TypeScript)
// ============================================================
/// <reference path="./deno-shim.d.ts" />
// Tests all SDK functions against the CARD Set schema and the
// MedGraph + Reddit templates. Mirrors the Node v0.2.0 test
// suite (test-sdk.js), adapted for:
//   - async sha256 (Web Crypto)
//   - ES module imports
//   - Deno-native template loading via Deno.readTextFile
//
// Run from the repo root:
//   deno test --allow-read packages/card-receiver/deno/test/test-sdk.ts
// or run as a script:
//   deno run --allow-read packages/card-receiver/deno/test/test-sdk.ts
//
// The test runner here does NOT require deno test framework — it's
// a self-contained script that exits 0 on pass and 1 on fail, the
// same way the Node test suite works. This makes it easier to wire
// into CI alongside the Node tests.
// ============================================================

import {
  auditAccess,
  type CardSet,
  createAuditChain,
  createSessionToken,
  defineServiceRules,
  type PlatformPolicy,
  sha256,
  validateCardSet,
} from "../src/index.ts";

let passed = 0;
let failed = 0;

function assert(condition: boolean, name: string): void {
  if (condition) {
    passed++;
    console.log("  ✅ " + name);
  } else {
    failed++;
    console.log("  ❌ " + name);
  }
}

// Deep clone helper (no structuredClone dependency on older Deno).
function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x));
}

async function loadTemplate(relativePath: string): Promise<CardSet> {
  // Path is relative to the repo root — caller should run tests from there.
  const text = await Deno.readTextFile(relativePath);
  return JSON.parse(text) as CardSet;
}

async function runTests(): Promise<void> {
  console.log("\n═══════════════════════════════════════════════");
  console.log(" @opnli/card-receiver v0.2.0-deno — Test Suite");
  console.log("═══════════════════════════════════════════════\n");

  // Load templates from the repo. Tests are run from repo root.
  const medgraphTemplate = await loadTemplate(
    "templates/medgraph-health.json",
  );
  const redditTemplate = await loadTemplate(
    "templates/reddit-consumer.json",
  );

  // ──────────────────────────────────────────────────────────
  console.log("── defineServiceRules ──");
  // ──────────────────────────────────────────────────────────

  const mgConfig = {
    serviceName: "MedGraph",
    serviceId: "medgraph-001",
    minimumShieldLevel: "green" as const,
    allowedResources: ["medical_records"],
    maxAccessLevel: "read" as const,
    allowedActions: ["summarize", "search", "compare"],
    rateLimit: { requestsPerWindow: 30, windowSeconds: 60 },
    retention: "session_only" as const,
    sessionTtlSeconds: 3600,
    nhbSummary: {
      entity: "BigCROC",
      data: "Your medical records",
      use: "Read and summarize your lab results",
      boundary: "This session only",
    },
  };

  const { policy, cardStack, nhbInvitation } = defineServiceRules(mgConfig);

  assert(
    policy.minimumShieldLevel === "green",
    "Policy has correct shield level",
  );
  assert(
    policy.allowedResources.includes("medical_records"),
    "Policy includes medical_records resource",
  );
  assert(policy.maxAccessLevel === "read", "Policy enforces read-only");
  assert(policy.allowedActions.length === 3, "Policy has 3 allowed actions");
  assert(cardStack.service_name === "MedGraph", "Card stack has service name");
  assert(
    cardStack.retention === "session_only",
    "Card stack enforces session_only retention",
  );
  assert(
    nhbInvitation !== null && nhbInvitation.entity === "BigCROC",
    "NHB invitation has entity line",
  );
  assert(
    nhbInvitation !== null && nhbInvitation.boundary === "This session only",
    "NHB invitation has boundary line",
  );

  // Test validation errors
  let threw = false;
  try {
    // deno-lint-ignore no-explicit-any
    defineServiceRules({} as any);
  } catch {
    threw = true;
  }
  assert(threw, "Throws on empty config");

  threw = false;
  try {
    // deno-lint-ignore no-explicit-any
    defineServiceRules(
      { ...mgConfig, minimumShieldLevel: "platinum" as any },
    );
  } catch {
    threw = true;
  }
  assert(threw, "Throws on invalid shield level");

  // ──────────────────────────────────────────────────────────
  console.log("\n── validateCardSet ──");
  // ──────────────────────────────────────────────────────────

  const validCardSet = clone(medgraphTemplate);
  validCardSet.set_id = "urn:uuid:test-" + Date.now();
  validCardSet.presented_at = new Date().toISOString();
  validCardSet.principal!.id = "card:entity:user-mike-001";
  validCardSet.entity_card!.agent_id = "card:entity:agent-bigcroc-001";
  validCardSet.entity_card!.principal_id = "card:entity:user-mike-001";

  // Test without VE (local validation only)
  const validResult = await validateCardSet(
    validCardSet,
    policy as PlatformPolicy,
  );
  assert(
    validResult.valid === true,
    "Valid MedGraph CARD Set passes validation",
  );
  assert(validResult.session_scope !== null, "Session scope is populated");
  assert(
    validResult.session_scope?.agent_id === "card:entity:agent-bigcroc-001",
    "Session scope has correct agent_id",
  );
  assert(
    validResult.session_scope?.resources.includes("medical_records") ?? false,
    "Session scope includes medical_records",
  );
  assert(
    validResult.session_scope?.actions.includes("summarize") ?? false,
    "Session scope includes summarize action",
  );

  // Test null CARD Set
  const nullResult = await validateCardSet(null, policy as PlatformPolicy);
  assert(nullResult.valid === false, "Null CARD Set is rejected");

  // Test missing entity_card
  const noEntity = clone(validCardSet);
  delete (noEntity as Partial<CardSet>).entity_card;
  const noEntityResult = await validateCardSet(
    noEntity,
    policy as PlatformPolicy,
  );
  assert(noEntityResult.valid === false, "Missing entity_card is rejected");

  // Test wrong principal type
  const wrongPrincipal = clone(validCardSet);
  wrongPrincipal.principal!.type = "bot";
  const wrongPrincipalResult = await validateCardSet(
    wrongPrincipal,
    policy as PlatformPolicy,
  );
  assert(
    wrongPrincipalResult.valid === false,
    "Non-NHB principal is rejected",
  );

  // Test yellow shield against green requirement (INV-CA-1)
  const yellowShield = clone(validCardSet);
  yellowShield.entity_card!.shield_level = "yellow";
  const yellowResult = await validateCardSet(
    yellowShield,
    policy as PlatformPolicy,
  );
  assert(
    yellowResult.valid === false,
    "Yellow shield rejected when green required (INV-CA-1)",
  );
  assert(
    yellowResult.errors.some((e) => e.includes("Shield level")),
    "Error message mentions shield level",
  );

  // Test principal mismatch
  const mismatch = clone(validCardSet);
  mismatch.entity_card!.principal_id = "card:entity:user-DIFFERENT";
  const mismatchResult = await validateCardSet(
    mismatch,
    policy as PlatformPolicy,
  );
  assert(mismatchResult.valid === false, "Principal mismatch is rejected");

  // Test disallowed resource
  const badResource = clone(validCardSet);
  badResource.data_card!.data_resources.push({
    resource: "financial_records",
    access: "read",
    description: "test",
  });
  const badResourceResult = await validateCardSet(
    badResource,
    policy as PlatformPolicy,
  );
  assert(
    badResourceResult.valid === false,
    "Disallowed resource is rejected",
  );

  // Test access level exceeds maximum
  const writeAccess = clone(validCardSet);
  writeAccess.data_card!.data_resources[0].access = "write";
  const writeResult = await validateCardSet(
    writeAccess,
    policy as PlatformPolicy,
  );
  assert(
    writeResult.valid === false,
    "Write access rejected on read-only service (INV-CA-1)",
  );

  // Test disallowed action
  const badAction = clone(validCardSet);
  badAction.use_card!.permitted_actions.push({
    action: "delete",
    description: "test",
  });
  const badActionResult = await validateCardSet(
    badAction,
    policy as PlatformPolicy,
  );
  assert(badActionResult.valid === false, "Disallowed action is rejected");

  // Test requireVE without endpoint (INV-FC)
  const noVeResult = await validateCardSet(
    validCardSet,
    policy as PlatformPolicy,
    { requireVE: true },
  );
  assert(
    noVeResult.valid === false,
    "Fails closed when VE required but no endpoint (INV-FC)",
  );

  // Test Reddit template against Reddit-style policy (INV-CA-4)
  const redditPolicy: PlatformPolicy = {
    minimumShieldLevel: "green",
    allowedResources: [
      "subreddit:posts",
      "subreddit:comments",
      "user:subscriptions",
      "user:saved_posts",
    ],
    maxAccessLevel: "read",
    allowedActions: ["summarize", "search", "curate", "alert"],
    maxCallsPerDay: 1000,
  };

  const redditCardSet = clone(redditTemplate);
  redditCardSet.set_id = "urn:uuid:test-reddit-" + Date.now();
  redditCardSet.presented_at = new Date().toISOString();
  redditCardSet.principal!.id = "card:entity:user-mike-001";
  redditCardSet.entity_card!.agent_id = "card:entity:agent-bigcroc-001";
  redditCardSet.entity_card!.principal_id = "card:entity:user-mike-001";

  const redditResult = await validateCardSet(redditCardSet, redditPolicy);
  assert(
    redditResult.valid === true,
    "Valid Reddit CARD Set passes validation (generalizability - INV-CA-4)",
  );

  // ──────────────────────────────────────────────────────────
  console.log("\n── createSessionToken ──");
  // ──────────────────────────────────────────────────────────

  const session = await createSessionToken(validResult.session_scope!, 3600);
  assert(session.token.startsWith("crs_"), "Token has crs_ prefix");
  assert(session.token.length === 36, "Token is 36 chars (crs_ + 32 hex)");
  assert(session.expires_at !== undefined, "Has expiration");
  assert(session.scope === validResult.session_scope, "Scope is preserved");
  assert(session.issued_at !== undefined, "Has issued_at");

  // Test with service rules
  const sessionWithRules = await createSessionToken(
    validResult.session_scope!,
    3600,
    { serviceRules: cardStack },
  );
  assert(
    sessionWithRules.service_rules !== undefined,
    "Service rules included in response",
  );
  assert(
    sessionWithRules.service_rules?.service_name === "MedGraph",
    "Service name in rules",
  );

  // Test with persistence adapter
  type PersistedRecord = { token: string; agent_id: string };
  const persistedHolder: { value: PersistedRecord | null } = { value: null };
  const sessionWithPersist = await createSessionToken(
    validResult.session_scope!,
    3600,
    {
      persistSession: (record) => {
        persistedHolder.value = {
          token: record.token,
          agent_id: record.agent_id,
        };
        return Promise.resolve();
      },
    },
  );
  assert(persistedHolder.value !== null, "Persistence callback was called");
  assert(
    persistedHolder.value?.token === sessionWithPersist.token,
    "Persisted record has correct token",
  );
  assert(
    persistedHolder.value?.agent_id === "card:entity:agent-bigcroc-001",
    "Persisted record has agent_id",
  );

  // Test fail-closed on persistence error
  let failClosed = false;
  try {
    await createSessionToken(validResult.session_scope!, 3600, {
      persistSession: () => Promise.reject(new Error("DB down")),
    });
  } catch {
    failClosed = true;
  }
  assert(failClosed, "Fails closed when persistence throws (INV-FC)");

  // Test session expiration (INV-CA-2)
  const shortSession = await createSessionToken(
    validResult.session_scope!,
    1,
  );
  const expiresAt = new Date(shortSession.expires_at);
  const issuedAt = new Date(shortSession.issued_at);
  const ttlMs = expiresAt.getTime() - issuedAt.getTime();
  assert(ttlMs <= 2000, "Short session expires within ~1 second (INV-CA-2)");

  // ──────────────────────────────────────────────────────────
  console.log("\n── auditAccess ──");
  // ──────────────────────────────────────────────────────────

  const chain = createAuditChain();

  const audit1 = await auditAccess(
    "crs_testtoken",
    {
      action: "agent_records_listed",
      target_type: "agent_session",
      target_id: "session-001",
    },
    { auditChain: chain },
  );

  assert(
    audit1.action === "agent_records_listed",
    "Audit has correct action",
  );
  assert(audit1.target_type === "agent_session", "Audit has target_type");
  assert(
    audit1.target_id === "session-001",
    "Audit has target_id (ID only, no content - INV-CA-5)",
  );
  assert(audit1.entry_hash !== undefined, "Audit has entry_hash (INV-16)");
  assert(audit1.prev_hash !== undefined, "Audit has prev_hash (INV-16)");
  assert(
    audit1.entry_hash?.length === 64,
    "Hash is SHA-256 (64 hex chars)",
  );

  // Test hash chain integrity
  const audit2 = await auditAccess(
    "crs_testtoken",
    {
      action: "agent_record_read",
      target_type: "timeline_event",
      target_id: "evt-002",
    },
    { auditChain: chain },
  );

  assert(
    audit2.prev_hash === audit1.entry_hash,
    "Hash chain links: audit2.prev_hash === audit1.entry_hash (INV-16)",
  );

  // Verify hash is deterministic — recompute audit1's entry_hash from
  // its own fields and prev_hash. Must match.
  const recomputed = await sha256(
    JSON.stringify({
      session_token: audit1.session_token,
      action: audit1.action,
      target_type: audit1.target_type,
      target_id: audit1.target_id,
      timestamp: audit1.timestamp,
      result: audit1.result,
    }) + ":" + audit1.prev_hash,
  );
  assert(
    recomputed === audit1.entry_hash,
    "Hash chain is verifiable (recomputed matches)",
  );

  // Test with persistence
  type PersistedAudit = { entry_hash: string };
  const auditPersistedHolder: { value: PersistedAudit | null } = { value: null };
  const audit3 = await auditAccess(
    "crs_testtoken",
    {
      action: "agent_record_read",
      target_type: "timeline_event",
      target_id: "evt-003",
    },
    {
      auditChain: chain,
      persistAudit: (entry) => {
        if (entry.entry_hash) {
          auditPersistedHolder.value = { entry_hash: entry.entry_hash };
        }
        return Promise.resolve();
      },
    },
  );
  assert(
    auditPersistedHolder.value !== null,
    "Audit persistence callback called",
  );
  assert(
    auditPersistedHolder.value?.entry_hash === audit3.entry_hash,
    "Persisted audit has hash",
  );

  // Test audit does NOT contain content (INV-CA-5 enforcement)
  const auditStr = JSON.stringify(audit1);
  assert(
    !auditStr.includes("lab_results"),
    "Audit does NOT contain filenames (INV-CA-5)",
  );
  assert(
    !auditStr.includes("cholesterol"),
    "Audit does NOT contain medical content (INV-CA-5)",
  );

  // ──────────────────────────────────────────────────────────
  console.log("\n── sha256 utility ──");
  // ──────────────────────────────────────────────────────────

  assert((await sha256("hello")).length === 64, "SHA-256 returns 64-char hex");
  assert(
    (await sha256("hello")) === (await sha256("hello")),
    "SHA-256 is deterministic",
  );
  assert(
    (await sha256("hello")) !== (await sha256("world")),
    "SHA-256 is sensitive to input",
  );

  // Cross-implementation parity: SHA-256 of "hello" is well-known.
  assert(
    (await sha256("hello")) ===
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "SHA-256('hello') matches reference value (Node/Deno parity)",
  );

  // ──────────────────────────────────────────────────────────
  console.log("\n── Cross-template generalizability (INV-CA-4) ──");
  // ──────────────────────────────────────────────────────────

  assert(validResult.valid === true, "MedGraph validates with same SDK");
  assert(redditResult.valid === true, "Reddit validates with same SDK");
  assert(
    validResult.session_scope?.resources[0] === "medical_records",
    "MedGraph scope has medical_records",
  );
  assert(
    redditResult.session_scope?.resources[0] === "subreddit:posts",
    "Reddit scope has subreddit:posts",
  );

  // ──────────────────────────────────────────────────────────
  console.log("\n═══════════════════════════════════════════════");
  console.log(" Results: " + passed + " passed, " + failed + " failed");
  console.log("═══════════════════════════════════════════════\n");

  Deno.exit(failed > 0 ? 1 : 0);
}

runTests().catch((e: unknown) => {
  console.error("Test suite error:", e);
  Deno.exit(1);
});
