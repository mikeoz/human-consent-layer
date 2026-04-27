# @opnli/card-receiver — Deno/TypeScript Port

CARD Receiver SDK for Deno HTTP handlers and Supabase Edge Functions. Behavioral parity with the Node SDK at `packages/card-receiver/src/`, with two intentional differences:

1. **`sha256()` is async** (Web Crypto API)
2. **`verifyEntityWithVE()` matches the live VE contract** at `ve-staging.opn.li` (six-field schema with SHA-256 request hash) — see the *VE Contract* section below.

The Node and Deno builds share the same logic, the same test vectors, and the same invariant enforcement (INV-CA-1 through INV-CA-6, INV-FC, INV-16, INV-NEVER-3 / INV-CA-5).

---

## Layout

```
packages/card-receiver/deno/
├── src/
│   ├── card-set-validator.ts   # validateCardSet, verifyEntityWithVE,
│   │                           # createSessionToken, auditAccess,
│   │                           # sha256, createAuditChain
│   ├── service-rules.ts        # defineServiceRules
│   ├── middleware.ts           # cardReceiverHandle (Deno HTTP)
│   └── index.ts                # public entry point
├── test/
│   └── test-sdk.ts             # 60+ assertions, mirrors Node test-sdk.js
├── deno.json
└── README.md
```

---

## Install Deno (one-time, on the dev machine)

macOS:

```bash
brew install deno
```

Or via the official installer:

```bash
curl -fsSL https://deno.land/install.sh | sh
```

Verify:

```bash
deno --version
```

Supabase Edge Functions ship Deno as their runtime, so once the SDK is deployed to Supabase the runtime install is handled by Supabase itself.

---

## Run the Tests

From the `human-consent-layer` repo root:

```bash
deno task --config packages/card-receiver/deno/deno.json test
```

Or the explicit form:

```bash
deno run --allow-read --allow-net packages/card-receiver/deno/test/test-sdk.ts
```

The tests load the MedGraph and Reddit CARD Set templates from `templates/` (relative to repo root). They do not call the live VE — VE behavior is verified separately via the `verifyEntityWithVE()` contract documented below.

Expected output: `Results: 60+ passed, 0 failed`. Exit code 0 on success, 1 on any failure.

---

## Quick Start — Supabase Edge Function

```typescript
// supabase/functions/agent-authorize/index.ts
import { serve } from "https://deno.land/std/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  defineServiceRules,
  validateCardSet,
  createSessionToken,
} from "../../packages/card-receiver/deno/src/index.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

// Define MedGraph's service rules once at module load
const { policy, cardStack, nhbInvitation } = defineServiceRules({
  serviceName: "MedGraph",
  serviceId: "medgraph-001",
  minimumShieldLevel: "green",
  allowedResources: ["medical_records"],
  maxAccessLevel: "read",
  allowedActions: ["summarize", "search", "compare"],
  rateLimit: { requestsPerWindow: 30, windowSeconds: 60 },
  retention: "session_only",
  sessionTtlSeconds: 3600,
  nhbSummary: {
    entity: "BigCROC (your CROCbox AI agent)",
    data: "Your medical records stored in MedGraph",
    use: "Read and summarize your lab results",
    boundary: "This session only — no data retained",
  },
});

serve(async (req) => {
  const { cardSet } = await req.json();

  // Validate against MedGraph's policy + the VE
  const result = await validateCardSet(cardSet, policy, {
    veEndpoint: "https://ve-staging.opn.li/v1/verify",
    requireVE: true,
  });

  if (!result.valid) {
    return new Response(JSON.stringify({ errors: result.errors }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Issue scoped session token; persist to agent_sessions
  const session = await createSessionToken(result.session_scope!, 3600, {
    serviceRules: cardStack,
    persistSession: async (record) => {
      const { error } = await supabase.from("agent_sessions").insert({
        session_token: record.token,
        agent_id: record.agent_id,
        agent_name: record.agent_name,
        user_id: record.principal_id,
        allowed_ops: record.allowed_ops,
        expires_at: record.expires_at,
      });
      if (error) throw error;
    },
  });

  return new Response(JSON.stringify(session), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
});
```

---

## VE Contract (verified empirically against ve-staging.opn.li, 27APR26)

`verifyEntityWithVE()` posts the following body to the VE endpoint:

```json
{
  "agent_id": "<enrolled agent identifier>",
  "card_id": "<the CARD Set's set_id>",
  "operation_type": "api_call",
  "session_id": "ve-verify-<uuid>",
  "timestamp": "<ISO 8601 UTC, generated at request time>",
  "request_hash": "<SHA-256 hex of agent_id + card_id + operation_type + session_id + timestamp>"
}
```

Constraints enforced by the VE:

| Field | Rule |
|---|---|
| `operation_type` | Must be one of: `web_search`, `filesystem_read`, `filesystem_write`, `shell_exec`, `api_call` |
| `timestamp` | Must be within 30 seconds of VE server time |
| `request_hash` | Must be SHA-256 over the canonical concatenation, lowercase hex |
| `agent_id` | Must be enrolled with the VE |

The Deno SDK fails closed (returns `{ verified: false }`) on any of: network error, timeout, abort, non-2xx response, malformed response. INV-FC is preserved.

---

## Differences From The Node SDK

| Concern | Node | Deno |
|---|---|---|
| `sha256()` | Synchronous (`crypto.createHash`) | Async (`crypto.subtle.digest`) |
| Module syntax | CommonJS (`require` / `module.exports`) | ES modules (`import` / `export`) |
| File extensions | `.js` | `.ts` |
| Express middleware | `cardReceiverMiddleware()` returns Express middleware | `cardReceiverHandle(req, config)` returns `{ ok, session }` or `{ ok: false, response }` |
| Random bytes | `Math.random` (legacy) | `crypto.getRandomValues` (cryptographically secure) |
| VE call | **Latent bug** — sends 4-field payload that the live VE rejects | **Fixed** — sends 6-field payload with SHA-256 request_hash |

A patch bringing the Node SDK's `verifyEntityWithVE()` in line with the corrected Deno version is shipped in the same Session C deliverable as `patches/node-sdk-verifyEntityWithVE-fix.md`. After applying the patch, both SDKs are functionally equivalent against the live VE.

---

*v0.2.0-deno — Session C, April 27, 2026*
