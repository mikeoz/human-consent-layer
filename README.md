# The Human Consent Layer

**An open standard for giving humans real-time, machine-enforced control over what AI agents do with their data.**

The Human Consent Layer (HCL) is the consent infrastructure for the Agent Economy. It converts a human decision — Allow or Deny — into a machine-enforceable, auditable event. Every agent action that touches human data passes through a consent gate. Every decision is recorded in a tamper-evident chain. Every authorization is revocable.

MCP standardized how agents discover and call tools. WebMCP is bringing that to the browser. Neither addresses what happens between the tool call and the human: did the human say yes, did they understand what they were saying yes to, and can they verify the record later?

The HCL is that missing layer.

*My data + Your AI + My control = Living Intelligence*

---

## The Four-Link Consent Chain

Every HCL consent decision passes through four links. Each link depends on the one before it. Break any link and the consent is invalid.

**Link 1 — Human Initiation.** An action that requires consent begins only when a human initiates it — directly or through an explicit standing authorization. No automated process may substitute for human initiation.

**Link 2 — Context Required.** The consent decision cannot be solicited without presenting the context on which it depends. No Allow/Deny button appears without the information the human needs to decide.

**Link 3 — CARDs Provide the Context.** The context is structured as four CARDs (Community Approved Reliable Data): Entity (who is acting), Data (what data is involved), Use (for what purpose), and Boundary (under what limits). CARDs are simultaneously machine-validatable and human-readable.

**Link 4 — The HCL Enforces the Decision.** The decision is machine-enforced at the point of action. Every attempted action produces a record in the tamper-evident audit chain. If the audit record cannot be written, the action cannot proceed.

---

## The CARD Model

Every trust-relevant entity in the HCL is represented by a CARD — a structured credential with four parts that answer four questions:

| CARD | Question | Example |
|------|----------|---------|
| **Entity** | Who is acting? | Agent name, operator, model, verification state |
| **Data** | What data is involved? | Files the agent can access, read/write scope |
| **Use** | For what purpose? | Summarize, search, answer questions — not train |
| **Boundary** | Under what limits? | This session only, fail-closed on timeout |

A CARD Set — four CARDs wrapped together — is the unit of authorization. An agent cannot act under one CARD without the other three.

The CARD schemas are in [`schema/`](schema/).

---

## Shield Conformance Levels

The HCL defines three conformance levels. The human always knows which level they are receiving.

| Shield | Consent Model | When the Human Decides |
|--------|--------------|----------------------|
| **Green Shield** | Consent Before Execution | Before the action occurs. The action does not execute until the human authorizes it. |
| **Yellow Shield** | Consent Before Delivery | After the action executes but before the result is delivered. The human controls delivery. |
| **Red Shield** | Non-conformant | No external consent mechanism. Warning label required. |

Green is strictly stronger than Yellow. The HCL defaults to the strongest level the platform supports. Yellow Shield does not pretend to be Green. This is the honesty principle.

---

## Five System Invariants

The HCL maintains five properties at all times, not just at decision time:

**INV-FC — Fail-Closed.** If the consent gate cannot confirm consent, or if the audit record cannot be written, the action does not execute. There is no fail-open mode.

**INV-TE — Tamper-Evident.** Every decision produces a SHA-256 hash that incorporates the previous decision's hash, forming a chain. Modification of any historical record breaks the chain at a detectable point.

**INV-AMF — Allow Means Forward, Deny Means Block.** Allow causes the action to proceed. Deny causes the action to be blocked. There is no partially-allowed state. There is no denied-but-executed-anyway state.

**INV-3L — Three-Layer Separation.** Enforcement happens at the interface layer (where the agent acts), not at the dashboard (which only aggregates and displays). The dashboard cannot enforce, by design.

**INV-MA — Model-Agnostic.** The consent gate, audit trail, and enforcement operate identically regardless of which AI model, provider, or runtime is underneath. The HCL does not depend on any model's capabilities or any provider's policies.

---

## What's in This Repo

human-consent-layer/
├── SPEC.md # The normative HCL specification
├── schema/
│ ├── card-credential.schema.json # CARD credential schema
│ └── card-set.schema.json # CARD Set schema
├── packages/
│ └── atl-devkit/ # DevKit — add HCL consent to any agent
│ ├── src/
│ │ ├── index.js
│ │ ├── consent-gate.js
│ │ ├── audit-logger.js
│ │ └── present-cards.js
│ ├── package.json
│ └── README.md
├── templates/
│ ├── medgraph-health.json # Example: health data CARD Set
│ └── reddit-consumer.json # Example: consumer platform CARD Set
├── CONTRIBUTING.md
└── LICENSE # Apache 2.0


**SPEC.md** — The normative specification defining the four-link consent chain, the CARD model, the Shield conformance levels, and the five invariants.

**schema/** — JSON Schema definitions for CARD credentials and CARD Sets. These are the machine-readable formats that agents and platforms use to present and validate trust context.

**packages/atl-devkit/** — The Developer Kit. An npm module that adds HCL consent gating to any AI agent platform. See the [DevKit README](packages/atl-devkit/README.md) for the API and quick start.

**templates/** — Example CARD Sets for common use cases: health data sharing, consumer platform integration.

---

## The Three Realities of Trust

The HCL is founded on three realities:

1. **Trust is a human emotion.** It cannot be computed by a machine. Security frameworks catalog threats. The HCL gives the human the ability to decide.

2. **Trust requires transparency.** The human must see who is acting, what they want to do, and what limits apply — before they decide. CARDs provide this transparency.

3. **Trust is a choice that must be enforced.** The human's Allow or Deny is not advisory. It is machine-enforced. No code path exists to override a denial.

---

## How the HCL Relates to Other Frameworks

The HCL is complementary to existing agent security work, not a replacement for any of it.

| Layer | Function | Examples |
|-------|----------|---------|
| Threat identification | Catalog risks | OWASP Agentic AI Top 10 |
| Deployment scoping | Classify architectures | AWS Scoping Matrix |
| Design constraints | Constrain agent architecture | Meta Rule of Two |
| Sandbox isolation | Isolate execution | NVIDIA NemoClaw |
| Tool discovery | Standardize agent-to-site calls | WebMCP |
| **Human consent** | **Enforce the human's decision** | **HCL** |

SSL secured the pipe. OAuth secured the handshake. WebMCP standardizes the tool call. The HCL secures the human's authority over what happens next.

---

## Reference Implementation

[CROCbox](https://github.com/mikeoz/crocbox) is the reference implementation of the HCL for OpenClaw agents — a desktop application that wraps OpenClaw with a complete consent layer including Green Shield enforcement, tamper-evident audit, and Trust Network integration.

[MyDataBkt](https://github.com/mikeoz/mydatabkt) is the reference implementation for consent-gated personal data storage — your data, on your machine, with consent-gated read and write through the HCL.

---

## Related

- [W3C Position Paper — The Agent Trust Layer](https://github.com/mikeoz/human-consent-layer/blob/main/SPEC.md) (see SPEC.md)
- [CROCbox](https://github.com/mikeoz/crocbox) — HCL reference implementation for OpenClaw
- [MyDataBkt](https://github.com/mikeoz/mydatabkt) — Consent-gated personal data bucket
- [opn.li](https://opn.li) — The Openly Trusted Network
- [openlytrusted.ai](https://openlytrusted.ai) — Give trust a try

---

## License

Apache 2.0 — Opnli Corporation

Certain enforcement mechanisms implemented in products built on this specification are the subject of [Provisional Patent Application #63/992,579](https://opn.li) filed February 27, 2026. The HCL specification and schemas in this repository are open and freely implementable under the Apache 2.0 license.

---

*Only a human can give consent. Consent requires context. CARDs provide context. The Human Consent Layer enforces the decision.*
