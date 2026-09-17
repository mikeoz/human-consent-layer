# Human Consent Layer — Specification

**Version:** 1.0-draft
**Date:** September 2026
**Status:** Draft — Open for community review
**License:** Apache 2.0

---

## 1. Purpose

This document is the normative specification of the Human Consent Layer (HCL). It defines what the HCL is, what properties it maintains, and what a conformant implementation must do. It is written for two audiences: developers building HCL-conformant agents and platforms, and technical reviewers evaluating the HCL against other approaches.

This document describes the standard — the WHAT. It does not describe the internals of any specific implementation. Reference implementations are listed in Section 11.

---

## 2. The Problem

Software systems in which one entity acts on behalf of another — an AI agent executing a tool call, a service processing personal data, a tracker collecting behavioral signals — require a mechanism by which the human authorizes the action. The mechanisms currently in wide use do not produce authorizations that are simultaneously human-meaningful, contextually accurate, machine-enforceable, and verifiable after the fact.

**Terms-of-Service consent** produces a legal artifact at account creation but does not produce an operational constraint at the moment of action. The behaviors covered by the ToS are opaque at the time of consent.

**OAuth scope delegation** names the capability being granted, but the naming is at the wrong granularity. "Read email" is the same scope whether the agent reads one message at the user's direction or exports every message for external processing. The scope is granted once and applies to all subsequent calls.

**Model-runtime guardrails** operate inside the AI model's output path. They do not represent the human, do not persist a decision beyond the session, and do not produce an audit artifact the human can verify. The human is the recipient of the guardrail's output, not the principal whose decision the guardrail enforces.

The consequence is that a substantial category of agent action happens either without real consent or with a synthetic consent that would not survive honest inspection.

---

## 3. Four Properties of a Valid Consent Primitive

A consent primitive suitable for governing AI agent actions must produce authorizations with four properties. Each is testable.

**Human-meaningful.** The human can accurately describe, in their own words, what they are authorizing at the moment they authorize it. Test: ask the human to explain, thirty seconds after deciding, what they just consented to. If the answer is structurally wrong, the primitive failed.

**Contextually accurate.** The authorization is bound to a specific context: the entity acting, the data involved, the purpose it serves, and the limits within which it operates. Changes to any element require new authorization. Test: if the acting entity changes its behavior without re-asking, has the consent been violated? If yes, the primitive is contextually accurate.

**Machine-enforceable.** The authorization state is readable by the enforcement mechanism at the moment of action, and the enforcement mechanism honors it. Test: if the human revokes, does the next attempted action fail closed? If yes, machine-enforceable.

**After-the-fact verifiable.** The human can inspect, days or months later, the record of a specific consent decision and confirm that the record has not been altered. Test: can the human, using only tools they control, verify that the record is identical to the record as it was written?

Terms-of-Service consent fails every property except a weak form of the first. OAuth delegation satisfies the third but fails the second and fourth. Model-runtime guardrails fail all four when measured from the human's perspective.

---

## 4. The Four-Link Consent Chain

The HCL is defined by four operational links. Each link is a precondition for the next. The absence of any link invalidates the consent.

### 4.1 Link 1 — Human Initiation

An action that requires consent begins only when a human principal initiates it, either by directly instructing the agent or by establishing a standing authorization within an explicit scope. No automated process, no aggregate-consent inference, and no "reasonable default" may substitute for this initiation.

The enforcement test: can a non-human process produce an Allow state without a human in the loop? If yes, Link 1 is broken.

### 4.2 Link 2 — Context Required

The consent decision cannot be solicited without presenting the context on which the decision depends. The context is the CARD Set (Section 5). Any consent UI that offers an Allow/Deny choice without rendering the corresponding Entity, Data, Use, and Boundary content fails Link 2.

The test: can the human answer the four CARD questions in their own words immediately before deciding? If not, Link 2 is broken.

### 4.3 Link 3 — CARDs Provide the Context

The context must be structured as the four CARDs — not as an ad-hoc description, not as a scope string, not as a policy document. Ad-hoc descriptions are not machine-interpretable. Scope strings are not human-interpretable. The CARD Set is the only format that is simultaneously machine-validatable and human-readable.

The test: can both the platform's CARD validation logic and the human principal read the same credential and reach consistent conclusions about what is being authorized? If not, Link 3 is broken.

### 4.4 Link 4 — HCL Enforces the Decision

The decision must be machine-enforced at the point of action. Every attempted action must produce a record in the tamper-evident audit chain. Enforcement takes one of three forms: in-line enforcement (the action is blocked), proxy enforcement (the platform issues a constrained session token), or queued enforcement with fail-closed default (the action is denied until the decision is made or times out).

The audit record is not optional. If the audit record cannot be written, the decision cannot be enforced, and therefore the action cannot occur.

The test: if the audit subsystem fails, does the consent gate also fail — closed? If yes, Link 4 is intact.

### 4.5 The Chain

The four links are chained: each depends on the previous. Link 4 enforcement is meaningful only if Link 3 context is correct. Link 3 context is meaningful only if Link 2 required it. Link 2 is meaningful only if Link 1 happened.

A system that implements Link 4 without Link 1 is a policy engine, not a consent layer. A system that implements Links 1 and 4 without 2 and 3 is a signed-authorization system, not a consent layer. All four are required. Any system that claims to implement the HCL can be tested on all four.

---

## 5. The CARD Model

### 5.1 The Four CARDs

Every trust-relevant entity in the HCL is represented by a CARD (Community Approved Reliable Data) — a structured credential with four parts. The four parts answer four questions the human must answer before authorizing an action:

| CARD | Question | Content |
|------|----------|---------|
| **Entity** | Who is acting? | Identity of the agent: name, operator, model, authorization chain, verification state. |
| **Data** | What data is involved? | The specific data the entity will read, write, or process. Scope, sensitivity, storage location. |
| **Use** | For what purpose? | The declared purpose: summarize, search, answer questions, execute commands. What is permitted and what is prohibited. |
| **Boundary** | Under what limits? | Time windows, rate limits, geographic scope, session duration, spending caps. When the authorization expires. |

### 5.2 Why Four

The choice of four CARDs corresponds to the minimum number of questions a human must answer to give contextually accurate consent (Section 3, second property).

Fewer than four loses critical context. A three-CARD model that omits Boundary allows an entity to act indefinitely. A three-CARD model that omits Use prevents the human from distinguishing beneficial from adversarial data access.

More than four introduces categories that are either redundant (a "Risk" CARD is a property of Boundary) or operator-specific (a "Compliance" CARD is a third-party concern, not a principal concern).

The four correspond to four well-formed questions in natural language: Who, What, What for, What limits. This linguistic correspondence is what makes the model human-legible without a translation layer.

### 5.3 The CARD as Credential

A CARD is a credential in the formal sense: it is issued by an authority (the Trust Network Operator), it represents a verified claim, and it can be presented, inspected, and revoked. The CARD credential schema is published in this repository under `schema/` and is formatted as JSON Schema. The CARD schema includes interoperability hooks (`delegation_vrcs`) for integration with decentralized trust graph systems.

### 5.4 The CARD Set

A CARD Set — four CARDs wrapped together with a principal signature, a timestamp, and a Trust Network Operator attestation — is the unit of authorization. When an agent seeks to operate within a platform, it presents its CARD Set. The platform validates each CARD. On valid presentation, a scoped session token is issued. Every subsequent action carries the session token and, by reference, the CARD Set that authorized it.

### 5.5 The Same Pattern Across Domains

The CARD model applies identically across trust domains:

| Element | AI Agent | Web Tracking | Service |
|---------|----------|-------------|---------|
| **Entity** | BigCROC / authorized by Mike / Claude Sonnet | doubleclick.net / Google / advertising | MedGraph / Healthcare AI / HIPAA |
| **Data** | Documents folder read, web search | Cookie IDE, cross-site tracking identifier | Medical records the patient authorizes |
| **Use** | Summarize, search, answer — not train | Targeted advertising across 47 sites | Answer health questions, surface research |
| **Boundary** | This session / fail-closed on timeout | 13 months / cross-site / GDPR scope | Session-scoped / no retention |

A human who learns to read CARDs for one domain can read CARDs for any other domain without retraining. The rendering is configurable; the pattern is invariant.

---

## 6. Shield Conformance Levels

The HCL defines three conformance levels. Not all platforms provide identical consent hooks. The Shield model accommodates this reality while requiring honesty about what level the human is receiving.

### 6.1 Green Shield — Consent Before Execution (CBE)

The action does not execute until the human authorizes it. The human decides whether the action happens.

**Conformance level:** MUST (normative). This is full HCL conformance.

**Platform requirement:** The platform must provide pre-execution hooks — a mechanism by which the consent layer can intercept an action before it occurs.

### 6.2 Yellow Shield — Consent Before Delivery (CBD)

The action executes, but the result is held pending the human's decision. The human decides whether the result is delivered and whether future actions are permitted.

**Conformance level:** SHOULD (conformant). This is partial conformance with mandatory labeling.

**Platform requirement:** The platform must provide a post-execution event stream with tool detection capability.

**Honesty requirement:** Yellow Shield implementations MUST display the Yellow Shield indicator. Yellow Shield MUST NOT be presented as Green Shield. The human must know the action has already executed.

### 6.3 Red Shield — Non-Conformant

No external consent mechanism is available. The human is informed but not in control.

**Conformance level:** Non-conformant. Warning label required.

### 6.4 The Honesty Principle

The human always knows which Shield level they are receiving. The Shield indicator is visible at all times during agent operation, not only during consent events. A system that hides the Shield level, or that misrepresents Yellow as Green, is non-conformant regardless of its technical implementation.

---

## 7. System Invariants

The HCL maintains five properties at all points in the system's operation, not just at decision time. Each invariant is stated as a precondition-postcondition pair with a test.

### 7.1 INV-FC — Fail-Closed

**Precondition:** An action requires consent but the consent gate cannot confirm consent within the timeout window, OR the audit record cannot be written.

**Postcondition:** The action does not execute.

**Test:** Disable the audit chain writer. Attempt any consent-requiring action. Verify the action does not execute.

### 7.2 INV-TE — Tamper-Evident

**Precondition:** Any party modifies a historical audit entry in any field.

**Postcondition:** The hash chain breaks at a detectable point. Any verifier correctly reports the chain as invalid, identifying the entry where modification occurred.

**Test:** Modify any field of any audit entry. Run the chain verifier. Confirm it reports the exact point of corruption.

### 7.3 INV-AMF — Allow Means Forward, Deny Means Block

**Precondition:** The consent gate records a decision.

**Postcondition:** Allow causes the action to proceed to its intended effect. Deny causes the action to be blocked. There is no partially-allowed state. There is no denied-but-executed-anyway state.

**Test:** Click Deny. Verify the action does not execute. Click Allow. Verify the action does execute and produces its intended result.

### 7.4 INV-3L — Three-Layer Separation

**Precondition:** The system has a network layer (Trust Network), an interface layer (products where consent is captured and enforced), and an aggregation layer (the dashboard).

**Postcondition:** Enforcement happens at the interface layer only. The aggregation layer never enforces — it only aggregates and displays. The network layer validates identities but does not hold per-decision enforcement state.

**Test:** Attempt to trigger enforcement from the dashboard without the interface-layer product. Verify no enforcement occurs.

### 7.5 INV-MA — Model-Agnostic Enforcement

**Precondition:** An AI agent operating under the HCL switches between underlying models, providers, or runtimes.

**Postcondition:** The consent gate, audit trail, and enforcement operate identically. The HCL does not depend on any specific model's capabilities or any specific provider's policies.

**Test:** Configure with provider A. Run all consent gate tests. Switch to provider B. Re-run. Verify identical behavior.

---

## 8. The Verification Endpoint

The Verification Endpoint (VE) is the network-layer service that validates CARDs against the Trust Network's enrollment record. Its role is narrow by design: it validates that an entity is enrolled, that its CARDs are current, and that it has not been revoked. It does not hold per-decision state and does not make policy decisions about whether an action should proceed.

### 8.1 Fail-Closed Semantics

A caller that receives a non-success response, a network timeout, or a service unavailability response MUST treat the result as a denial of access. There is no fail-open mode. A caller that cannot determine authorization status with certainty MUST deny access.

### 8.2 Trust Network Catalog

The Trust Network catalog is the directory of verified entities. Each entry contains the entity's identity, type, CARD Set, and certification level. The catalog provides aggregate consent signals — summary statistics on consent patterns — while preserving individual privacy. No query path exists that links a specific human to a specific entity's consent rate.

---

## 9. Normative Requirements for Conformant Implementations

An implementation claiming HCL conformance MUST satisfy the following:

**MUST** provide a consent gate that holds agent actions pending human decision (Allow/Deny).

**MUST** present CARD context (Entity, Data, Use, Boundary) before soliciting the consent decision.

**MUST** maintain a tamper-evident audit log recording every consent decision with SHA-256 hash chain integrity.

**MUST** implement fail-closed behavior: timeout or system failure results in Deny, not Allow.

**MUST** display the Shield conformance level (Green/Yellow/Red) honestly to the human at all times during agent operation.

**MUST** enforce the human's Deny decision with no override mechanism.

**SHOULD** implement Consent Before Execution (Green Shield) where the platform provides pre-execution hooks.

**SHOULD** integrate with a Verification Endpoint for Trust Network enrollment and real-time trust verification.

**MAY** implement adaptive enforcement that selects the strongest available consent level based on platform capabilities detected at runtime.

**MAY** implement standing consent — durable authorizations for specific CARD contexts that auto-allow without re-prompting, reviewable and revocable at any time.

---

## 10. Comparisons

The HCL occupies a specific position in the agent trust landscape. It is complementary to, not a replacement for, existing frameworks.

### 10.1 vs. Model-Runtime Guardrails

Guardrails operate inside the model's inference pipeline, enforcing the provider's safety policy. The HCL operates outside the model, enforcing the human's consent decision. The guardrail represents the provider. The HCL represents the human. Both can operate simultaneously.

### 10.2 vs. OAuth Scope Delegation

OAuth grants a named scope once, enforced on all subsequent calls. The HCL operates at the action level with CARD context on every call. OAuth is machine-enforceable but not contextually accurate or after-the-fact verifiable. The HCL satisfies all four properties (Section 3).

### 10.3 vs. Policy Engines (OPA, Cedar)

Policy engines evaluate authorization against declarative rules written by administrators. The HCL captures consent from the human principal at action time. A policy engine expresses organizational policy. The HCL expresses human consent. A system that uses a policy engine as its consent layer has made a category error: organizational policy is not human consent.

### 10.4 vs. Agent Orchestration Platforms

Orchestration platforms (LangChain, CrewAI, LangGraph) coordinate multi-step agent tasks. They do not define a consent primitive. The HCL is orthogonal to orchestration — an orchestration platform can run HCL-gated agents without modification.

### 10.5 vs. Sandbox Isolation

Sandbox systems (NVIDIA NemoClaw/OpenShell) isolate the agent's execution environment. The HCL gives the human visibility into and control over what the agent does within that environment. The sandbox is the seatbelt engineered into the chassis. The HCL is the seatbelt the driver can see and control.

---

## 11. Reference Implementations

**CROCbox** ([github.com/mikeoz/crocbox](https://github.com/mikeoz/crocbox)) — The first complete HCL implementation. Wraps OpenClaw with Green Shield consent enforcement, tamper-evident audit, and Trust Network integration. Desktop application for macOS.

**MyDataBkt** ([github.com/mikeoz/mydatabkt](https://github.com/mikeoz/mydatabkt)) — Consent-gated personal data storage. Your data stays on your machine. Read and write operations are gated by the HCL consent chain with signed proofs.

**Opnli Native Chat** ([opn.li](https://opn.li)) — Browser-based AI chat with Green Shield consent on every tool call (search, fetch, file analysis, bucket read/write), five-choice consent card, standing rules, and hash-chained audit. All major model families supported.

---

## 12. Open Questions

The following are known gaps. Each will be addressed; none are addressed today.

**Cross-TNO federation.** The current implementation assumes a single Trust Network Operator. Multi-TNO federation — where CARDs issued by one operator are validated by another — is specified but not implemented.

**Cross-device conflict resolution.** Concurrent consent decisions from multiple devices (revoke on laptop, allow on phone before sync) require conflict resolution beyond last-write-wins.

**Notification channels.** Alerts for consent events currently require visiting the dashboard. Push notifications, email digests, and browser badge counts are specified but not implemented.

**Accessibility.** The consent UI targets WCAG 2.1 AA but has not been formally audited.

---

## 13. Glossary

| Term | Definition |
|------|-----------|
| **Agent Economy** | A market structure in which AI agents act as intermediaries between humans and platforms, under explicit human authorization with machine-enforceable constraints. |
| **ATL** | Agent Trust Layer. The product-line name for the HCL plus supporting infrastructure. |
| **CARD** | Community Approved Reliable Data. A structured credential with four parts: Entity, Data, Use, Boundary. |
| **CARD Set** | Four CARDs wrapped together as a unit of authorization. |
| **CBE** | Consent Before Execution. Green Shield mode. |
| **CBD** | Consent Before Delivery. Yellow Shield mode. |
| **DevKit** | The open-source developer toolkit for adding HCL consent to agents and platforms. |
| **Green Shield** | Full HCL conformance: Consent Before Execution. |
| **HCL** | Human Consent Layer. The trust infrastructure specified in this document. |
| **NHB** | Normal Human Being. The human principal in the HCL. The term emphasizes that the system is designed for people who are not developers or security specialists. |
| **TNO** | Trust Network Operator. The entity that operates the Verification Endpoint and maintains the Trust Network catalog. |
| **VE** | Verification Endpoint. The service that validates CARDs and enrollments in real time. |
| **Yellow Shield** | Partial HCL conformance: Consent Before Delivery. |

---

## 14. References

- [HCL Technical White Paper](https://opn.li) — Full technical description of the HCL architecture.
- [W3C Position Paper — The Agent Trust Layer](https://opn.li) — Proposed standard for the W3C WebMCP Community Group.
- [CARD Credential Schema](schema/card-credential.schema.json) — JSON Schema for CARD credentials.
- [CARD Set Schema](schema/card-set.schema.json) — JSON Schema for CARD Sets.
- [DevKit](packages/atl-devkit/) — Developer toolkit for HCL integration.

---

*Only a human can give consent. Consent requires context. CARDs provide context. The Human Consent Layer enforces the decision.*

*— HCL Specification v1.0-draft, September 2026*
