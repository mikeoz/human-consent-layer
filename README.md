# Agent Trust Layer (ATL)

**The consent layer for the Agent Economy.**

MCP standardized the connection. The ATL standardizes the consent.

AI agents can read your files, search the web, execute code, and call
APIs — often without asking. The Agent Trust Layer is the open
infrastructure that puts humans back in control: every agent action
requires human consent before it happens.

## What's In This Repo

### DevKit — packages/atl-devkit/

The ATL DevKit — an npm module that adds human consent to any AI
agent in 3 lines of code. Install it, wrap your agent's message
stream, and every action is consent-gated.

    npm install @opnli/atl-devkit

Three function calls. Zero external dependencies. Works with any
agent platform that streams sequential events.

See the DevKit README (packages/atl-devkit/README.md) for the
full API and quick start guide.

### CARD Schema — schema/

The CARD (Credential for Agent Runtime Decisions) schema. A CARD is
the trust credential that agents carry in the ATL. It declares the
agent's identity, consent model, tool surface, and audit capability.

The schema includes a delegation_vrcs hook for integration with
Decentralized Trust Governance (DTG) infrastructure — linking
per-action human consent to verifiable relationship credentials.

## The Three Realities of Trust

Every trust decision involves three questions:

1. **Know** — Who is acting? CARD credentials (identity)
2. **Choose** — What is allowed? Consent gate (this DevKit)
3. **Check** — What happened? Audit log (tamper-evident)

## Two Shield Levels

| Shield | Model | When Human Decides | Platform Requirement |
|--------|-------|--------------------|---------------------|
| **Green Shield** | Consent Before Execution | Before the action occurs | Platform must support pre-execution approval events |
| **Yellow Shield** | Consent Before Delivery | After execution, before result delivery | Any platform with sequential event streams |

Green is strictly stronger than Yellow. The ATL defaults to the
strongest level the platform supports.

## Design Principles

- **Non-invasive.** Wraps agent platforms. Does not modify them.
- **Fail-closed.** No response = denied. Connection drop = denied.
- **Platform-agnostic.** Works with any sequential event stream.
- **Honest.** Yellow Shield is not Green Shield. We say so.
- **Auditable.** SHA-256 hash chain on every decision.
- **Open.** Apache 2.0. Build on it.

## Reference Implementation

CROCbox (https://github.com/mikeoz/crocbox) is the reference
implementation of the ATL — a desktop application that wraps
OpenClaw in a complete trust layer. CROCbox is the first
CARD-Carrying Agent with verified Consent Before Execution.

## The Agent Economy

*My data + Your AI + My control = Living Intelligence*

OpenClaw gave developers 5 lines to give agents power.
The ATL gives developers 3 lines to make that power trustworthy.

TCP/IP needed SSL. MCP needs ATL.

## License

Apache-2.0 — Openly Personal Networks, Inc. (https://opn.li)

## Links

- Opn.li: https://opn.li
- CROCbox: https://github.com/mikeoz/crocbox
- DevKit docs: packages/atl-devkit/README.md
- CARD Schema: schema/card-credential.schema.json
