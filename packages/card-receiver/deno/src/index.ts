// @opnli/card-receiver — CARD Receiver SDK (Deno/TypeScript)
// For Deno HTTP handlers and Supabase Edge Functions.
// ============================================================
// v0.2.0-deno — Session C port
//
// CARD Issuer (define your rules):
//   defineServiceRules(config) → { policy, cardStack, nhbInvitation }
//
// CARD Receiver (validate incoming agents):
//   validateCardSet(cardSet, policy, options) → { valid, errors, session_scope }
//   createSessionToken(scope, ttl, options) → { token, expires_at, ... }
//   auditAccess(token, action, options) → audit entry with hash chain
//
// Request handler helper (replaces Express middleware):
//   cardReceiverHandle(request, config) → { ok, session, token } | { ok: false, response }
//
// Utilities:
//   verifyEntityWithVE(entityCard, cardId, veEndpoint, timeout, opType)
//     → { verified, reason, ve_response? }
//   createAuditChain(initialHash) → chain tracker
//   sha256(data) → Promise<hex hash>
// ============================================================

export {
  auditAccess,
  createAuditChain,
  createSessionToken,
  sha256,
  validateCardSet,
  verifyEntityWithVE,
} from "./card-set-validator.ts";

export type {
  AuditAccessOptions,
  AuditAction,
  AuditChain,
  AuditEntry,
  BoundaryCard,
  CardSet,
  CreateSessionTokenOptions,
  DataCard,
  EntityCard,
  PlatformPolicy,
  SessionRecord,
  SessionScope,
  UseCard,
  ValidateCardSetOptions,
  ValidateResult,
  VeVerifyResult,
} from "./card-set-validator.ts";

export { defineServiceRules } from "./service-rules.ts";

export type {
  CardStack,
  NhbInvitation,
  ServiceRulesConfig,
  ServiceRulesPolicy,
  ServiceRulesResult,
} from "./service-rules.ts";

export { cardReceiverHandle, inferOperation } from "./middleware.ts";

export type {
  CardReceiverFailure,
  CardReceiverHelperConfig,
  CardReceiverResult,
  CardReceiverSuccess,
  SessionLookupRecord,
} from "./middleware.ts";
