// @opnli/card-receiver — Service Rules Definition (Deno/TypeScript)
// The "CARD Issuer" side: services define what CARDs they require.
// ============================================================

// ─────────────────────────────────────────────────────────────
// Type definitions
// ─────────────────────────────────────────────────────────────

export interface ServiceRulesConfig {
  serviceName: string;
  serviceId: string;
  minimumShieldLevel: "green" | "yellow";
  allowedResources: string[];
  maxAccessLevel: "read" | "write" | "read-write";
  allowedActions: string[];
  rateLimit?: { requestsPerWindow: number; windowSeconds: number };
  retention: "session_only" | "persistent" | "cache_ttl";
  sessionTtlSeconds?: number;
  nhbSummary?: {
    entity: string;
    data: string;
    use: string;
    boundary: string;
  };
}

export interface ServiceRulesPolicy {
  minimumShieldLevel: "green" | "yellow";
  allowedResources: string[];
  maxAccessLevel: "read" | "write" | "read-write";
  allowedActions: string[];
  maxCallsPerDay?: number;
}

export interface CardStack {
  service_name: string;
  service_id: string;
  required_shield: "green" | "yellow";
  allowed_resources: string[];
  max_access_level: "read" | "write" | "read-write";
  allowed_actions: string[];
  rate_limit: { requestsPerWindow: number; windowSeconds: number } | null;
  retention: "session_only" | "persistent" | "cache_ttl";
  session_ttl_seconds: number;
  defined_at: string;
}

export interface NhbInvitation {
  entity: string;
  data: string;
  use: string;
  boundary: string;
}

export interface ServiceRulesResult {
  policy: ServiceRulesPolicy;
  cardStack: CardStack;
  nhbInvitation: NhbInvitation | null;
}

// ─────────────────────────────────────────────────────────────
// defineServiceRules
// ─────────────────────────────────────────────────────────────

/**
 * Define the service's CARD requirements — the "CARD Stack" that
 * agents must present to access this service.
 *
 * This is the CARD Issuer function. The service declares its rules once
 * during setup. The returned policy object is passed to validateCardSet()
 * on every incoming agent request.
 */
export function defineServiceRules(
  config: ServiceRulesConfig,
): ServiceRulesResult {
  const errors: string[] = [];

  // ── Required fields ───────────────────────────────────────────
  if (!config.serviceName) errors.push("serviceName is required");
  if (!config.serviceId) errors.push("serviceId is required");
  if (!config.minimumShieldLevel) {
    errors.push("minimumShieldLevel is required");
  }
  if (
    !config.allowedResources ||
    !Array.isArray(config.allowedResources) ||
    config.allowedResources.length === 0
  ) {
    errors.push("allowedResources must be a non-empty array");
  }
  if (!config.maxAccessLevel) errors.push("maxAccessLevel is required");
  if (
    !config.allowedActions ||
    !Array.isArray(config.allowedActions) ||
    config.allowedActions.length === 0
  ) {
    errors.push("allowedActions must be a non-empty array");
  }
  if (!config.retention) errors.push("retention is required");

  // ── Validate enum values ──────────────────────────────────────
  const validShields = ["green", "yellow"];
  if (
    config.minimumShieldLevel &&
    !validShields.includes(config.minimumShieldLevel)
  ) {
    errors.push('minimumShieldLevel must be "green" or "yellow"');
  }

  const validAccess = ["read", "write", "read-write"];
  if (config.maxAccessLevel && !validAccess.includes(config.maxAccessLevel)) {
    errors.push('maxAccessLevel must be "read", "write", or "read-write"');
  }

  const validRetention = ["session_only", "persistent", "cache_ttl"];
  if (config.retention && !validRetention.includes(config.retention)) {
    errors.push(
      'retention must be "session_only", "persistent", or "cache_ttl"',
    );
  }

  // ── Rate limit validation ─────────────────────────────────────
  if (config.rateLimit) {
    if (
      typeof config.rateLimit.requestsPerWindow !== "number" ||
      config.rateLimit.requestsPerWindow <= 0
    ) {
      errors.push("rateLimit.requestsPerWindow must be a positive number");
    }
    if (
      typeof config.rateLimit.windowSeconds !== "number" ||
      config.rateLimit.windowSeconds <= 0
    ) {
      errors.push("rateLimit.windowSeconds must be a positive number");
    }
  }

  if (errors.length > 0) {
    throw new Error("Invalid service rules: " + errors.join("; "));
  }

  // ── Build the platformPolicy object (consumed by validateCardSet) ──
  const policy: ServiceRulesPolicy = {
    minimumShieldLevel: config.minimumShieldLevel,
    allowedResources: config.allowedResources,
    maxAccessLevel: config.maxAccessLevel,
    allowedActions: config.allowedActions,
    maxCallsPerDay: config.rateLimit
      ? Math.floor(
        config.rateLimit.requestsPerWindow *
          (86400 / config.rateLimit.windowSeconds),
      )
      : undefined,
  };

  // ── Build the CARD Stack definition (what the service requires) ──
  const sessionTtl = config.sessionTtlSeconds || 3600;
  const cardStack: CardStack = {
    service_name: config.serviceName,
    service_id: config.serviceId,
    required_shield: config.minimumShieldLevel,
    allowed_resources: config.allowedResources,
    max_access_level: config.maxAccessLevel,
    allowed_actions: config.allowedActions,
    rate_limit: config.rateLimit || null,
    retention: config.retention,
    session_ttl_seconds: sessionTtl,
    defined_at: new Date().toISOString(),
  };

  // ── Build the NHB Issuance Invitation (INV-CA-3: uniform UX) ──
  const nhbInvitation: NhbInvitation | null = config.nhbSummary
    ? {
      entity: config.nhbSummary.entity,
      data: config.nhbSummary.data,
      use: config.nhbSummary.use,
      boundary: config.nhbSummary.boundary,
    }
    : null;

  return { policy, cardStack, nhbInvitation };
}
