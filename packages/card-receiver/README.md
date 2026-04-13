# @opnli/card-receiver

**CARD Receiver SDK** — Validate incoming CARD Sets from CARD-Carrying Agents.

For platforms adopting the Human Consent Layer. If an agent wants to access your platform, this SDK validates its credentials.

## Install

```bash
npm install @opnli/card-receiver
```

## Quick Start

```javascript
const { validateCardSet, createSessionToken } = require('@opnli/card-receiver');

// Define your platform's policy
const policy = {
  minimumShieldLevel: 'green',
  allowedResources: ['subreddit:posts', 'subreddit:comments', 'user:subscriptions'],
  maxAccessLevel: 'read',
  allowedActions: ['summarize', 'search', 'curate', 'alert'],
  maxCallsPerDay: 1000
};

// Validate an incoming CARD Set
const result = await validateCardSet(cardSet, policy, {
  veEndpoint: 'https://ve-staging.opn.li/verify'
});

if (result.valid) {
  // Issue a scoped session token
  const session = createSessionToken(result.session_scope, 3600);
  console.log('Access granted:', session.token);
} else {
  console.log('Access denied:', result.errors);
}
```

## API

### `validateCardSet(cardSet, platformPolicy, options)`
Validates all four CARDs against platform policy and optionally verifies the Entity CARD against the VE.

### `createSessionToken(sessionScope, ttlSeconds)`
Creates a session token scoped to the validated CARD Set's permissions.

### `auditAccess(token, action)`
Logs an API access event against the session.

## License

Apache-2.0

*My Data + Your AI + My Control = Living Intelligence*
