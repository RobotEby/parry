# Parry_DDoS

![alt text](assets/image.png)

**Application-layer security middleware for Express.js.**  
Detects common SQL Injection, XSS, NoSQL Injection, Prototype Pollution, Path Traversal, risky request shapes, optional HTTP Parameter Pollution, and route-scoped authentication abuse before route handling.

```
63 real HTTP tests available  ·  1049/1049 local tests passed  ·  zero production dependencies
```

---

## Table of Contents

- [Why Parry_DDoS?](#why-parry_ddos)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Full Configuration](#full-configuration)
- [How It Works](#how-it-works)
  - [Detection Pipeline](#detection-pipeline)
  - [Intelligent Rate Limiting](#intelligent-rate-limiting)
  - [Inspected Surfaces](#inspected-surfaces)
  - [Application-Layer Guards](#application-layer-guards)
  - [Distributed Rate Limiting with Redis](#distributed-rate-limiting-with-redis)
  - [Brute Force Protection](#brute-force-protection)
  - [Threat Events](#threat-events)
  - [Observability](#observability)
  - [Admin API](#admin-api)
  - [DDoS Scope and Edge Protection](#ddos-scope-and-edge-protection)
  - [AWS Reference Infrastructure](#aws-reference-infrastructure)
- [Project Structure](#project-structure)
- [Tests](#tests)
  - [Payload Regression Testing](#payload-regression-testing)
- [Response Headers](#response-headers)
- [SIEM and Alert Integration](#siem-and-alert-integration)
- [TypeScript](#typescript)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why Parry_DDoS?

Most Node.js applications rely on validation at the route or ORM layer, which means malicious payloads can reach application logic before hitting any barrier. Parry_DDoS acts **before** your routes as an Express middleware.

- Common malicious payloads can be blocked before route logic and database access.
- No extra production dependencies — pure Node.js native.
- Every threat is logged with IP, method, route, and affected field.
- IPs that repeatedly send detected attacks can be temporarily banned by the store-backed limiter.

---

## Features

| Feature                  | Detail                                                                                                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **SQL Injection**        | 13 patterns — UNION, OR/AND bypass, comments, SLEEP/BENCHMARK, DROP/ALTER, xp_cmdshell, information_schema, hex encoding, LOAD FILE                                                  |
| **XSS**                  | 15 patterns — `<script>`, inline event handlers, `javascript:`, `vbscript:`, `data:` URI, SVG injection, template injection (Angular/Vue/Handlebars), null-byte, `autofocus+onfocus` |
| **NoSQL Injection**      | Dangerous MongoDB operators (`$where`, `$expr`, `$function`) and suspicious ones (`$gt`, `$ne`, `$or`, `$regex` etc.) in objects and JSON strings                                    |
| **Prototype Pollution**  | Dangerous keys such as `__proto__`, `constructor`, and `prototype` in query, params, and body                                                                                         |
| **Path Traversal**       | Raw, URL-encoded, and double-encoded traversal segments in request values                                                                                                             |
| **Request Shape Guard**  | Conservative limits for object depth, total keys, array length, and string length                                                                                                    |
| **Optional HPP Guard**   | Opt-in duplicate query parameter detection with per-field allowlist                                                                                                                   |
| **Rate Limiting**        | Store-backed rate limiting per observed IP with `X-RateLimit-*` headers                                                                                                             |
| **Route Policies**       | Per-route matchers for exact paths, wildcards, arrays, methods, and RegExp                                                                                                           |
| **Brute Force Guard**    | Optional login/auth abuse protection with `res.on('finish')`, manual failure/success hooks, and Store-backed counters                                                               |
| **Threat Events**        | Central structured events with id, severity, action, request id, detector/module, and sanitized metadata                                                                             |
| **Metrics**              | Lightweight in-process counters for requests, blocked requests, rate limits, brute force blocks, and events by type/severity/detector/action                                         |
| **Admin API**            | Optional read-only Express router for health, metrics, recent events, active MemoryStore bans, and configured policies                                                              |
| **Intelligent Ban**      | Suspicious activity counter separate from request volume, backed by MemoryStore by default or RedisStore in distributed deployments                                                  |
| **Multi-layer Decoding** | URL decode (up to 3 passes), HTML entities, Unicode zero-width strip, before any scan                                                                                                |
| **`onThreat` Callback**  | Hook for integration with SIEM, Slack, PagerDuty, DataDog, etc.                                                                                                                      |
| **TypeScript**           | Full typings included in `types/index.d.ts`                                                                                                                                          |

---

## Installation

```bash
npm install express   # only peer dependency
```

> **Parry_DDoS has zero production dependencies.**  
> `express` is a `peerDependency` — if it's already in your project, nothing else to install.
> For Redis-backed distributed rate limiting, install and configure a Redis client in your application, for example `npm install redis`.

---

## Quick Start

```js
const express = require('express');
const { Parry_DDoS } = require('./src/middleware');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Apply before any route
app.use(Parry_DDoS());

app.post('/login', (req, res) => {
  res.json({ ok: true });
});

app.listen(3000);
```

With default settings, the middleware is fully operational. Core detectors, conservative guards, and MemoryStore-backed rate limiting are enabled out of the box; HPP is opt-in.

---

## Full Configuration

```js
app.use(
  Parry_DDoS({
    // ── Detectors ───────────────────────────────────────────────
    sql: true, // Enable SQL Injection detection
    xss: true, // Enable XSS detection
    nosql: true, // Enable NoSQL Injection detection

    // ── Additional Application-Layer Guards ─────────────────────
    hpp: {
      enabled: false, // Opt-in: duplicated query params can be valid for some APIs
      allowDuplicateParamsFor: ['tags', 'filters'],
    },
    prototypePollution: {
      enabled: true,
    },
    pathTraversal: {
      enabled: true,
    },
    requestShape: {
      enabled: true,
      maxDepth: 8,
      maxKeys: 500,
      maxArrayLength: 100,
      maxStringLength: 10_000,
    },

    // ── Rate Limiting ───────────────────────────────────────────
    rateLimit: {
      enabled: true,
      max: 100, // Max requests per window per IP
      windowMs: 60_000, // Window duration in ms (default: 1 min)
      headers: true, // Emit X-RateLimit-* headers when a store result exists
    },
    // Legacy top-level maxRequests/windowMs options are still supported.

    // ── Store ───────────────────────────────────────────────────
    // Defaults to MemoryStore. Pass RedisStore for distributed deployments.
    store: undefined,
    storeFailureMode: 'fail-open', // or 'fail-closed'

    // ── Route Policies and Brute Force ──────────────────────────
    preset: 'off', // 'off' | 'recommended' | 'strict'
    bruteForce: { enabled: false },
    policies: [
      {
        name: 'auth-login',
        match: { method: 'POST', path: '/login' },
        inheritGlobalRateLimit: true,
        rateLimit: {
          enabled: true,
          max: 20,
          windowMs: 60_000,
          key: 'ip',
        },
        bruteForce: {
          enabled: true,
          maxAttempts: 5,
          windowMs: 15 * 60_000,
          blockDurationMs: 10 * 60_000,
          keys: ['ip', 'body.email', 'ip+body.email'],
          failureStatusCodes: [400, 401, 403],
          successStatusCodes: [200, 201, 204],
          resetOnSuccess: true,
        },
      },
    ],

    // ── Intelligent Ban ─────────────────────────────────────────
    suspiciousThreshold: 5, // Detected attacks before ban
    banDurationMs: 300_000, // Ban duration in ms (default: 5 min)

    // ── Logging ─────────────────────────────────────────────────
    logThreats: true, // Display colored logs in the console
    debug: false,

    // ── Events and Observability ────────────────────────────────
    events: {
      maxEvents: 500, // In-memory recent event buffer
    },
    requestId: {
      enabled: true,
      header: 'x-request-id',
      responseHeader: false, // or 'X-Parry-Request-Id'
    },
    admin: {
      enabled: false, // Admin router is never mounted automatically
      allowMutations: false,
    },

    // ── Integration Hook ────────────────────────────────────────
    onThreat(event, req, res) {
      // event.type      → 'SQL_INJECTION_BLOCKED', 'RATE_LIMIT_EXCEEDED', ...
      // event.ip        → client IP
      // event.threats[] → preserved for detector compatibility
      // event.requestId → x-request-id or generated req_...
    },
    onEvent(event) {
      // Receives every normalized Parry event.
    },
    onStoreError(error, event) {
      // Optional hook for Redis/custom store outages.
    },
  })
);
```

### Default Values

| Option                | Default          |
| --------------------- | ---------------- |
| `sql`                 | `true`           |
| `xss`                 | `true`           |
| `nosql`               | `true`           |
| `hpp.enabled`         | `false`          |
| `hpp.allowDuplicateParamsFor` | `[]`     |
| `prototypePollution.enabled` | `true`    |
| `pathTraversal.enabled` | `true`         |
| `requestShape.enabled` | `true`         |
| `requestShape.maxDepth` | `8`           |
| `requestShape.maxKeys` | `500`          |
| `requestShape.maxArrayLength` | `100`    |
| `requestShape.maxStringLength` | `10000` |
| `rateLimit` / `rateLimit.enabled` | `true` |
| `rateLimit.max` / `maxRequests` | `100`  |
| `rateLimit.windowMs` / `windowMs` | `60000` (1 min) |
| `rateLimit.headers`   | `true`           |
| `store`               | `MemoryStore`    |
| `storeFailureMode`    | `'fail-open'`    |
| `preset`              | `'off'`          |
| `bruteForce.enabled`  | `false`          |
| `policies`            | `[]`             |
| `events.maxEvents`    | `500`            |
| `admin.enabled`       | `false`          |
| `admin.allowMutations` | `false`         |
| `requestId.enabled`   | `true`           |
| `requestId.header`    | `'x-request-id'` |
| `requestId.responseHeader` | `false`     |
| `debug`               | `false`          |
| `suspiciousThreshold` | `5`              |
| `banDurationMs`       | `300000` (5 min) |
| `logThreats`          | `true`           |
| `maxObjectDepth`      | `5`              |

---

## How It Works

### Detection Pipeline

Every request goes through the following pipeline before reaching any route:

```
Request
    │
    ├─► [1] Route policy lookup
    │       ├── optional brute force block check
    │       └── optional route-specific rate limit
    │
    ├─► [2] Global Rate Limit check  ──────── 429 if exceeded or banned
    │
    ├─► [3] Target collection and request metadata
    │       ├── query params
    │       ├── body (recursive flatten up to maxObjectDepth)
    │       ├── route params
    │       └── sensitive headers (user-agent, referer, cookie, x-forwarded-for)
    │
    ├─► [4] Application-layer guards
    │       ├── Request shape limits
    │       ├── HTTP Parameter Pollution (when enabled)
    │       ├── Prototype Pollution keys
    │       └── Path Traversal values
    │
    ├─► [5] Multi-layer decoding per value
    │       ├── URL decode (up to 3 passes — anti double-encoding)
    │       ├── HTML entities (&lt; &amp; &#x27; etc.)
    │       └── Unicode zero-width strip
    │
    ├─► [6] Parallel scan per detector
    │       ├── SQLInjectionDetector.scan(value)
    │       ├── XSSDetector.scan(value)
    │       └── NoSQLDetector.scan(rawValue)  ← receives object or string
    │
    ├─► [7] Threat detected?
    │       ├── YES → recordSuspicious(ip) · EventBus · onThreat() · 400
    │       └── NO  → next()
    │
    └─► Application route
            └── auth policy observes final status with res.on('finish')
```

### Intelligent Rate Limiting

Parry_DDoS maintains **two independent counters** per observed IP through a Store:

```
IP: 203.0.113.42
├── rate limit     → request count for the active window
│                    (blocked when > maxRequests / rateLimit.max)
└── suspicious     → incremented on every detected attack
                     (banned when >= suspiciousThreshold)
```

This means an IP can exceed the request limit without being marked malicious, while an IP making only a few malicious requests is temporarily banned after reaching the suspicious threshold.

By default, Parry_DDoS uses `MemoryStore`, which is appropriate for development and single-process deployments. In multi-process, containerized, serverless, or load-balanced deployments, each process has its own MemoryStore state unless you configure a shared store.

If the store fails, Parry_DDoS defaults to `storeFailureMode: 'fail-open'`: rate limiting is skipped for that request, but SQL/XSS/NoSQL and application-layer detectors still run. Use `storeFailureMode: 'fail-closed'` in high-security environments when a rate-limit store outage should block requests with `503`.

### Inspected Surfaces

```
POST /api/users?search=<payload>
│
├── query.search           ← query string
├── body                   ← root object (NoSQL top-level operators)
├── body.username          ← direct fields
├── body.address.street    ← nested fields (up to maxObjectDepth)
├── params.id              ← route params
├── header.user-agent      ← sensitive headers
├── header.referer
├── header.cookie
└── header.x-forwarded-for
```

### Application-Layer Guards

The additional guards are intentionally conservative:

- **HPP** is disabled by default. Enable it when your API does not intentionally accept duplicated query parameters, or allow specific fields with `allowDuplicateParamsFor`.
- **Prototype Pollution** blocks dangerous keys in `query`, `params`, and `body`, including nested objects.
- **Path Traversal** checks request values after safe URL decoding, including double-encoded traversal segments.
- **Request Shape Guard** blocks unusually deep, large, or long request structures before they reach route handlers.

### Distributed Rate Limiting with Redis

Use `RedisStore` when your application runs behind multiple instances, containers, PM2 cluster workers, ECS/Kubernetes replicas, or load-balanced services. MemoryStore only protects each process individually.

Parry_DDoS does not install Redis for you. Create and connect the Redis client in your application, then pass it to the middleware:

```js
const express = require('express');
const { createClient } = require('redis');
const { Parry_DDoS, RedisStore } = require('parry');

async function main() {
  const redis = createClient({ url: process.env.REDIS_URL });
  await redis.connect();

  const app = express();
  app.use(express.json());

  app.use(
    Parry_DDoS({
      store: new RedisStore({
        client: redis,
        prefix: 'parry',
      }),
      storeFailureMode: 'fail-open',
      rateLimit: {
        enabled: true,
        windowMs: 60_000,
        max: 100,
        headers: true,
      },
    })
  );

  app.listen(3000);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
```

`RedisStore` expects a node-redis v4 compatible client with `get`, `set`, `del`, `incr`, `pExpire`/`pTTL`, and `eval` or `multi/exec` support. It uses namespaced keys such as `parry:rl:{key}`, `parry:ban:{key}`, and `parry:suspicious:{key}`.

RedisStore helps coordinate HTTP flood and application-layer abuse controls across instances. It is not a replacement for edge protection against volumetric DDoS.

### Brute Force Protection

Brute force protection is route-scoped and disabled by default. Enable it with explicit policies or `preset: 'recommended'`/`'strict'`.

```js
const { Parry_DDoS, RedisStore } = require('parry');

app.use(
  Parry_DDoS({
    store: new RedisStore({ client: redis }),
    policies: [
      {
        name: 'auth-login',
        match: { method: 'POST', path: '/login' },
        bruteForce: {
          enabled: true,
          maxAttempts: 5,
          windowMs: 15 * 60_000,
          blockDurationMs: 10 * 60_000,
          keys: ['ip', 'body.email', 'ip+body.email'],
          failureStatusCodes: [400, 401, 403],
          resetOnSuccess: true,
        },
        rateLimit: {
          enabled: true,
          max: 20,
          windowMs: 60_000,
          key: 'ip',
        },
      },
    ],
  })
);
```

Policies support exact methods/paths, arrays, simple wildcards such as `/auth/*`, and `RegExp` paths. Policy rate limits are additional only when configured; the global rate limit still applies unless `inheritGlobalRateLimit: false` is set.

The BruteForceGuard checks Store-backed block keys before the route handler and observes the final response with `res.on('finish')`. It records failures from status codes such as `400`, `401`, and `403`, and resets counters on success when `resetOnSuccess` is enabled.

For APIs that return `200` with `{ success: false }`, use the manual hooks:

```js
app.post('/login', async (req, res) => {
  const user = await authService.validate(req.body.email, req.body.password);

  if (!user) {
    req.parry.recordAuthFailure('invalid_credentials');
    return res.status(200).json({ success: false });
  }

  req.parry.recordAuthSuccess();
  return res.json({ success: true });
});
```

When blocked, the response is generic and includes `Retry-After`:

```json
{
  "error": "Too many authentication attempts",
  "code": "BRUTE_FORCE_BLOCKED",
  "retryAfter": 600
}
```

Keys never include `body.password` by default. Avoid putting tokens, passwords, cookies, or authorization headers into custom keys. RedisStore can share brute force counters across instances, but applications should still use password hashing, MFA where appropriate, generic login errors, monitoring, and edge/WAF controls.

### Threat Events

Parry normalizes security activity into structured threat events. Events are sanitized before they reach the event store, callbacks, metrics, or Admin API.

```json
{
  "id": "evt_lx000001_1",
  "type": "SQL_INJECTION_BLOCKED",
  "module": "detector",
  "detector": "SQL_INJECTION",
  "detectorSlug": "sql",
  "severity": "high",
  "action": "blocked",
  "reason": "SQL injection pattern detected",
  "ip": "127.0.0.1",
  "method": "POST",
  "path": "/login",
  "statusCode": 400,
  "requestId": "req_abc123",
  "userAgent": "Mozilla/5.0",
  "timestamp": "2026-01-01T00:00:00.000Z",
  "metadata": {}
}
```

Canonical event types include `SQL_INJECTION_BLOCKED`, `XSS_BLOCKED`, `NOSQL_INJECTION_BLOCKED`, `HPP_BLOCKED`, `PROTOTYPE_POLLUTION_BLOCKED`, `PATH_TRAVERSAL_BLOCKED`, `REQUEST_SHAPE_BLOCKED`, `RATE_LIMIT_EXCEEDED`, `ROUTE_RATE_LIMIT_EXCEEDED`, `TEMPORARY_BAN_HIT`, `BRUTE_FORCE_ATTEMPT`, `BRUTE_FORCE_BLOCKED`, `BRUTE_FORCE_RESET`, `STORE_ERROR`, and `HOOK_ERROR`.

Sensitive values are not stored in events: passwords, tokens, cookies, authorization headers, credentials, secrets, and raw request bodies are redacted or omitted. `onThreat(event, req, res)` remains supported and now receives the normalized event while preserving `event.threats[]` for detector blocks.

### Observability

Use `createParry()` when you need access to metrics, the event bus, or the recent event store:

```js
const { createParry } = require('parry');

const parry = createParry({
  logThreats: false,
  events: { maxEvents: 500 },
  requestId: {
    enabled: true,
    header: 'x-request-id',
    responseHeader: 'X-Parry-Request-Id',
  },
  onThreat(event) {
    console.log(event.type, event.severity, event.requestId);
  },
  onEvent(event) {
    // Forward to your logger, SIEM, CloudWatch, or queue.
  },
});

app.use(parry.middleware());

const snapshot = parry.metrics.snapshot();
const recent = parry.eventBus.getRecentEvents({ limit: 50, severity: 'high' });
```

Metrics are intentionally lightweight and in-process: `totalRequests`, `allowedRequests`, `blockedRequests`, `rateLimitedRequests`, `bruteForceBlocks`, `activeBans`, `eventsByType`, `eventsBySeverity`, `eventsByDetector`, `eventsByAction`, `startedAt`, and `uptimeMs`. They are useful for local inspection and dashboard foundations, not a replacement for Prometheus, OpenTelemetry, CloudWatch, SIEM, WAF logs, or provider-level observability.

Request ids are enabled by default. Parry reads `x-request-id` when present, otherwise it generates a `req_...` id and attaches it to `req.parry.requestId`. A response header is only emitted when `requestId.responseHeader` is configured.

### Admin API

The Admin API is an optional read-only Express router. It is **never mounted automatically** and it does not enable CORS. Mount it only behind authentication, network restrictions, VPN, IP allowlists, or equivalent controls.

```js
const express = require('express');
const { createParry, createParryAdminRouter } = require('parry');

const app = express();
const parry = createParry({
  admin: { enabled: true },
});

function requireAdminAuth(req, res, next) {
  if (req.headers['x-admin-token'] !== process.env.PARRY_ADMIN_TOKEN) {
    return res.status(401).json({ error: true, message: 'Unauthorized' });
  }
  return next();
}

app.use(parry.middleware());
app.use('/_parry', requireAdminAuth, createParryAdminRouter(parry));
```

You can also pass an auth callback directly to the router:

```js
app.use(
  '/_parry',
  createParryAdminRouter(parry, {
    auth: (req) => req.headers['x-admin-token'] === process.env.PARRY_ADMIN_TOKEN,
  })
);
```

Available endpoints:

| Endpoint | Description |
| -------- | ----------- |
| `GET /health` | Basic status, package version, uptime, and store type |
| `GET /metrics` | Metrics snapshot |
| `GET /events` | Recent events with filters and `limit`/`offset` pagination |
| `GET /events/:id` | Single event lookup |
| `GET /bans` | Active MemoryStore bans when available; empty list for stores without snapshots |
| `GET /policies` | Normalized route policies without sensitive request data |

Never expose the Parry Admin API publicly without authentication and network restrictions. It is a foundation for internal operations and a future dashboard, not a public management interface.

### DDoS Scope and Edge Protection

Parry_DDoS runs inside Express after traffic has already reached your Node.js process. It can reject malicious or excessive application-layer requests seen by that process, but it does not absorb volumetric floods, network-layer attacks, or connection exhaustion that must be stopped before the application receives traffic.

For volumetric DDoS protection, use edge and infrastructure controls such as CloudFront, AWS WAF, AWS Shield, ALB rate-based rules, or an equivalent CDN, WAF, load balancer, or provider-level protection. Treat Parry_DDoS as one application-layer control behind those services.

### AWS Reference Infrastructure

This repository includes a Terraform reference under `infra/terraform` for a realistic AWS deployment shape: CloudFront, AWS WAF, public ALB, private ECS Fargate tasks, private ElastiCache Redis, and CloudWatch logs.

The stack is intentionally demonstrative. It does not create secrets, Route 53 records, ACM certificates, or production multi-account foundations. Start with:

- `infra/terraform/README.md`
- `docs/aws-infra.md`
- `docs/aws-security-notes.md`
- `docs/aws-cost-notes.md`

The AWS reference shows how Parry fits behind edge protection. It does not change Parry into a volumetric DDoS protection product.

---

## Project Structure

```
Parry_DDoS/
│
├── src/
│   ├── middleware/           ← Backwards-compatible public entrypoint
│   ├── express/              ← Express adapter: req/res/next, IP, targets, responses
│   ├── core/                 ← Analysis engine, events, scoring, compatibility shims
│   │
│   ├── detectors/
│   │   ├── sql.js            ← SQL Injection detector
│   │   ├── xss.js            ← XSS detector
│   │   ├── nosql.js          ← NoSQL Injection detector
│   │   ├── hpp.js            ← HTTP Parameter Pollution detector
│   │   ├── prototype-pollution.js
│   │   ├── path-traversal.js
│   │   ├── request-shape.js
│   │   └── index.js          ← Barrel export
│   │
│   ├── rate-limit/           ← Store-backed limiter and key helpers
│   ├── policies/             ← Route policy matcher, presets, normalization
│   ├── brute-force/          ← BruteForceGuard, auth key builder, block responses
│   ├── stores/               ← Store contract, MemoryStore, RedisStore
│   ├── events/               ← ThreatEvent model, EventBus, recent event store
│   ├── observability/        ← Metrics and Admin API snapshot helpers
│   ├── admin/                ← Optional read-only Admin API router
│   ├── logger/               ← Console reporter
│   └── utils/                ← Decode, normalize, flatten helpers
│
├── config/
│   └── defaults.js           ← Centralized default values
│
├── constants/
│   └── patterns.js           ← All regex patterns in one place
│
├── types/
│   └── index.d.ts            ← Public TypeScript typings
│
├── tests/
│   ├── unit/
│   │   ├── detectors.test.js        ← SQL/XSS/NoSQL tests
│   │   ├── applicationGuards.test.js
│   │   ├── engine.test.js
│   │   ├── observability.test.js
│   │   └── rateLimiter.test.js      ← RateLimiter tests
│   ├── integration/
│   │   ├── middleware.test.js       ← Middleware end-to-end with req/res mock
│   │   └── observability.test.js    ← Events, metrics, Admin API
│   ├── fixtures/
│   │   ├── payloads.js              ← Reusable attack payloads
│   │   ├── application-layer.js     ← Curated guard fixtures
│   │   └── payloads/                ← JSON payload regression fixtures
│   ├── regression/                  ← Defensive payload regression suite
│   └── index.js                 ← Aggregated test runner
│
├── scripts/
│   ├── payloads/             ← Fixture validation and report generation
│   ├── test-server.js        ← Express server for real HTTP tests
│   └── run-tests.js          ← 63 HTTP test suite against the server
│
├── examples/
│   └── express-basic.js      ← Full integration example
│
├── infra/
│   └── terraform/            ← AWS reference infrastructure modules and dev env
│
├── docs/
│   ├── architecture.md       ← Documented design decisions
│   ├── aws-infra.md
│   ├── aws-security-notes.md
│   ├── aws-cost-notes.md
│   ├── testing-payloads.md
│   └── payload-regression-report.md
│
└── package.json
```

---

## Tests

Parry_DDoS has two independent test suites: **1049 local tests** in `npm test` plus **63 real HTTP tests** for the Express test server.

### Local suite (1049 tests) — no network, no server

```bash
npm test
```

Covers isolated detectors, application-layer guards, the `RateLimiter`, MemoryStore, RedisStore with a fake client, policy matching, brute force behavior, the core engine, observability modules, Admin API helpers, defensive payload fixtures, and the middleware with `req`/`res` mocks. Runs in any environment, including CI.

```
▶ Unit — Detectors                         30 tests
▶ Unit — RateLimiter                       14 tests
▶ Unit — Stores                            28 tests
▶ Unit — Policies                           8 tests
▶ Unit — Brute Force                       20 tests
▶ Unit — Core Engine                        6 tests
▶ Unit — App Guards                        19 tests
▶ Unit — Observability                     33 tests
▶ Integration — Middleware                 56 tests
▶ Integration — Observability/Admin API    33 tests
▶ Regression — Payload Suite              802 tests
────────────────────────────────────────────────────
Total                                    1049 tests  |  0 failures
```

### Payload Regression Testing

Parry includes a curated defensive payload regression suite under `tests/fixtures/payloads`. The fixtures are small local JSON files inspired by known web security categories, including SQLi, XSS, NoSQLi, HPP, Prototype Pollution, Path Traversal, Request Shape, BruteForceGuard scenarios, monitor-only Command Injection and SSRF categories, and benign false-positive controls.

PayloadsAllTheThings may be used as a read-only local reference when `external/PayloadsAllTheThings` exists, but the external repository is not required, not imported, not copied into runtime code, and not vendored into the package.

```bash
npm run test:fixtures
npm run test:payload-regression
npm run test:payload-report
```

The payload suite never executes payloads, never passes them to a shell, never uses them in real database queries, and never performs SSRF/network requests. Command Injection and SSRF fixtures are monitor/pending coverage until dedicated detectors exist.

### Real HTTP suite (63 tests) — fires real requests against Express

```bash
# Terminal 1 — start the test server
npm run start:test

# Terminal 2 — run the HTTP tests
npm run test:http
```

Covers clean requests, all attack vectors in body/query/params/headers, `X-RateLimit-*` headers, window exhaustion, intelligent ban, and simultaneous multiple threats.

```
  Sanity checks                  2 tests
  Clean requests                 6 tests
  SQL Injection                 16 tests
  XSS                           12 tests
  NoSQL Injection               12 tests
  X-RateLimit Headers            5 tests
  Volume Rate Limiting           3 tests
  Intelligent Ban                3 tests
  Multiple Threats               4 tests
─────────────────────────────────────────
Total                           63 tests  |  0 failures
```

---

## Response Headers

When rate limiting is enabled and the Store check succeeds, Parry_DDoS injects the following headers into responses:

| Header                  | Description                              |
| ----------------------- | ---------------------------------------- |
| `X-RateLimit-Limit`     | Configured maximum requests              |
| `X-RateLimit-Remaining` | Requests remaining in the current window |
| `X-RateLimit-Reset`     | Window reset timestamp (ms)              |

When a request is blocked, the response follows this format:

```json
// 400 — threat detected
{
  "error": true,
  "message": "Request blocked: malicious pattern detected.",
  "threats": [
    { "detector": "SQL_INJECTION", "field": "body.username" },
    { "detector": "XSS",           "field": "body.comment"  },
    { "detector": "REQUEST_SHAPE", "field": "body", "reason": "Object key count exceeds 500" }
  ]
}

// 429 — rate limit or ban
{
  "error": true,
  "message": "Too many suspicious requests. IP temporarily banned.",
  "banExpiresAt": 1712700000000
}

// 429 — brute force block
{
  "error": "Too many authentication attempts",
  "code": "BRUTE_FORCE_BLOCKED",
  "retryAfter": 600
}
```

---

## SIEM and Alert Integration

Use the `onThreat` callback to forward events to any external system:

```js
// Slack
Parry_DDoS({
  onThreat(event) {
    // Threat events include top-level type, detector, severity, reason, and requestId
    // while preserving event.threats[] for detector blocks.
    fetch('https://hooks.slack.com/services/...', {
      method: 'POST',
      body: JSON.stringify({
        text: `Parry event: ${event.type}\nIP: ${event.ip}\nRoute: ${event.method} ${event.url || event.path}`,
      }),
    });
  },
});

// DataDog
Parry_DDoS({
  onThreat(event) {
    dogstatsd.increment('parry.threat', 1, [`type:${event.type}`, `severity:${event.severity}`]);
  },
});

// Structured log file (NDJSON)
const fs = require('fs');
Parry_DDoS({
  logThreats: false, // disable console output, use callback only
  onThreat(event) {
    fs.appendFileSync('threats.ndjson', JSON.stringify(event) + '\n');
  },
});
```

---

## TypeScript

Parry_DDoS includes full typings with no `@types/*` required:

```ts
import { Parry_DDoS, Parry_DDoSOptions, ThreatEvent } from 'parry';

const options: Parry_DDoSOptions = {
  suspiciousThreshold: 3,
  onThreat: (event: ThreatEvent) => {
    console.log(event.type, event.severity, event.threats);
  },
};

app.use(Parry_DDoS(options));
```

Exported types include `Parry_DDoSOptions`, `ThreatEvent`, `ThreatLogEntry`, `ThreatMatch`, `ThreatEventType`, `MetricsSnapshot`, `ParryInstance`, `AdminRouterOptions`, `RateLimitResult`, `IPSnapshot`, `DetectorType`, `LogEntryType`, `RateLimiter`, `EventBus`, `MemoryEventStore`, `Metrics`, `SQLInjectionDetector`, `XSSDetector`, `NoSQLDetector`, `HPPDetector`, `PrototypePollutionDetector`, `PathTraversalDetector`, and `RequestShapeGuard`.
Store and policy exports are also typed: `RateLimitStore`, `StoreBlockResult`, `MemoryStore`, `RedisStore`, `PolicyConfig`, and `ParryRequestContext`.

---

## Roadmap

Parry_DDoS is under active development. Upcoming versions focus on stronger application-layer controls, production hardening, and clearer integration with edge protection layers:

### `v1.1` — Production Hardening

- [ ] CIDR verification for trusted proxies before accepting `X-Forwarded-For`
- [ ] Protection against Header Injection and HTTP Response Splitting
- [ ] IP and route allowlist support for excluding specific paths from inspection

### `v1.2` — Distributed Persistence Hardening

- [ ] Additional shared store adapters (Memcached, DynamoDB, etc.)
- [ ] Optional key hashing for stores that should not persist raw client identifiers
- [ ] Real-time ban synchronization patterns via Pub/Sub where appropriate

### `v1.3` — Application-Layer Abuse Controls

- [ ] Token Bucket with per-route burst control
- [ ] Request fingerprinting for repeated application-layer attack patterns
- [ ] Hooks for challenge-response providers when clients enter a grey zone
- [ ] Guidance for handling slow requests at the proxy/load-balancer layer

### `v1.4` — Operations and Observability

- [ ] Docker and Kubernetes deployment examples for applications using the middleware
- [x] Terraform reference architecture behind CloudFront, AWS WAF, ALB, ECS Fargate, and ElastiCache Redis
- [ ] Production CI/CD, multi-account, and advanced deployment examples
- [ ] Web monitoring dashboard with real-time threat map, ban history, and per-detector metrics
- [ ] Metrics export in Prometheus/OpenTelemetry format

### `v2.0` — Adaptive Intelligence

- [ ] Session-level behavioral analysis — detects attack patterns distributed over time (slow attacks)
- [ ] IP reputation model with automatic decay
- [ ] Integration with external threat intelligence feeds (AbuseIPDB, Spamhaus)
- [ ] Learning mode: collects legitimate traffic to automatically calibrate thresholds

---

## Contributing

Contributions are welcome. To get started:

```bash
git clone <repo>
cd Parry_DDoS
npm install

# Run the tests before any changes
npm test

# For new detectors: add patterns to constants/patterns.js
# For new tests: add fixtures to tests/fixtures/payloads.js
```

When opening a PR, please include:

- Unit tests for the altered detector or module
- Updates to `types/index.d.ts` if the public API changes
- A `CHANGELOG.md` entry (if present)

---

## License

MIT — see `LICENSE` for details.

---

<div align="center">
  <sub>Built with native Node.js · Zero production dependencies · Tested with 1049 application-layer cases</sub>
</div>
