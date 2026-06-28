# Parry_DDoS

![alt text](assets/image.png)

**Application-layer security middleware for Express.js.**  
Detects common SQL Injection, XSS, NoSQL Injection, Prototype Pollution, Path Traversal, risky request shapes, and optional HTTP Parameter Pollution before route handling.

```
63 real HTTP tests available  ·  108/108 local tests passed  ·  zero production dependencies
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
  - [DDoS Scope and Edge Protection](#ddos-scope-and-edge-protection)
- [Project Structure](#project-structure)
- [Tests](#tests)
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
- IPs that repeatedly send detected attacks can be temporarily banned by the in-memory limiter.

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
| **Rate Limiting**        | In-memory sliding window per observed IP with `X-RateLimit-*` headers                                                                                                                |
| **Intelligent Ban**      | Suspicious activity counter separate from request volume, scoped to the current Node.js process                                                                                      |
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

With default settings, the middleware is fully operational. Core detectors, conservative guards, and in-memory rate limiting are enabled out of the box; HPP is opt-in.

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
    rateLimit: true,
    maxRequests: 100, // Max requests per window per IP
    windowMs: 60_000, // Window duration in ms (default: 1 min)

    // ── Intelligent Ban ─────────────────────────────────────────
    suspiciousThreshold: 5, // Detected attacks before ban
    banDurationMs: 300_000, // Ban duration in ms (default: 5 min)

    // ── Logging ─────────────────────────────────────────────────
    logThreats: true, // Display colored logs in the console

    // ── Integration Hook ────────────────────────────────────────
    onThreat(entry, req, res) {
      // entry.type      → 'THREAT' | 'BAN' | 'RATE_LIMIT'
      // entry.ip        → client IP
      // entry.threats[] → [{ detector, field, pattern }]
      // entry.method    → 'POST', 'GET', etc.
      // entry.url       → affected route
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
| `rateLimit`           | `true`           |
| `maxRequests`         | `100`            |
| `windowMs`            | `60000` (1 min)  |
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
    ├─► [1] Rate Limit check  ──────── 429 if exceeded or banned
    │
    ├─► [2] Target collection and request metadata
    │       ├── query params
    │       ├── body (recursive flatten up to maxObjectDepth)
    │       ├── route params
    │       └── sensitive headers (user-agent, referer, cookie, x-forwarded-for)
    │
    ├─► [3] Application-layer guards
    │       ├── Request shape limits
    │       ├── HTTP Parameter Pollution (when enabled)
    │       ├── Prototype Pollution keys
    │       └── Path Traversal values
    │
    ├─► [4] Multi-layer decoding per value
    │       ├── URL decode (up to 3 passes — anti double-encoding)
    │       ├── HTML entities (&lt; &amp; &#x27; etc.)
    │       └── Unicode zero-width strip
    │
    ├─► [5] Parallel scan per detector
    │       ├── SQLInjectionDetector.scan(value)
    │       ├── XSSDetector.scan(value)
    │       └── NoSQLDetector.scan(rawValue)  ← receives object or string
    │
    ├─► [6] Threat detected?
    │       ├── YES → recordSuspicious(ip) · log · onThreat() · 400
    │       └── NO  → next()
    │
    └─► Application route
```

### Intelligent Rate Limiting

Parry_DDoS maintains **two independent in-memory counters** per observed IP in the current Node.js process:

```
IP: 203.0.113.42
├── timestamps[]   → sliding window of normal requests
│                    (blocked when > maxRequests)
└── suspicious     → incremented on every detected attack
                     (banned when >= suspiciousThreshold)
```

This means an IP can exceed the request limit without being marked malicious, while an IP making only a few malicious requests is temporarily banned after reaching the suspicious threshold.

The `RateLimiter` runs automatic cleanup every 10 minutes to prevent unbounded memory growth. In multi-process, serverless, or clustered deployments, each instance has its own local counters unless you add shared persistence.

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

### DDoS Scope and Edge Protection

Parry_DDoS runs inside Express after traffic has already reached your Node.js process. It can reject malicious or excessive application-layer requests seen by that process, but it does not absorb volumetric floods, network-layer attacks, or connection exhaustion that must be stopped before the application receives traffic.

For volumetric DDoS protection, use edge and infrastructure controls such as CloudFront, AWS WAF, AWS Shield, ALB rate-based rules, or an equivalent CDN, WAF, load balancer, or provider-level protection. Treat Parry_DDoS as one application-layer control behind those services.

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
│   ├── rate-limit/           ← Sliding-window limiter
│   ├── stores/               ← In-memory store
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
│   │   └── rateLimiter.test.js      ← RateLimiter tests
│   ├── integration/
│   │   └── middleware.test.js   ← Middleware end-to-end with req/res mock
│   ├── fixtures/
│   │   ├── payloads.js              ← Reusable attack payloads
│   │   └── application-layer.js     ← Curated guard fixtures
│   └── index.js                 ← Aggregated test runner
│
├── scripts/
│   ├── test-server.js        ← Express server for real HTTP tests
│   └── run-tests.js          ← 63 HTTP test suite against the server
│
├── examples/
│   └── express-basic.js      ← Full integration example
│
├── docs/
│   └── architecture.md       ← Documented design decisions
│
└── package.json
```

---

## Tests

Parry_DDoS has two independent test suites totalling **171 tests**.

### Local suite (108 tests) — no network, no server

```bash
npm test
```

Covers isolated detectors, application-layer guards, the `RateLimiter`, the core engine, and the middleware with `req`/`res` mocks. Runs in any environment, including CI.

```
▶ Unit — Detectors          32 tests
▶ Unit — RateLimiter         9 tests
▶ Unit — Core Engine         6 tests
▶ Unit — App Guards         19 tests
▶ Integration — Middleware  42 tests
─────────────────────────────────────
Total                      108 tests  |  0 failures
```

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

Parry_DDoS injects the following headers into **every** response:

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
```

---

## SIEM and Alert Integration

Use the `onThreat` callback to forward events to any external system:

```js
// Slack
Parry_DDoS({
  onThreat(entry) {
    // New threat events include top-level detector, severity, reason, and target
    // while preserving entry.threats[] for compatibility.
    fetch('https://hooks.slack.com/services/...', {
      method: 'POST',
      body: JSON.stringify({
        text: `🚨 *${entry.threats[0].detector}* detected\nIP: ${entry.ip}\nRoute: ${entry.method} ${entry.url}`,
      }),
    });
  },
});

// DataDog
Parry_DDoS({
  onThreat(entry) {
    dogstatsd.increment('parry_ddos.threat', 1, [`detector:${entry.threats[0].detector}`]);
  },
});

// Structured log file (NDJSON)
const fs = require('fs');
Parry_DDoS({
  logThreats: false, // disable console output, use callback only
  onThreat(entry) {
    fs.appendFileSync('threats.ndjson', JSON.stringify(entry) + '\n');
  },
});
```

---

## TypeScript

Parry_DDoS includes full typings with no `@types/*` required:

```ts
import { Parry_DDoS, Parry_DDoSOptions, ThreatLogEntry } from './src/middleware';

const options: Parry_DDoSOptions = {
  suspiciousThreshold: 3,
  onThreat: (entry: ThreatLogEntry) => {
    console.log(entry.threats);
  },
};

app.use(Parry_DDoS(options));
```

Exported types: `Parry_DDoSOptions`, `ThreatLogEntry`, `ThreatMatch`, `RateLimitResult`, `IPSnapshot`, `DetectorType`, `LogEntryType`, `RateLimiter`, `SQLInjectionDetector`, `XSSDetector`, `NoSQLDetector`, `HPPDetector`, `PrototypePollutionDetector`, `PathTraversalDetector`, `RequestShapeGuard`.

---

## Roadmap

Parry_DDoS is under active development. Upcoming versions focus on stronger application-layer controls, production hardening, and clearer integration with edge protection layers:

### `v1.1` — Production Hardening

- [ ] CIDR verification for trusted proxies before accepting `X-Forwarded-For`
- [ ] Protection against Header Injection and HTTP Response Splitting
- [ ] IP and route allowlist support for excluding specific paths from inspection

### `v1.2` — Distributed Persistence

- [ ] Redis adapter for `RateLimiter` — multi-instance and Kubernetes cluster support without state loss
- [ ] `StorageAdapter` interface to plug in any backend (Memcached, DynamoDB, etc.)
- [ ] Real-time ban synchronization across instances via Pub/Sub

### `v1.3` — Application-Layer Abuse Controls

- [ ] Token Bucket with per-route burst control
- [ ] Request fingerprinting for repeated application-layer attack patterns
- [ ] Hooks for challenge-response providers when clients enter a grey zone
- [ ] Guidance for handling slow requests at the proxy/load-balancer layer

### `v1.4` — Operations and Observability

- [ ] Docker and Kubernetes deployment examples for applications using the middleware
- [ ] Reference architectures behind CloudFront, AWS WAF, Shield, ALB, or equivalent edge protection
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
  <sub>Built with native Node.js · Zero production dependencies · Tested with 171 application-layer cases</sub>
</div>
