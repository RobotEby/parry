# Parry

Application-layer security middleware for Express.js.

## Overview

Parry is a CommonJS security middleware for Express applications. It helps block common application-layer abuse before requests reach route handlers, while keeping the public API small and compatible with standard Express middleware usage.

Parry detects and blocks patterns associated with SQL injection, XSS, NoSQL injection, HTTP parameter pollution, prototype pollution, path traversal, rate abuse, and brute-force authentication attempts. It also emits structured Threat Events and metrics that can be inspected through an optional read-only Admin API.

Parry is not a complete volumetric DDoS protection product. Network floods, L3/L4 abuse, TLS exhaustion, CDN filtering, and edge rate controls should be handled by CloudFront, AWS WAF, Shield, a CDN, an ALB/load balancer, or equivalent infrastructure controls.

## Why Parry

Parry centralizes application-layer security policy in one Express middleware. That gives backend teams a consistent place to tune detector behavior, route-based limits, brute-force protection, event logging, and distributed rate limiting.

It is designed for development and production-like deployments:

- use `MemoryStore` for local development and single-process services;
- use `RedisStore` for multiple instances, containers, ECS, Kubernetes, PM2 cluster, or load-balanced services;
- expose the Admin API only behind authentication, private networking, VPN, or a trusted reverse proxy.

## Features

- SQL injection detection
- XSS detection
- NoSQL injection detection
- HTTP parameter pollution checks
- Prototype pollution checks
- Path traversal checks
- Request shape guard
- Global and route-based rate limiting
- BruteForceGuard for authentication routes
- `MemoryStore` and optional `RedisStore`
- Structured Threat Events
- Metrics and observability helpers
- Optional read-only Admin API
- Route-based policies and presets
- Docker demo API
- AWS reference infrastructure

## Installation

```bash
npm install @roboteby/parry
```

Parry expects Express to be installed by your application.

## Quick Start

```js
const express = require('express');
const { createParry } = require('@roboteby/parry');

const app = express();

const parry = createParry({
  preset: 'recommended',
});

app.use(express.json());
app.use(parry.middleware());

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.listen(3000);
```

Parse JSON and URL-encoded bodies before Parry when you want Parry to inspect request bodies. Keep Parry before routes that should be protected.

The legacy `Parry_DDoS(options)` export remains available for existing CommonJS integrations:

```js
const { Parry_DDoS } = require('@roboteby/parry');

app.use(express.json());
app.use(Parry_DDoS({ preset: 'recommended' }));
```

## Presets

Parry supports conservative presets for common application-layer protection:

- `off`: no route-policy preset is added.
- `recommended`: enables practical defaults for common auth routes and low-noise application-layer checks.
- `strict`: uses more restrictive brute-force and route rate-limit defaults for sensitive environments.

Every option can still be configured explicitly. Prefer starting with `recommended`, reviewing logs and events, then tightening route policies where needed.

## Stores

`MemoryStore` is the default store. It is suitable for tests, demos, local development, and single-process deployments.

For distributed deployments, use `RedisStore` with a Redis client created by your application:

```js
const { createClient } = require('redis');
const { createParry, RedisStore } = require('@roboteby/parry');

const redis = createClient({ url: process.env.REDIS_URL });
await redis.connect();

const parry = createParry({
  store: new RedisStore({ client: redis, prefix: 'parry' }),
  rateLimit: {
    enabled: true,
    max: 100,
    windowMs: 60_000,
    headers: true,
  },
});
```

If your service runs behind multiple instances, containers, or load balancers, use a shared store. `MemoryStore` protects only the current Node.js process.

## Brute-Force Protection

Route policies can protect sensitive authentication endpoints without making the global rate limit too aggressive:

```js
const parry = createParry({
  policies: [
    {
      name: 'auth-login',
      match: { method: 'POST', path: '/login' },
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
        resetOnSuccess: true,
      },
    },
  ],
});
```

Routes can also report authentication outcomes manually:

```js
app.post('/login', async (req, res) => {
  const user = await authService.validate(req.body.email, req.body.password);

  if (!user) {
    req.parry?.recordAuthFailure('invalid_credentials');
    return res.status(200).json({ success: false });
  }

  req.parry?.recordAuthSuccess();
  return res.json({ success: true });
});
```

## Threat Events and Admin API

Parry emits structured Threat Events for blocked requests, rate limits, brute-force blocks, store errors, and hook errors. Events are sanitized before reaching logs, hooks, metrics, or the Admin API.

The optional Admin API is read-only and is never mounted automatically:

```js
const { createParry, createParryAdminRouter } = require('@roboteby/parry');

const parry = createParry({
  admin: {
    enabled: true,
    auth: {
      mode: 'token',
      token: process.env.PARRY_ADMIN_TOKEN,
    },
  },
});

app.use(parry.middleware());
app.use('/_parry', createParryAdminRouter(parry));
```

Main endpoints:

- `GET /_parry/health`
- `GET /_parry/metrics`
- `GET /_parry/events`
- `GET /_parry/events/:id`
- `GET /_parry/bans`
- `GET /_parry/policies`

Protect the Admin API with token auth for local demos, or with VPN, private networking, Cloudflare Access, AWS ALB/Cognito auth, trusted proxy auth, or IP allowlists in production.

## Parry Security Console

The separate `parry-security-console` repository provides a read-only dashboard for the Parry Admin API. It displays health, metrics, Threat Events, bans/blocks, and route policies. It does not contain middleware logic, does not execute payloads, and is not a scanner.

For local development, the console can use Vite proxying with `VITE_PARRY_API_URL=/api/parry`.

## Docker Demo

The repository includes a demo Express API with Redis:

```bash
docker compose up --build
```

Useful local checks:

```bash
curl http://localhost:3000/health

curl http://localhost:3000/_parry/health \
  -H "x-parry-admin-token: change-me"

curl -X POST http://localhost:3000/echo \
  -H "Content-Type: application/json" \
  -d '{"message":"hello"}'
```

The `change-me` token is for local demos only.

## Security Model

Parry operates inside the Express application. It helps identify and block suspicious application-layer requests, but it does not replace edge and infrastructure controls.

Production deployments should account for:

- CloudFront, AWS WAF, Shield, CDN, ALB, or equivalent edge protection for volumetric DDoS and network-layer abuse.
- RedisStore or another shared store for distributed rate limits and brute-force counters.
- Admin API authentication and network restrictions.
- Trusted proxy configuration before accepting `x-forwarded-for`, Cloudflare Access, ALB/Cognito, or reverse-proxy identity headers.
- Generic authentication responses that do not reveal whether a username or email exists.

Browser-visible Admin API tokens are appropriate only for local development and demos. Production consoles should be protected by VPN, private networking, Cloudflare Access, ALB/Cognito, reverse proxy auth, or a backend/admin gateway.

## Documentation

Additional documentation is available in the repository:

- [Admin API](https://github.com/RobotEby/parry-express-security-middleware/blob/main/docs/admin-api.md)
- [Admin API authentication](https://github.com/RobotEby/parry-express-security-middleware/blob/main/docs/admin-api-auth.md)
- [AWS Admin API authentication](https://github.com/RobotEby/parry-express-security-middleware/blob/main/docs/aws-admin-auth.md)
- [Docker demo](https://github.com/RobotEby/parry-express-security-middleware/blob/main/docs/docker-demo.md)
- [AWS infrastructure notes](https://github.com/RobotEby/parry-express-security-middleware/blob/main/docs/aws-infra.md)
- [CI/CD](https://github.com/RobotEby/parry-express-security-middleware/blob/main/docs/ci-cd.md)
- [Release process](https://github.com/RobotEby/parry-express-security-middleware/blob/main/docs/release.md)
- [Payload regression testing](https://github.com/RobotEby/parry-express-security-middleware/blob/main/docs/testing-payloads.md)
- [Architecture](https://github.com/RobotEby/parry-express-security-middleware/blob/main/docs/architecture.md)

The npm package keeps `docs/`, infrastructure, Docker demo files, and tests out of the published runtime package.

## Development

```bash
npm ci
npm test
npm run test:fixtures
npm run test:payload-regression
npm run package:check
npm pack --dry-run
```

`npm test` uses local mocks and fake stores. It does not require Redis, AWS, Cloudflare, or external services.

## Roadmap

Planned areas for future work:

- Redis-backed event persistence
- OpenTelemetry and Prometheus export
- Express 4 compatibility matrix
- Optional hashing/redaction for store keys
- Additional detector tuning with benign counterexamples
- Admin API hardening and deployment guides

## License

MIT
