# Parry

[![npm version](https://img.shields.io/npm/v/@roboteby/parry)](https://www.npmjs.com/package/@roboteby/parry)
[![license](https://img.shields.io/npm/l/@roboteby/parry)](./LICENSE)
[![node](https://img.shields.io/node/v/@roboteby/parry)](https://www.npmjs.com/package/@roboteby/parry)

Application-layer security middleware for Express that combines abuse detection,
request guards, rate limiting, brute-force protection and security observability.

The current stable release is `@roboteby/parry@2.0.0` on the npm `latest`
dist-tag.

## Install

```bash
npm install @roboteby/parry express@^5.2.1
```

Parry 2 requires Node.js `>=22` and Express `^5.2.1`.

## Minimal example

```js
const express = require('express');
const { createParry } = require('@roboteby/parry');

const app = express();
app.use(express.json({ limit: '64kb' }));

const parry = createParry({ preset: 'recommended' });
app.use(parry.middleware());

app.get('/health', (_req, res) => res.json({ ok: true }));
app.listen(3000);
```

Body parsers must run before Parry when request bodies should be inspected.
Mount Parry before the routes it protects.

## Main capabilities

- Request Shape limits for depth, key count, array length and string length.
- Heuristic SQL injection and XSS detection, plus NoSQL operator guards.
- HTTP parameter pollution, prototype pollution and path traversal guards.
- Global and route-specific rate limiting.
- Brute-force counters and temporary blocks for authentication routes.
- Sanitized Threat Events, process-local metrics and an optional read-only Admin
  API.
- In-memory state by default, with an optional `RedisStore` for shared protection
  state.

## Security boundaries

Parry is a defense-in-depth control for the Express application layer. It is not
a WAF and does not replace a CDN, reverse proxy, load balancer or volumetric
L3/L4 DDoS protection. It also does not replace authentication, authorization,
schema validation, parameterized queries, context-aware escaping/output
encoding or CSP.

SQLi and XSS detection is heuristic, so false positives and false negatives are
possible. Request Shape runs before heavier scans to bound their cost, but an
allowed request is not proof that its input is safe for downstream use.

Trusted proxy handling depends on narrow, correct `trustedProxies`
configuration. See the [security model](./docs/security-model.md) before enabling
forwarded-header trust.

## Public API

The recommended root exports are:

- `createParry(options)` — creates the middleware and its observability context.
- `createParryAdminRouter(parry, options)` — creates the optional Admin router.
- `MemoryStore` — keeps protection state in one process.
- `RedisStore` — uses an application-owned Redis client for shared protection
  state.

Existing exports remain available. `Parry_DDoS(options)` is a deprecated
compatibility wrapper around `createParry(options).middleware()`, and
`Parry_DDoSOptions` is a deprecated TypeScript alias for `ParryOptions`.

Advanced typed exports are available from `/core`, `/detectors`, `/stores`,
`/policies`, `/brute-force`, `/events`, `/observability` and `/admin`.

## Admin API

The Admin API exposes health, process metrics, recent sanitized events, active
bans and normalized policies. It is never mounted automatically and fails during
construction unless authentication is configured:

```js
const { createParryAdminRouter } = require('@roboteby/parry');

app.use(
  '/_parry',
  createParryAdminRouter(parry, {
    auth: {
      mode: 'token',
      token: process.env.PARRY_ADMIN_TOKEN,
    },
  })
);
```

Anonymous Admin access is an explicit local-development opt-in and is rejected
in production. External identity modes depend on a configured trusted boundary;
Parry does not perform cryptographic JWT/JWKS verification, and `verifyJwt: true`
fails explicitly.

See [Admin API](./docs/admin-api.md) for authentication modes and deployment
guidance.

## Redis

The application creates and connects the Redis client. Parry does not install or
own a Redis package implicitly.

```js
const { createClient } = require('redis');
const { createParry, RedisStore } = require('@roboteby/parry');

const client = createClient({ url: process.env.REDIS_URL });
await client.connect();

const parry = createParry({
  store: new RedisStore({ client, prefix: 'parry' }),
  storeFailureMode: 'fail-closed',
});
```

`RedisStore` shares rate-limit state, brute-force state, counters and related
bans/blocks across instances. Threat Events, the default event buffer and
metrics remain local to each process unless the application exports them.

## Runtime support

- Node.js `>=22`
- Express `^5.2.1`
- CommonJS

CI covers Node.js 22 and 24. Parry 2 does not imply or announce an ESM migration.

## Documentation

- [Configuration](./docs/configuration.md)
- [Security model](./docs/security-model.md)
- [Admin API](./docs/admin-api.md)
- [Deployment](./docs/deployment.md)
- [Testing](./docs/testing.md)
- [Architecture](./docs/architecture.md)
- [Releasing](./docs/releasing.md)
- [OpenAPI contract](./docs/openapi/parry-admin-api.yaml)
- [Generated payload regression report](./docs/payload-regression-report.md)

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the development workflow and
[SECURITY.md](./SECURITY.md) for vulnerability reporting.

## License

[MIT](./LICENSE)
