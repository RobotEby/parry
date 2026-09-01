# Parry

[![npm version](https://img.shields.io/npm/v/@roboteby/parry)](https://www.npmjs.com/package/@roboteby/parry)
[![license](https://img.shields.io/npm/l/@roboteby/parry)](./LICENSE)
[![node](https://img.shields.io/node/v/@roboteby/parry)](https://www.npmjs.com/package/@roboteby/parry)

Application-layer security middleware for Express 5.

Parry combines request-shape limits, heuristic SQL injection/XSS/NoSQL checks,
HTTP parameter pollution and prototype/path traversal guards with rate limiting,
route policies, brute-force protection, sanitized Threat Events, and an optional
read-only Admin API. It is CommonJS and has no mandatory Redis dependency.

The stable npm release is `1.1.1` on `latest`. The earlier `1.1.0-rc.1` remains
available on the `rc` dist-tag; it is not the recommended installation.

## Install

```bash
npm install @roboteby/parry
```

Express `^5.2.1` is a peer dependency.

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

Body parsers must run before Parry if request bodies should be inspected. Mount
Parry before the routes it protects.

## Security boundaries

Parry is one application-layer control. It does not replace validation and
parameterized queries in the application, output encoding and CSP in the browser,
authentication/authorization, a reverse proxy, CDN/WAF, load balancer, or
volumetric L3/L4 DDoS protection.

SQLi and XSS detection is heuristic. The patterns are intentionally bounded and
the Request Shape guard runs before heavier scans, but applications still need
tests for their own traffic and false-positive profile. A clean Parry decision is
not proof that input is safe for every downstream interpreter.

When `MemoryStore` is used, counters and bans exist only inside one Node.js
process. `RedisStore` shares rate-limit and brute-force state across instances.
Threat Events, the in-memory event buffer, and metrics remain local to each
process unless the application exports them through `onEvent` or another
observability integration.

See [the security model](./docs/security-model.md) and [configuration](./docs/configuration.md).

## Public API

The four recommended stable exports are:

- `createParry(options)` — create a middleware instance and observability context;
- `createParryAdminRouter(parry, options)` — create the optional read-only Admin router;
- `MemoryStore` — single-process state store;
- `RedisStore` — adapter for an application-owned Redis client.

All existing exports remain available. `Parry_DDoS(options)` is deprecated but
kept as a compatibility wrapper around `createParry(options).middleware()`.
`Parry_DDoSOptions` remains a deprecated TypeScript alias for `ParryOptions`.

Advanced APIs have typed subpaths: `/core`, `/detectors`, `/stores`, `/policies`,
`/brute-force`, `/events`, `/observability`, and `/admin`.

## Admin API is fail-closed

The Admin router now throws during construction when no authentication strategy
is configured:

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

`allowInsecureAdminApi: true`, `auth.mode: 'none'`, and the legacy
`requireAuth: false` alias are explicit local-development opt-ins. They warn and
are rejected whenever `NODE_ENV=production`, even if an override is present.
An empty token is invalid. External Cloudflare/ALB modes validate a trusted
boundary but do not pretend that decoding a JWT is cryptographic verification;
`verifyJwt: true` fails explicitly in this 1.x implementation.

Full configuration and deployment patterns are in [Admin API](./docs/admin-api.md).

## Redis

Create and connect the Redis client in the application; Parry never installs or
owns a Redis package implicitly.

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

## Runtime support

The 1.x package keeps `engines.node >=18` and CI covers Node 18, 20, 22, and 24.
Node 18 and 20 are legacy/EOL compatibility targets. Use Node 22 or 24 for new
production deployments. Raising the minimum to Node 22 is reserved for v2. See
the [official Node.js release schedule](https://nodejs.org/en/about/previous-releases).

## Documentation

- [Configuration](./docs/configuration.md)
- [Security model](./docs/security-model.md)
- [Admin API](./docs/admin-api.md)
- [Testing](./docs/testing.md)
- [Deployment](./docs/deployment.md)
- [Architecture](./docs/architecture.md)
- [Releasing](./docs/releasing.md)
- [OpenAPI contract](./docs/openapi/parry-admin-api.yaml)
- [Generated payload regression report](./docs/payload-regression-report.md)

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development workflow and
[SECURITY.md](./SECURITY.md) for vulnerability reporting.

## License

[MIT](./LICENSE)
