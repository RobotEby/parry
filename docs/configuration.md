# Configuration

`createParry(options)` validates configuration synchronously and returns a Parry
instance. Invalid positive limits, event capacity, policy matches, header names,
IP/CIDR rules, NoSQL allowlists, and Redis client contracts fail early.

## Detection

```js
const parry = createParry({
  sql: true,
  xss: true,
  nosql: true,
  hpp: { enabled: false, allowDuplicateParamsFor: [] },
  prototypePollution: { enabled: true },
  pathTraversal: { enabled: true },
  requestShape: {
    enabled: true,
    maxDepth: 8,
    maxKeys: 500,
    maxArrayLength: 100,
    maxStringLength: 10_000,
  },
});
```

Request Shape runs first. If a shape limit is exceeded, Parry stops the heavier
application-layer scans for that request. HPP, Prototype Pollution, and NoSQL
inspect structured surfaces. SQLi, XSS, and Path Traversal inspect scalar leaves
from query, params, body, and selected headers.

Plain display placeholders such as `${value}` and `{{value}}` are accepted.
Executable template expressions containing constructs such as `alert(` or
`constructor.constructor` remain blocked.

## Exact-path NoSQL allowlists

Only known suspicious operators can be allowed and only at their exact parent
path:

```js
const parry = createParry({
  nosql: {
    enabled: true,
    allowedOperators: {
      'body.filters.price': ['$gt', '$lte'],
    },
  },
});
```

An allowlist for `body.filters.price` does not apply to
`body.filters.discount`, child objects, query, or params. `$where`, `$expr`,
`$function`, and `$accumulator` can never be allowlisted. Operators nested under
an allowed object continue to be inspected against their own exact paths.

## Header scanning

The compatibility default is:

```js
headers: {
  scan: ['user-agent', 'referer', 'x-forwarded-for', 'cookie'];
}
```

Names are validated, normalized to lowercase, and deduplicated. Set `scan: []`
to disable detector scanning of headers. This does not change the separate use
of headers for request IDs, proxy resolution, or Admin authentication.

## Rate limiting and stores

```js
const parry = createParry({
  rateLimit: {
    enabled: true,
    max: 100,
    windowMs: 60_000,
    headers: true,
  },
  suspiciousThreshold: 5,
  banDurationMs: 300_000,
  storeFailureMode: 'fail-open',
});
```

`MemoryStore` is the default. Use `RedisStore` for shared counters and bans. The
application supplies a connected Redis client implementing the documented
contract. `fail-open` keeps traffic flowing on a store error; `fail-closed`
returns 503.

## Route policies and brute force

```js
policies: [
  {
    name: 'auth-login',
    match: { method: 'POST', path: '/login' },
    rateLimit: { enabled: true, max: 20, windowMs: 60_000, key: 'ip' },
    bruteForce: {
      enabled: true,
      maxAttempts: 5,
      windowMs: 15 * 60_000,
      blockDurationMs: 10 * 60_000,
      keys: ['ip', 'body.email', 'ip+body.email'],
      resetOnSuccess: true,
    },
  },
];
```

Every explicit policy needs a non-empty name and a match containing method or
path. Available presets are `off`, `recommended`, and `strict`. Authentication
routes can call `req.parry.recordAuthFailure(reason)` and
`req.parry.recordAuthSuccess()` when status codes do not express the outcome.

## Request IDs

```js
requestId: {
  enabled: true,
  header: 'x-request-id',
  responseHeader: 'X-Parry-Request-Id',
}
```

An incoming configured header is preserved. Otherwise Parry generates
`req_<UUID>`. `responseHeader: false` keeps the ID internal.

## Trusted proxies

```js
trustProxyHeaders: true,
trustedProxies: ['10.0.0.0/8', '173.245.48.0/20'],
```

Forwarded headers are considered only when the direct socket peer is trusted.
See [the security model](./security-model.md) for the chain algorithm.

## Events and callbacks

```js
events: { maxEvents: 500 },
logThreats: true,
onThreat(event, req, res) {},
onEvent(event) {},
onStoreError(error, event) {},
```

The in-memory event buffer and metrics are per process. Export events explicitly
to make observability distributed.

Admin options are documented separately in [Admin API](./admin-api.md).
