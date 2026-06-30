# Architecture

Parry is organized around a small Express adapter and a reusable application-layer analysis core. The goal is to keep request/response handling separate from detector logic, store implementations, event generation, and observability.

## Directory Structure

```txt
parry-express-security-middleware/
├── src/
│   ├── admin/          Optional read-only Admin API router and auth strategies
│   ├── brute-force/    BruteForceGuard and authentication key builder
│   ├── core/           Analysis engine, scoring, and threat event helpers
│   ├── detectors/      SQLi, XSS, NoSQLi, HPP, prototype pollution, path traversal, and shape guards
│   ├── events/         Event bus, event sanitization, and in-memory event store
│   ├── express/        Express adapter: req/res/next, IP resolution, request targets, responses
│   ├── logger/         Console reporter
│   ├── middleware/     Compatibility entrypoints for legacy imports
│   ├── observability/  Metrics and Admin API snapshot helpers
│   ├── policies/       Route policy matching and normalization
│   ├── rate-limit/     Store-backed rate limiter
│   ├── stores/         Store contract, MemoryStore, and RedisStore
│   └── utils/          Shared decode, flatten, and normalize helpers
├── config/             Runtime defaults
├── constants/          Centralized detector patterns
├── types/              Public TypeScript declarations
├── tests/              Unit, integration, and payload regression tests
└── docs/               Repository documentation
```

## Express Adapter and Core Engine

Only `src/express/` knows about `req`, `res`, and `next`. It resolves the client IP, attaches request context, applies route policies, calls the rate limiter, collects request targets, and formats HTTP responses.

The core engine receives normalized request data and returns a structured decision. This keeps detector behavior testable without a running HTTP server and leaves room for future adapters if needed.

## Detector Organization

Detector modules live under `src/detectors/`. Shared decoding and normalization helpers live under `src/utils/`, and common regex patterns live in `constants/patterns.js`.

Centralizing patterns keeps detector tuning easier to review and makes it simpler to add benign counterexamples when a rule needs adjustment. Payload regression fixtures live under `tests/fixtures/payloads/` and are used only by tests.

## Stores and Rate Limiting

The rate limiter depends on the Store interface instead of a specific storage implementation.

- `MemoryStore` is the default and protects a single Node.js process.
- `RedisStore` accepts a Redis client created by the host application and coordinates counters across instances.

Rate limiting, temporary bans, suspicious counters, brute-force counters, and route policy counters use separate namespaces so one control does not overwrite another.

## Route Policies and BruteForceGuard

Route policies are evaluated in the Express adapter because they depend on request method, path, route response status, and `res.on('finish')`.

The BruteForceGuard checks blocked keys before a route handler runs, then records authentication failures or successes after the response finishes. Applications that return `200` for failed logins can call `req.parry.recordAuthFailure()` or `req.parry.recordAuthSuccess()` to avoid relying only on status codes.

## Threat Events and Observability

Security-relevant activity is normalized into Threat Events. Events are sanitized before they reach listeners, logs, metrics, the in-memory event store, or the Admin API.

The Admin API is a separate read-only Express router. It is never mounted automatically and should be protected by token auth for local demos or by stronger production controls such as private networking, VPN, Cloudflare Access, AWS ALB/Cognito auth, trusted proxy auth, or IP allowlists.

## Proxy and Client IP Handling

Parry ignores forwarded IP headers by default. When running behind a trusted proxy, configure `trustProxyHeaders` and `trustedProxies` so forwarded client IPs are accepted only from known proxy addresses or CIDR ranges.

The same boundary model applies to Admin API external-auth modes. Cloudflare Access and AWS ALB/Cognito headers are accepted only when the request comes through a trusted boundary or presents a configured shared proxy secret.

## Production Notes

Parry operates inside the application. It complements, but does not replace, CDN, WAF, load balancer, and cloud edge controls. Use CloudFront, AWS WAF, Shield, ALB, a CDN, or equivalent infrastructure for volumetric DDoS and network-layer protection.
