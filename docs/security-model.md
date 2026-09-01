# Security Model

Parry protects the Express application layer. It evaluates parsed request data,
applies local or distributed abuse state, and emits sanitized operational events.
It is defense in depth, not a standalone security boundary for the entire stack.
It is not a WAF and does not provide infrastructure-level volumetric DDoS
protection.

## Responsibilities

Parry can:

- reject excessive request depth, key count, array length, and string length;
- detect bounded heuristic patterns associated with SQLi and XSS;
- reject dangerous or unapproved NoSQL operators;
- detect HPP, prototype-pollution keys, and path traversal sequences;
- enforce global and route-specific rate/brute-force policies;
- keep shared counters and bans when configured with Redis.

The application still owns authentication, authorization, schema validation,
parameterized database access, output encoding, safe file handling, secrets, and
correct error handling. Infrastructure owns TLS termination, edge filtering, bot
controls, network isolation, volumetric DDoS resistance, and availability
scaling.

## Heuristic detectors

SQLi/XSS pattern matching can produce false positives and false negatives. Parry
runs the Request Shape guard before regex-based scans and uses bounded patterns,
but no regex list can understand every downstream SQL, HTML, template, or script
context. Test representative application traffic and keep primary controls in
the sink: parameterized queries for SQL, context-aware escaping/CSP for browsers,
and explicit operator construction for databases.

## Request scanning flow

1. Resolve the direct client or trusted proxy chain and assign a request ID.
2. Apply brute-force and route/global rate-limit state.
3. Run Request Shape; stop heavier scans when a limit is violated.
4. Inspect HPP, prototype keys, and NoSQL once over structured surfaces.
5. Collect scalar leaves once and scan them for SQLi, XSS, and path traversal.
6. Deduplicate findings and choose the highest finding severity.
7. Block with the existing response shape and emit a sanitized Threat Event.

## Proxy trust

Parry ignores `x-forwarded-for` and `x-real-ip` unless
`trustProxyHeaders: true` and the direct socket peer matches `trustedProxies`.
For XFF, it validates a bounded chain, walks from right to left, discards trusted
proxy hops, and selects the first untrusted hop. All-trusted chains use the
leftmost forwarded address. Empty, malformed, or overlong chains fall back to
the direct socket IP.

This supports boundaries such as client → Cloudflare → ALB → Express without
letting a public client select the leftmost header value. Keep CIDRs narrow and
update them through an operational process.

## State and observability

`RedisStore` distributes counters and bans only. Metrics, listeners, and the
default event buffer are local to a process. Treat the Admin API as sensitive
operational data and export events to a durable system when audit retention is
required.

Events are sanitized, but consumers should still apply least privilege and data
retention limits. Parry does not log raw request bodies as an audit trail.

## Admin boundary

The Admin router is never mounted automatically and fails closed without auth.
Anonymous local opt-ins are forbidden in production. See [Admin API](./admin-api.md).

Report security issues through [SECURITY.md](../SECURITY.md).
