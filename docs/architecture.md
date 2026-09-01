# Architecture

Parry 2.0.0 is CommonJS. `src/index.js` is the compatibility surface; the
implementation is split by responsibility:

```text
src/
  express/          middleware lifecycle, request targets, proxy IP, responses
  core/             scan decisions, scoring, event conversion
  detectors/        SQLi, XSS, NoSQL, HPP, prototype, path, request shape
  rate-limit/        global rate-limit orchestration
  stores/            MemoryStore and RedisStore
  policies/          matching, normalization, presets
  brute-force/       auth outcomes, keys, blocks
  events/            sanitization, in-memory event store, listeners
  observability/     process-local metrics and snapshots
  admin/             read-only router and auth strategies
```

Internal compatibility wrappers were removed. `src/core/index.js` imports the
real rate-limit and logger modules, and the package root imports the real Express
middleware module. No removed wrapper was a package export.

## Request lifecycle

```text
Express request
  -> trusted client IP + request ID
  -> brute-force block check
  -> route policy rate limit
  -> global rate limit
  -> Request Shape guard
  -> structured guards (HPP, prototype, NoSQL)
  -> scalar leaf collection
  -> SQLi, XSS, path traversal
  -> deduplicate + maximum severity
  -> allow OR block + sanitized Threat Event
```

The shape guard protects downstream work. Query, params, body, and configured
headers are traversed once for scalar leaves. `stringValue` is created during
collection and reused by scalar detectors. Structured NoSQL inspection maintains
exact paths for operator policy.

## State ownership

The store owns rate-limit counters, suspicious counts, bans, generic counters,
and brute-force blocks. The event bus, recent-event buffer, and metrics belong to
one Parry instance. `createParryAdminRouter` resolves that instance context but
does not mount or authenticate itself implicitly.

## Compatibility

The root retains all existing exports. The recommended stable exports are
`createParry`, `createParryAdminRouter`, `MemoryStore`, and `RedisStore`.
Advanced subpaths expose implementation-level APIs with specific declaration
files. Event and response formats remain compatible; Admin anonymity by omission
is the intentional security behavior change documented in the changelog. The
current package does not imply or announce an ESM migration.
