# Payload Regression Testing

Parry keeps a small defensive payload regression suite under `tests/fixtures/payloads`.
These fixtures exist to prevent detector regressions and false-positive drift in the
application-layer middleware.

## Reference Source

When available locally, `external/PayloadsAllTheThings` may be used as a read-only
reference for known web security payload categories. The external repository is not
required for tests, is not imported by test code, and is not included in runtime code.

The fixtures committed to this repository are small, curated, local examples. They are
not a vendored copy of PayloadsAllTheThings.

PayloadsAllTheThings attribution:

- Project: PayloadsAllTheThings
- Repository: https://github.com/swisskyrepo/PayloadsAllTheThings

Review the upstream license and project guidance before copying external content at
larger scale. Do not copy large blocks from external payload lists into this project.

## Defensive Use Rules

- Payloads are never executed as JavaScript.
- Payloads are never executed as shell commands.
- Payloads are never used in real database queries.
- SSRF fixtures never make HTTP, DNS, or network requests.
- Command Injection fixtures are strings only and are never passed to a shell.
- Request Shape fixtures are synthetic and bounded for fast CI execution.
- Fixtures live only in `tests/fixtures` and documentation, never in `src` runtime code.

## Commands

```bash
npm run test:fixtures
npm run test:payload-regression
npm run test:payload-report
npm test
```

`test:fixtures` validates schema, IDs, category/file consistency, severity/mode values,
and exact fixture counts.

`test:payload-regression` runs detector and middleware regression checks against the
curated fixtures.

`test:payload-report` regenerates `docs/payload-regression-report.md` without internet
access.

## Coverage Model

Implemented detector categories are enforced in tests: SQL Injection, XSS, NoSQL
Injection, HTTP Parameter Pollution, Prototype Pollution, Path Traversal, Request Shape,
and BruteForceGuard scenarios.

Command Injection and SSRF fixtures are monitor/pending coverage in this version because
Parry does not currently ship dedicated detectors for those categories. They remain in
the fixture set so future detectors can be added with regression coverage already shaped.

Benign fixtures are first-class controls. If a benign fixture is blocked, adjust the
detector carefully or mark a future strict/monitor behavior explicitly; do not remove the
benign control just to make a test pass.
