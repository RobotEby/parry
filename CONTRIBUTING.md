# Contributing

Thank you for improving Parry. Keep changes focused, preserve CommonJS and the
documented 2.x API, and add regression coverage for behavior changes.

## Development

Requirements:

- Node 22 or 24; CI covers both supported runtime lines;
- npm with lockfile support;
- Docker and Terraform only for their optional validation steps.

```bash
npm ci
npm test
npm run lint
npm run format:check
```

Before opening a pull request, run the complete checklist in
[docs/testing.md](./docs/testing.md). Use `npm run format` for mechanical
formatting. Do not edit the generated payload report by hand; update fixtures and
run `npm run test:payload-report`.

## Tests and fixtures

Use `node:test` and `node:assert/strict`. Add malicious fixtures only for
detectors that exist in runtime code, and add benign controls whenever tuning a
heuristic. Each security finding should retain detector, field, pattern/reason,
severity, response, and Threat Event coverage.

## Compatibility

Do not remove or rename a public root/subpath export in 2.x. Mark legacy APIs as
deprecated and keep declarations aligned with runtime. The Admin router's
fail-closed behavior is intentional and must not be relaxed.

## Security reports

Use [SECURITY.md](./SECURITY.md) instead of a public issue for vulnerabilities.
Ordinary false positives can use the false-positive issue form.
