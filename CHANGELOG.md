# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and the project follows Semantic
Versioning for public APIs and documented runtime behavior.

## [Unreleased]

### Added

- Added exact-path NoSQL operator allowlists through
  `nosql.allowedOperators`, configurable scalar header scanning, internal option
  validation, typed advanced subpaths, TypeScript declaration tests, and 75
  benign false-positive controls.
- Added security, contribution, issue, pull-request, testing, deployment,
  architecture, and release guidance.

### Changed

- Made `createParry` and `ParryOptions` the recommended API names while retaining
  every existing public export and the deprecated `Parry_DDoS`/
  `Parry_DDoSOptions` aliases.
- Reordered scanning so Request Shape runs first, structured guards inspect each
  surface once, scalar leaves are serialized once, duplicate findings are
  removed, and aggregate severity uses the most severe finding.
- Resolved trusted proxy chains from right to left and changed generated request
  IDs to `req_${crypto.randomUUID()}`.
- Migrated tests to `node:test`/`node:assert`, ESLint 9 flat configuration, full
  Prettier checks, Node 18/20/22/24 CI, OIDC-only npm publishing, and an optional
  Terraform example under `infra/examples/aws`.
- Updated repository metadata and links to `RobotEby/parry`.

### Security

- **Intentional breaking behavior:** `createParryAdminRouter` no longer permits
  anonymous access by default. It fails during construction unless real auth is
  configured or insecure access is explicitly selected outside production.
- In production, `allowInsecureAdminApi`, `auth.mode: "none"`, and legacy
  `requireAuth: false` are always rejected. Empty tokens and invalid IP/CIDR
  boundaries are rejected, and `verifyJwt: true` continues to fail explicitly.
- Removed stale monitor-only fixtures for Command Injection and SSRF because
  Parry 1.x does not implement those detectors.

## [1.1.1] - 2026-07-02

### Changed

- Published `@roboteby/parry@1.1.1` to the stable `latest` npm dist-tag.

## [1.1.0-rc.1] - 2026-07-02

### Added

- Published the first release candidate under the `rc` npm dist-tag.
- Added route policies, distributed rate limiting, brute-force protection,
  Threat Events, metrics, the read-only Admin API, Docker demonstration, and AWS
  reference infrastructure.

### Security

- Clarified that Parry is application-layer Express middleware and does not
  replace CDN/WAF, load-balancer, or volumetric DDoS controls.
