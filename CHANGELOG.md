# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/) for public API and
runtime behavior. The format is based on [Keep a Changelog](https://keepachangelog.com/),
without adding a changelog generation dependency.

## [Unreleased]

## [1.1.0-rc.1] - 2026-07-02

### Added

- Published the first npm release candidate as `@roboteby/parry@1.1.0-rc.1`
  under the `rc` dist-tag.
- Documented the release candidate installation path with
  `npm install @roboteby/parry@rc`.
- Added package hardening, release workflow documentation, and package tarball
  validation scripts.
- Included the current application-layer protection surface: route policies,
  distributed rate limiting, BruteForceGuard, Threat Events, metrics, and the
  read-only Admin API.
- Added documentation for Admin API authentication modes, payload regression
  testing, Docker demo usage, AWS reference infrastructure, and CI/CD.

### Security

- Documented npm publishing and supply-chain hardening with Trusted
  Publishing/OIDC.
- Clarified that Parry is application-layer Express middleware and does not
  replace CloudFront, AWS WAF, Shield, Cloudflare, CDN, ALB, or edge-layer
  volumetric DDoS protection.
