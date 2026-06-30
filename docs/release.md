# Release Process

Parry uses manual, reviewable releases controlled by Git tags. The npm publish
workflow runs only for tags that start with `v`, for example `v1.2.3`.

Do not publish directly from a workstation unless the automated release path is
unavailable and the package has been reviewed manually.

## Semantic Versioning

Use Semantic Versioning for public API, defaults, and runtime behavior.

PATCH:

- bug fixes;
- false-positive fixes;
- internal refactors with no public API change;
- documentation and test updates;
- package metadata or CI changes that do not affect runtime behavior.

MINOR:

- new opt-in detector;
- new optional Store adapter;
- new compatible public API;
- new compatible preset;
- new metric or threat event that preserves existing event compatibility.

MAJOR:

- public API changes;
- blocking default changes that can reject requests previously allowed;
- incompatible threat event format changes;
- removal of legacy aliases or subpath exports;
- incompatible Node.js engine changes.

Examples:

```bash
npm version patch
npm version minor
npm version major
npm version prerelease --preid beta
```

## Changelog

Update `CHANGELOG.md` before creating a release tag. Keep the `Unreleased`
section for the next release and move completed entries under a version heading
when cutting a release.

Use these groups when applicable:

- Added
- Changed
- Deprecated
- Removed
- Fixed
- Security

Do not invent historical entries when the history is not reliable.

## Local Release Checklist

```bash
npm ci
npm test
npm run test:fixtures
npm run test:payload-regression
npm run package:check
npm pack --dry-run
GITHUB_REF_NAME=v$(node -p "require('./package.json').version") npm run package:check-tag
npm audit --omit=dev
git diff --check
```

Inspect the tarball before the first publish:

```bash
npm pack
tar -tzf roboteby-parry-*.tgz
```

The tarball must not contain tests, payload fixtures, Terraform, Docker files,
GitHub workflows, external references, `.env` files, Terraform state, or real
`tfvars` files.

## Stable Release

```bash
npm version patch
git push origin main --follow-tags
```

The pushed tag must match `package.json` exactly. `v1.2.3` publishes with npm
dist-tag `latest`.

## Prerelease

```bash
npm version prerelease --preid beta
git push origin main --follow-tags
```

Dist-tag policy:

- `v1.2.3` -> `latest`
- `v1.2.3-beta.1` -> `beta`
- `v1.2.3-alpha.1` -> `next`
- `v1.2.3-rc.1` -> `next`
- `v1.2.3-next.1` -> `next`

## Reverting a Release

Prefer `npm deprecate` over unpublish for published versions, unless npm policy
and the situation clearly justify unpublishing.

Example:

```bash
npm deprecate @roboteby/parry@1.2.3 "Deprecated due to release issue. Upgrade to 1.2.4."
```

## Release Safety Rules

- Do not commit npm tokens, AWS credentials, `.env`, or real `tfvars`.
- Do not publish without `npm run package:check`.
- Do not publish payload fixtures in the npm package.
- Do not change blocking defaults without a major version.
- Do not use release automation that hides version, changelog, and tarball review.

## Future Automation

The project can migrate to `semantic-release` after the public API is more
stable. Releases are currently manual so versioning, changelog updates, and
package contents remain explicit and reviewable.
