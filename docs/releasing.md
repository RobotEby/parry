# Releasing

No release is created merely by merging changes. The package version remains the
source of truth, tags use `v<version>`, and every unreleased change belongs under
`CHANGELOG.md` → `Unreleased` until maintainers deliberately prepare a release.

## Current channels

- `@roboteby/parry@2.0.0` is stable on `latest`.
- `@roboteby/parry@1.1.0-rc.1` remains on `rc`.

The publish workflow maps stable versions to `latest`, `-rc.N` to `rc`, beta to
`beta`, alpha to `alpha`, and next builds to `next`.

## Validation

Run the complete command set in [testing](./testing.md). In particular, validate
the exact tag with:

```bash
GITHUB_REF_NAME=v2.0.0 npm run package:check-tag
```

`package:check` validates repository metadata, npm's files allowlist, exported
paths, required files, forbidden paths, and common secret patterns. Tests load
the actual tarball from a temporary directory.

## npm publishing

`.github/workflows/npm-publish.yml` publishes from GitHub Actions using the
repository secret `NPM_TOKEN`. The secret contains a scoped granular npm access
token and is passed to npm as `NODE_AUTH_TOKEN` only for the authentication check
and publish steps. It must never be committed, printed, or copied into a
versioned file.

Tag pushes validate that `v<version>` matches `package.json`, select the npm
dist-tag, and run:

```bash
npm publish --access public --tag "$NPM_DIST_TAG" --provenance
```

Manual runs require an explicit package version and check out its existing tag
before validation. The workflow retains `id-token: write` and `--provenance` so
GitHub Actions can provide provenance for the published package; npm registry
authentication still uses the repository's granular token.

## Repository settings

The repository contains workflows and Dependabot configuration, but commits
cannot prove or enable host-level GitHub settings. Maintainers should enable:

- branch protection or rulesets requiring the runtime matrix and quality job;
- required review and dismissal of stale approvals for sensitive paths;
- private vulnerability reporting, Dependabot alerts/updates, secret scanning,
  and push protection where the account/plan supports them;
- protected deployment environments and least-privilege OIDC roles for AWS;
- tag/release protections appropriate to the maintainer model.

Review Actions and npm publisher permissions periodically. Supported Action
majors are pinned in workflow files and updated by Dependabot.
