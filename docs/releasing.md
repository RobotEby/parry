# Releasing

No release is created merely by merging changes. The package version remains the
source of truth, tags use `v<version>`, and every unreleased change belongs under
`CHANGELOG.md` → `Unreleased` until maintainers deliberately prepare a release.

## Current channels

- `@roboteby/parry@1.1.1` is stable on `latest`.
- `@roboteby/parry@1.1.0-rc.1` remains on `rc`.

The publish workflow maps stable versions to `latest`, `-rc.N` to `rc`, beta to
`beta`, alpha to `alpha`, and next builds to `next`.

## Validation

Run the complete command set in [testing](./testing.md). In particular, validate
the exact tag with:

```bash
GITHUB_REF_NAME=v1.1.1 npm run package:check-tag
```

`package:check` validates repository metadata, npm's files allowlist, exported
paths, required files, forbidden paths, and common secret patterns. Tests load
the actual tarball from a temporary directory.

## npm Trusted Publishing

`.github/workflows/npm-publish.yml` requests `id-token: write` and calls
`npm publish --provenance` without `NPM_TOKEN` or `NODE_AUTH_TOKEN`. The workflow
is intentionally unable to fall back to a long-lived npm token.

Before publishing, an npm package owner must configure a Trusted Publisher for:

- organization/user: `RobotEby`
- repository: `parry`
- workflow: `npm-publish.yml`

That is external npm configuration and cannot be enabled by a repository commit.
Without it, publishing must fail. Do not add a token to make the job pass. See
[npm Trusted Publishers](https://docs.npmjs.com/trusted-publishers/).

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
