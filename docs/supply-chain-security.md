# Supply Chain Security

Parry uses npm Trusted Publishing with GitHub Actions OIDC for package
publication. This avoids long-lived npm tokens in repository secrets.

## Trusted Publishing

Configure the package on npmjs.com with a Trusted Publisher:

- package: `@roboteby/parry`
- repository owner: `RobotEby`
- repository name: `Parry_InjectionAttacks`
- workflow filename: `npm-publish.yml`
- environment: leave empty unless a GitHub Environment is added later

The publish workflow grants:

- `contents: read`
- `id-token: write`

It does not use `NPM_TOKEN` or `NODE_AUTH_TOKEN`.

## Account Controls

Recommended controls:

- enable 2FA on npm accounts with publish rights;
- use Trusted Publishing instead of long-lived automation tokens;
- protect `main` and require CI before merging;
- review and sign release tags when practical;
- review `CHANGELOG.md` and `npm pack --dry-run` before tagging;
- use `npm publish --provenance` from CI;
- keep package `files` allowlist small.

## Tarball Review

Before a first public publish or major release:

```bash
npm run package:check
npm pack
tar -tzf roboteby-parry-*.tgz
```

The tarball should contain only runtime source, typings, package metadata,
README, license, and changelog.

## Secret Hygiene

Never commit:

- npm tokens;
- AWS credentials;
- `.env` files;
- real Terraform `tfvars`;
- Terraform state;
- private keys.

The package validation script blocks common accidental inclusions, but human
review is still required before creating a release tag.

## DDoS Scope

Publishing and supply-chain controls do not change Parry's scope. Parry is
application-layer middleware and does not replace CloudFront, AWS WAF, Shield,
ALB, or other edge protection for volumetric DDoS mitigation.
