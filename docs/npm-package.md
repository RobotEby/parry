# npm Package Contents

The npm package is intentionally small. Parry is runtime middleware; tests,
Terraform, Docker examples, CI configuration, and curated payload fixtures are
repository assets, not runtime package assets.

## Package Name

The package is prepared for publication as:

```text
@roboteby/parry
```

The legacy `Parry_DDoS` function remains exported for compatibility, but the npm
package name should describe the project as application-layer Express security,
not complete volumetric DDoS protection.

## Included

The `files` allowlist in `package.json` includes:

- `src`
- `config`
- `constants`
- `types`
- `README.md`
- `LICENSE`
- `CHANGELOG.md`
- `package.json`

## Excluded

The package must not include:

- `tests`
- payload fixtures
- `scripts`
- `infra`
- `docker`
- `.github`
- `external`
- `docs`
- `node_modules`
- `coverage`
- `.env`
- Terraform state or real `tfvars`

Run:

```bash
npm run package:check
npm pack --dry-run
```

## Testing a Local Tarball

```bash
npm pack
mkdir /tmp/parry-install-test
cd /tmp/parry-install-test
npm init -y
npm install /path/to/parry-express-security-middleware/roboteby-parry-*.tgz express
node -e "const { Parry_DDoS, MemoryStore } = require('@roboteby/parry'); console.log(typeof Parry_DDoS, typeof MemoryStore)"
```

## Public API

Stable root exports include:

- `Parry_DDoS`
- `createParry`
- `createParryAdminRouter`
- `MemoryStore`
- `RedisStore`

Existing subpath exports are kept for compatibility in this release:

- `@roboteby/parry/core`
- `@roboteby/parry/detectors`
- `@roboteby/parry/stores`
- `@roboteby/parry/policies`
- `@roboteby/parry/brute-force`
- `@roboteby/parry/events`
- `@roboteby/parry/observability`
- `@roboteby/parry/admin`

Do not depend on unlisted deep internal paths. If a future major release narrows
exports, it should first document deprecations and migration paths.

## Redis Policy

MemoryStore is the default. RedisStore is available for distributed
application-layer rate limiting and brute force counters, but the main package
does not install Redis for you.

Applications that need Redis should install and create their own Redis client,
then pass it to `RedisStore`.
