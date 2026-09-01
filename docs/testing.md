# Testing

The repository uses the built-in `node:test` runner and `node:assert/strict`.
Unit, integration, package, and payload-regression suites do not use custom
pass/fail aggregators.

## Local checks

From a clean checkout, run:

```text
npm ci
npm run lint
npm run format:check
npm test
npm run test:unit
npm run test:integration
npm run test:types
npm run test:fixtures
npm run test:payload-regression
npm run package:check
npm run package:dry-run
npm audit --omit=dev
GITHUB_REF_NAME=v2.0.0 npm run package:check-tag
docker build -f docker/demo-api/Dockerfile -t parry-demo-api .
docker compose config
terraform fmt -check -recursive infra/examples/aws
terraform -chdir=infra/examples/aws/environments/dev init -backend=false
terraform -chdir=infra/examples/aws/environments/dev validate
git diff --check
```

`test:integ` remains an alias for `test:integration`.

## Runtime matrix

CI installs with `npm ci` and runs `npm test` on Node 22 and 24, matching the
package's Node `>=22` requirement.

The package peer dependency and test environment use Express 5.2.1.

## Payload fixtures

Fixtures are small local defensive examples. They are neither executed against
external systems nor included in the npm package. The suite covers only detector
categories actually implemented by Parry. The generated report is
[payload-regression-report.md](./payload-regression-report.md).

Every malicious fixture is exercised through its direct detector and the full
middleware. Regression assertions cover blocking, detector, field, reason,
severity, structured event, and sensitive-data redaction. At least 75 benign
controls cover prose, snippets, Markdown, placeholders, JSON, URLs, safe HTML,
Unicode, frontend syntax, arrays, paths, and exact-path NoSQL allowlists.

To change fixtures:

1. Add a unique ID and provenance category.
2. Define the expected block state, detector, severity, and intended mode.
3. Update the exact expected count in `scripts/payloads/fixture-utils.js`.
4. Run `npm run test:fixtures`, `npm run test:payload-regression`, and
   `npm run test:payload-report`.

Do not add “monitor-only” payload categories for detectors the runtime does not
implement.

## Package tests

Package tests validate root and advanced subpath exports, their type maps, npm's
files allowlist, and removed internal files. They also build a real tarball,
unpack it into a temporary directory, and require the root and a subpath from
that isolated location.
