'use strict';

const pkg = require('../../package.json');

const refName = process.env.GITHUB_REF_NAME || '';
const expectedTag = `v${pkg.version}`;

if (!refName) {
  console.error('GITHUB_REF_NAME is required for package:check-tag.');
  process.exit(1);
}

if (refName !== expectedTag) {
  console.error(`Release tag mismatch: expected ${expectedTag}, got ${refName}.`);
  process.exit(1);
}

if (!/^v\d+\.\d+\.\d+(?:-(?:alpha|beta|rc|next)\.\d+)?$/.test(refName)) {
  console.error(
    `Release tag must be vX.Y.Z or vX.Y.Z-alpha.N, vX.Y.Z-beta.N, vX.Y.Z-rc.N, vX.Y.Z-next.N. Got ${refName}.`
  );
  process.exit(1);
}

console.log(`Release tag ${refName} matches package.json version ${pkg.version}.`);
