'use strict';

/**
 * Fails when version numbers written in the docs drift from package.json.
 *
 * Checked: `@roboteby/parry@X.Y.Z` specs, `GITHUB_REF_NAME=vX.Y.Z` examples and
 * `Parry X.Y.Z` mentions in README.md and Markdown files under docs/, plus the
 * version recorded in package-lock.json. Prerelease specs such as
 * `@roboteby/parry@1.1.0-rc.1` are intentionally ignored (they describe other
 * dist-tags). A missing CHANGELOG section for the current version is reported
 * as a warning only.
 */

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..', '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const pkg = JSON.parse(read('package.json'));
const version = pkg.version;

const PATTERNS = [
  { name: 'npm spec', regex: /@roboteby\/parry@(\d+\.\d+\.\d+)(?![\w.-])/g },
  { name: 'release tag example', regex: /GITHUB_REF_NAME=v(\d+\.\d+\.\d+)(?![\w.-])/g },
  { name: 'Parry version mention', regex: /\bParry (\d+\.\d+\.\d+)(?![\w.-])/g },
];

// Statements that wrap across lines, matched against the whole file.
const MULTILINE_PATTERNS = [
  { name: 'supported version', regex: /At present that\s+is `(\d+\.\d+\.\d+)`/g },
];

const files = ['README.md', 'CONTRIBUTING.md', 'SECURITY.md'];
for (const entry of fs.readdirSync(path.join(root, 'docs'))) {
  if (entry.endsWith('.md')) files.push(`docs/${entry}`);
}

const errors = [];

for (const file of files) {
  if (!fs.existsSync(path.join(root, file))) continue;
  const text = read(file);
  for (const { name, regex } of MULTILINE_PATTERNS) {
    for (const match of text.matchAll(regex)) {
      if (match[1] !== version) {
        errors.push(`${file} ${name} ${match[1]} does not match package.json ${version}`);
      }
    }
  }
  const lines = text.split('\n');
  lines.forEach((line, index) => {
    for (const { name, regex } of PATTERNS) {
      for (const match of line.matchAll(regex)) {
        if (match[1] !== version) {
          errors.push(
            `${file}:${index + 1} ${name} ${match[1]} does not match package.json ${version}`
          );
        }
      }
    }
  });
}

if (fs.existsSync(path.join(root, 'package-lock.json'))) {
  const lock = JSON.parse(read('package-lock.json'));
  const rootEntry = lock.packages && lock.packages[''];
  for (const found of [lock.version, rootEntry && rootEntry.version]) {
    if (found && found !== version) {
      errors.push(`package-lock.json version ${found} does not match package.json ${version}`);
    }
  }
}

if (!new RegExp(`^## \\[${version.replace(/\./g, '\\.')}\\]`, 'm').test(read('CHANGELOG.md'))) {
  console.warn(`Warning: CHANGELOG.md has no "## [${version}]" section.`);
}

if (errors.length > 0) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log(`Documented versions match package.json ${version} (${files.length} files checked).`);
