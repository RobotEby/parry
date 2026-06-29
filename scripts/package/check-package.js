'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const root = path.resolve(__dirname, '..', '..');
const packagePath = path.join(root, 'package.json');
const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));

const REQUIRED_FILES = [
  'README.md',
  'LICENSE',
  'CHANGELOG.md',
  'package.json',
  'src/index.js',
  'types/index.d.ts',
  'config/defaults.js',
  'constants/patterns.js',
];

const FORBIDDEN_PATTERNS = [
  /^tests\//,
  /^scripts\//,
  /^infra\//,
  /^docker\//,
  /^\.github\//,
  /^external\//,
  /^node_modules\//,
  /^coverage\//,
  /^\.nyc_output\//,
  /^docs\//,
  /(^|\/)\.env($|\.)/,
  /(^|\/)[^/]+\.tfvars$/,
  /\.tfstate(\.|$)/,
  /^terraform\.tfvars$/,
  /^tests\/fixtures\/payloads\//,
];

const SECRET_PATTERNS = [
  /AKIA[0-9A-Z]{16}/,
  /(AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*=\s*[^\s]{20,}/,
  /(NPM_TOKEN|NODE_AUTH_TOKEN)\s*=\s*[^\s]{10,}/,
  /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
];

const REQUIRED_PACKAGE_FIELDS = [
  'name',
  'version',
  'description',
  'main',
  'types',
  'license',
  'repository',
  'bugs',
  'homepage',
  'keywords',
  'exports',
  'files',
];

const EXPECTED_DESCRIPTION =
  'Application-layer security middleware for Express.js with injection detection, abuse mitigation, brute-force protection and distributed rate limiting.';

const EXPECTED_REPOSITORY_URL =
  'git+ssh://git@github.com/RobotEby/parry-express-security-middleware.git';

const EXPECTED_BUGS_URL =
  'https://github.com/RobotEby/parry-express-security-middleware/issues';

const EXPECTED_HOMEPAGE =
  'https://github.com/RobotEby/parry-express-security-middleware#readme';

const REQUIRED_KEYWORDS = [
  'express',
  'middleware',
  'security',
  'application-security',
  'appsec',
  'rate-limit',
  'brute-force',
  'xss',
  'sql-injection',
  'nosql-injection',
  'redis',
  'nodejs',
];

function main() {
  const failures = [];

  validatePackageMetadata(failures);
  validatePaths(failures);

  const packedFiles = getPackedFiles();
  validatePackedFiles(packedFiles, failures);
  scanPackedFilesForSecrets(packedFiles, failures);

  if (failures.length > 0) {
    console.error('Package validation failed:');
    for (const failure of failures) console.error(`- ${failure}`);
    process.exit(1);
  }

  console.log(`Package validation passed: ${packedFiles.length} files in npm pack dry-run.`);
}

function validatePackageMetadata(failures) {
  for (const field of REQUIRED_PACKAGE_FIELDS) {
    if (pkg[field] === undefined || pkg[field] === null || pkg[field] === '') {
      failures.push(`package.json is missing required field: ${field}`);
    }
  }

  if (pkg.name !== '@roboteby/parry') {
    failures.push(`package name must be @roboteby/parry, got ${pkg.name}`);
  }

  if (pkg.description !== EXPECTED_DESCRIPTION) {
    failures.push('package.json description must use the official Parry package description');
  }

  if (pkg.publishConfig?.access !== 'public') {
    failures.push('package.json publishConfig.access must be public');
  }

  if (pkg.repository?.url !== EXPECTED_REPOSITORY_URL) {
    failures.push('package.json repository.url must point to parry-express-security-middleware');
  }

  if (pkg.bugs?.url !== EXPECTED_BUGS_URL) {
    failures.push('package.json bugs.url must point to parry-express-security-middleware issues');
  }

  if (pkg.homepage !== EXPECTED_HOMEPAGE) {
    failures.push('package.json homepage must point to parry-express-security-middleware#readme');
  }

  const keywords = Array.isArray(pkg.keywords) ? pkg.keywords : [];
  for (const keyword of REQUIRED_KEYWORDS) {
    if (!keywords.includes(keyword)) {
      failures.push(`package.json keywords must include ${keyword}`);
    }
  }

  if (pkg.dependencies && Object.prototype.hasOwnProperty.call(pkg.dependencies, 'redis')) {
    failures.push('redis must not be a required runtime dependency of the main package');
  }

  const requiredFilesAllowlist = [
    'src',
    'config',
    'constants',
    'types',
    'README.md',
    'LICENSE',
    'CHANGELOG.md',
    'package.json',
  ];
  const files = Array.isArray(pkg.files) ? pkg.files : [];
  for (const entry of requiredFilesAllowlist) {
    if (!files.includes(entry)) failures.push(`package.json files allowlist is missing ${entry}`);
  }

  for (const blocked of ['docs', 'tests', 'scripts', 'infra', 'docker', '.github', 'external']) {
    if (files.includes(blocked) || files.includes(`${blocked}/`)) {
      failures.push(`package.json files allowlist must not include ${blocked}`);
    }
  }
}

function validatePaths(failures) {
  validateExistingRelativePath(pkg.main, 'main', failures);
  validateExistingRelativePath(pkg.types, 'types', failures);

  for (const file of REQUIRED_FILES) {
    validateExistingRelativePath(file, 'required file', failures);
  }

  validateExports(pkg.exports, failures);
}

function validateExports(exportsField, failures, prefix = 'exports') {
  if (typeof exportsField === 'string') {
    validateExistingRelativePath(exportsField, prefix, failures);
    return;
  }

  if (!exportsField || typeof exportsField !== 'object') {
    failures.push('package.json exports must be an object or string');
    return;
  }

  for (const [key, value] of Object.entries(exportsField)) {
    const label = `${prefix}.${key}`;
    if (typeof value === 'string') {
      validateExistingRelativePath(value, label, failures);
    } else if (value && typeof value === 'object') {
      validateExports(value, failures, label);
    } else {
      failures.push(`${label} must resolve to a string path or nested export object`);
    }
  }
}

function validateExistingRelativePath(relativePath, label, failures) {
  if (typeof relativePath !== 'string') {
    failures.push(`${label} must be a string path`);
    return;
  }

  const cleanPath = relativePath.replace(/^\.\//, '');
  const absolutePath = path.join(root, cleanPath);
  if (!absolutePath.startsWith(root) || !fs.existsSync(absolutePath)) {
    failures.push(`${label} points to missing path: ${relativePath}`);
  }
}

function getPackedFiles() {
  const output = execFileSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const report = JSON.parse(output);
  return (report[0] && report[0].files ? report[0].files : []).map((file) => file.path);
}

function validatePackedFiles(files, failures) {
  const fileSet = new Set(files);

  for (const file of REQUIRED_FILES) {
    if (!fileSet.has(file)) failures.push(`npm package is missing required file: ${file}`);
  }

  for (const file of files) {
    if (FORBIDDEN_PATTERNS.some((pattern) => pattern.test(file))) {
      failures.push(`forbidden file included in npm package: ${file}`);
    }
  }
}

function scanPackedFilesForSecrets(files, failures) {
  for (const file of files) {
    const absolutePath = path.join(root, file);
    if (!absolutePath.startsWith(root) || !fs.existsSync(absolutePath)) continue;
    if (fs.statSync(absolutePath).size > 1024 * 1024) continue;

    const content = fs.readFileSync(absolutePath, 'utf8');
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.test(content)) {
        failures.push(`potential secret pattern found in packed file: ${file}`);
      }
    }
  }
}

main();
