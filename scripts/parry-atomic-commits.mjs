#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import readline from 'node:readline/promises';

const ALLOWED_TYPES = new Set([
  'feat',
  'fix',
  'chore',
  'refactor',
  'style',
  'docs',
  'test',
  'build',
  'ci',
  'perf',
  'revert',
]);

const GENERATED_SEGMENTS = new Set([
  '.cache',
  '.git',
  '.turbo',
  '.vscode-test',
  'build',
  'coverage',
  'dist',
  'logs',
  'node_modules',
  'temp',
  'test-results',
  'tmp',
]);

const GENERATED_BASENAMES = new Set(['npm-debug.log', 'pnpm-debug.log', 'yarn-error.log']);

const CONFIG_FILES = new Set([
  '.dockerignore',
  '.editorconfig',
  '.eslintignore',
  '.eslintrc',
  '.eslintrc.cjs',
  '.eslintrc.js',
  '.gitignore',
  '.npmrc',
  '.prettierignore',
  '.prettierrc',
  '.prettierrc.cjs',
  '.prettierrc.js',
  '.prettierrc.json',
  'eslint.config.js',
  'eslint.config.mjs',
  'package-lock.json',
  'package.json',
  'pnpm-lock.yaml',
  'prettier.config.js',
  'yarn.lock',
]);

const ENV_ALLOWLIST = new Set([
  '.env.example',
  '.env.local.example',
  '.env.production.example',
  '.env.staging.example',
  '.env.test.example',
]);

const DATABASE_EXTENSIONS = new Set(['.sqlite', '.sqlite3', '.db', '.dump', '.backup', '.bak']);

const SECRET_ASSIGNMENT =
  /^\s*(?:export\s+)?([A-Z0-9_.-]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|DATABASE_URL|DB_URL|JWT[A-Z0-9_.-]*SECRET)[A-Z0-9_.-]*)\s*[:=]\s*("?[^"#\n]+"?|'\S+'|\S+)/i;

const SECRET_PATTERNS = [
  { name: 'private key block', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: 'AWS access key', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', pattern: /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/ },
  { name: 'Slack token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/ },
  {
    name: 'JWT token',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  },
];

const PARRY_DOMAINS = [
  {
    test: (filePath) => filePath.startsWith('src/detectors/') || filePath.startsWith('constants/'),
    label: 'attack detector',
    area: 'injection detection',
    capability:
      'detect SQL, NoSQL, XSS, and suspicious payloads before they reach application handlers',
  },
  {
    test: (filePath) => filePath.startsWith('src/core/') || filePath === 'src/core/index.js',
    label: 'security engine',
    area: 'core threat analysis',
    capability:
      'score suspicious requests and convert detector findings into actionable security decisions',
  },
  {
    test: (filePath) =>
      filePath.startsWith('src/rate-limit/') ||
      filePath.toLowerCase().includes('ratelimit') ||
      filePath.toLowerCase().includes('rate-limit') ||
      filePath.toLowerCase().includes('ddos'),
    label: 'rate limiter',
    area: 'abuse throttling',
    capability: 'reduce brute-force, request flooding, and DDoS-like pressure at application level',
  },
  {
    test: (filePath) => filePath.startsWith('src/middleware/'),
    label: 'Parry middleware',
    area: 'middleware protection layer',
    capability: 'apply Parry protections consistently in the HTTP request lifecycle',
  },
  {
    test: (filePath) => filePath.startsWith('src/express/') || filePath.startsWith('examples/'),
    label: 'Express integration',
    area: 'Express adapter',
    capability:
      'integrate Parry with Express applications through safe request and response handling',
  },
  {
    test: (filePath) => filePath.startsWith('src/stores/'),
    label: 'state store',
    area: 'runtime storage',
    capability:
      'keep runtime counters and mitigation state isolated behind replaceable storage adapters',
  },
  {
    test: (filePath) => filePath.startsWith('src/utils/'),
    label: 'utility layer',
    area: 'payload normalization',
    capability: 'normalize, decode, flatten, and prepare request data before security analysis',
  },
  {
    test: (filePath) => filePath.startsWith('src/logger/') || filePath.includes('/logger'),
    label: 'security logger',
    area: 'observability',
    capability:
      'report blocked requests, threat events, and middleware decisions in a structured way',
  },
  {
    test: (filePath) => filePath.startsWith('types/'),
    label: 'public types',
    area: 'developer experience',
    capability: 'document and stabilize the public API surface for TypeScript consumers',
  },
  {
    test: (filePath) => filePath.startsWith('tests/') || filePath.startsWith('test/'),
    label: 'test suite',
    area: 'quality assurance',
    capability: 'validate detectors, middleware behavior, abuse controls, and regression scenarios',
  },
  {
    test: (filePath) =>
      filePath.startsWith('docs/') || path.posix.basename(filePath).toLowerCase() === 'readme.md',
    label: 'documentation',
    area: 'project documentation',
    capability: 'explain Parry architecture, usage, limitations, and security behavior',
  },
  {
    test: (filePath) => filePath.startsWith('config/'),
    label: 'default configuration',
    area: 'configuration',
    capability: 'centralize defaults and safer runtime options for Parry protection rules',
  },
  {
    test: (filePath) => filePath.startsWith('scripts/'),
    label: 'automation script',
    area: 'developer workflow',
    capability: 'automate repeatable maintenance tasks without mixing unrelated changes',
  },
];

const ACTION_BY_STATUS = {
  added: 'adds',
  modified: 'updates',
  deleted: 'removes',
  renamed: 'renames',
};

const args = parseArgs(process.argv.slice(2));
const originalCwd = process.cwd();

main().catch((error) => {
  console.error(`\n[parry-atomic] Fatal error: ${error.message}`);
  process.exitCode = 1;
});

async function main() {
  const repoRoot = getRepoRoot();
  const repoName = path.basename(repoRoot);
  const headAtStart = hasHead(repoRoot);

  const rawStatus = git(repoRoot, ['status', '--porcelain=v1', '-z']).stdout;
  const statusEntries = parsePorcelainStatus(rawStatus);
  const expandedItems = expandStatusEntries(repoRoot, statusEntries);
  const plan = buildProcessingPlan(repoRoot, expandedItems, headAtStart, args);

  printHeader({
    repoName,
    repoRoot,
    currentDir: originalCwd,
    headExists: headAtStart,
    dryRun: args.dryRun,
    autoYes: args.yes,
    language: args.language,
    detectedEntries: statusEntries.length,
    detectedFiles: expandedItems.length,
    processCount: plan.items.length,
    ignoredCount: plan.ignored.length,
  });

  if (plan.ignored.length > 0) {
    console.log('\nIgnored files:');
    for (const ignored of plan.ignored) {
      console.log(`  - ${ignored.path} (${ignored.reason})`);
    }
  }

  if (plan.items.length === 0) {
    console.log('\nNo processable files found.');
    return;
  }

  const summary = {
    committed: 0,
    dryRun: 0,
    ignored: plan.ignored.length,
    skipped: 0,
    errors: 0,
  };

  const usedSubjects = new Set();

  const rl =
    args.yes || args.dryRun
      ? null
      : readline.createInterface({
          input: process.stdin,
          output: process.stdout,
        });

  try {
    if (!args.dryRun) {
      clearStaging(repoRoot);
    }

    for (const item of plan.items) {
      const generatedCommit = ensureUniqueCommit(
        generateCommit(repoRoot, item, headAtStart, args),
        item,
        usedSubjects
      );

      item.commit = generatedCommit;

      printItem(item, generatedCommit);

      if (args.dryRun) {
        console.log('  Result: dry-run, no commit created');
        summary.dryRun += 1;
        continue;
      }

      const decision = args.yes
        ? { action: 'commit', commit: generatedCommit }
        : await promptForDecision(rl, generatedCommit);

      if (decision.action === 'quit') {
        console.log('  Result: stopped by user');
        break;
      }

      if (decision.action === 'skip') {
        console.log('  Result: skipped by user');
        summary.skipped += 1;
        continue;
      }

      const validationError = validateSubject(decision.commit.subject);

      if (validationError) {
        console.log(`  Result: skipped invalid subject (${validationError})`);
        summary.skipped += 1;
        continue;
      }

      try {
        clearStaging(repoRoot);
        stageItem(repoRoot, item);
        assertOnlyCurrentItemStaged(repoRoot, item);

        if (!hasStagedChanges(repoRoot)) {
          console.log('  Result: skipped because staging produced no changes');
          summary.skipped += 1;
          continue;
        }

        git(repoRoot, ['commit', '-m', decision.commit.subject, '-m', decision.commit.body]);

        console.log('  Result: committed');
        summary.committed += 1;
      } catch (error) {
        console.log(`  Result: error (${error.message})`);
        summary.errors += 1;
      } finally {
        clearStaging(repoRoot);
      }
    }
  } finally {
    if (rl) {
      rl.close();
    }

    if (!args.dryRun) {
      clearStaging(repoRoot);
    }
  }

  printSummary(summary);

  if (summary.errors > 0) {
    process.exitCode = 1;
  }
}

function parseArgs(argv) {
  const options = {
    dryRun: false,
    includeDeleted: false,
    includeEnv: false,
    language: 'en',
    yes: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === '--dry-run') {
      options.dryRun = true;
    } else if (arg === '--include-deleted') {
      options.includeDeleted = true;
    } else if (arg === '--include-env') {
      options.includeEnv = true;
    } else if (arg === '--yes' || arg === '-y') {
      options.yes = true;
    } else if (arg === '--pt-br') {
      options.language = 'pt-br';
    } else if (arg === '--en') {
      options.language = 'en';
    } else if (arg === '--language') {
      const value = argv[index + 1];

      if (!['en', 'pt-br'].includes(value)) {
        throw new Error('--language must be "en" or "pt-br"');
      }

      options.language = value;
      index += 1;
    } else if (arg === '--help' || arg === '-h') {
      printUsage();
      process.exit(0);
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }

  return options;
}

function printUsage() {
  console.log(`Usage: node scripts/parry-atomic-commits.mjs [options]

Creates one atomic Git commit per changed file in the current repository.
Each commit receives a Conventional Commit subject and a complete bullet-list body.

Options:
  --yes, -y           Accept generated commits automatically
  --dry-run          Show the commit plan without staging or committing
  --include-env      Allow .env files to be considered
  --include-deleted  Allow deleted files to be committed
  --pt-br            Generate commit body text in Portuguese
  --en               Generate commit body text in English
  --language VALUE   Use "en" or "pt-br"
  --help, -h         Show this help message

Recommended flow:
  node scripts/parry-atomic-commits.mjs --dry-run
  node scripts/parry-atomic-commits.mjs
  node scripts/parry-atomic-commits.mjs --yes`);
}

function getRepoRoot() {
  const result = run('git', ['rev-parse', '--show-toplevel'], {
    cwd: originalCwd,
  });

  return result.stdout.trim();
}

function hasHead(repoRoot) {
  return (
    git(repoRoot, ['rev-parse', '--verify', 'HEAD'], {
      allowFailure: true,
    }).status === 0
  );
}

function git(repoRoot, gitArgs, options = {}) {
  return run('git', gitArgs, {
    cwd: repoRoot,
    ...options,
  });
}

function run(command, commandArgs, options = {}) {
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  if (result.error) {
    throw result.error;
  }

  if (!options.allowFailure && result.status !== 0) {
    const stderr = (result.stderr || '').trim();
    const stdout = (result.stdout || '').trim();
    const detail = stderr || stdout || `exit code ${result.status}`;

    throw new Error(`${command} ${commandArgs.join(' ')} failed: ${detail}`);
  }

  return {
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    status: result.status ?? 0,
  };
}

function parsePorcelainStatus(rawStatus) {
  if (!rawStatus) {
    return [];
  }

  const tokens = rawStatus.split('\0');

  if (tokens[tokens.length - 1] === '') {
    tokens.pop();
  }

  const entries = [];

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];

    if (!token || token.length < 4) {
      continue;
    }

    const status = token.slice(0, 2);
    const filePath = normalizePath(token.slice(3));
    const isRename = status.includes('R') || status.includes('C');

    if (isRename) {
      const oldPath = normalizePath(tokens[index + 1] || '');
      index += 1;

      entries.push({
        path: filePath,
        oldPath,
        status,
        statusLabel: `${status} ${oldPath} -> ${filePath}`,
        type: 'rename',
      });
    } else {
      entries.push({
        path: filePath,
        oldPath: null,
        status,
        statusLabel: `${status} ${filePath}`,
        type: 'file',
      });
    }
  }

  return entries;
}

function expandStatusEntries(repoRoot, entries) {
  const expanded = [];
  const seen = new Set();

  for (const entry of entries) {
    if (entry.type === 'rename') {
      addExpandedItem(expanded, seen, entry);
      continue;
    }

    const absolutePath = path.join(repoRoot, entry.path);

    if (entry.status === '??' && isDirectory(absolutePath)) {
      const files = listFilesRecursively(absolutePath, repoRoot);

      for (const filePath of files) {
        addExpandedItem(expanded, seen, {
          ...entry,
          path: filePath,
          statusLabel: `${entry.status} ${filePath}`,
        });
      }

      continue;
    }

    addExpandedItem(expanded, seen, entry);
  }

  return expanded.sort((a, b) => a.path.localeCompare(b.path));
}

function addExpandedItem(expanded, seen, entry) {
  const key =
    entry.type === 'rename'
      ? `rename:${entry.oldPath}->${entry.path}`
      : `${entry.status}:${entry.path}`;

  if (seen.has(key)) {
    return;
  }

  seen.add(key);

  expanded.push({
    ...entry,
    paths: entry.type === 'rename' ? [entry.oldPath, entry.path].filter(Boolean) : [entry.path],
  });
}

function listFilesRecursively(absoluteDir, repoRoot) {
  const files = [];
  const entries = fs.readdirSync(absoluteDir, {
    withFileTypes: true,
  });

  for (const entry of entries) {
    const absolutePath = path.join(absoluteDir, entry.name);
    const relativePath = normalizePath(path.relative(repoRoot, absolutePath));

    if (entry.isDirectory()) {
      if (!GENERATED_SEGMENTS.has(entry.name)) {
        files.push(...listFilesRecursively(absolutePath, repoRoot));
      }

      continue;
    }

    if (entry.isFile() || entry.isSymbolicLink()) {
      files.push(relativePath);
    }
  }

  return files.sort((a, b) => a.localeCompare(b));
}

function buildProcessingPlan(repoRoot, items, headExists, options) {
  const ignored = [];
  const processable = [];

  for (const item of items) {
    const ignoreReason = getIgnoreReason(repoRoot, item, options);

    if (ignoreReason) {
      ignored.push({
        path: item.path,
        reason: ignoreReason,
      });

      continue;
    }

    const secretReason = getSecretReason(repoRoot, item);

    if (secretReason) {
      ignored.push({
        path: item.path,
        reason: secretReason,
      });

      continue;
    }

    processable.push({
      ...item,
      existsInWorkingTree: fs.existsSync(path.join(repoRoot, item.path)),
      headExists,
    });
  }

  return {
    ignored,
    items: processable,
  };
}

function getIgnoreReason(repoRoot, item, options) {
  const paths = item.paths.length > 0 ? item.paths : [item.path];

  for (const filePath of paths) {
    const normalized = normalizePath(filePath);
    const baseName = path.posix.basename(normalized);
    const lowerBaseName = baseName.toLowerCase();
    const segments = normalized.split('/').filter(Boolean);

    if (segments.some((segment) => GENERATED_SEGMENTS.has(segment))) {
      return 'ignored generated or local-only directory';
    }

    if (GENERATED_BASENAMES.has(lowerBaseName) || lowerBaseName.endsWith('.log')) {
      return 'ignored log file';
    }

    if (DATABASE_EXTENSIONS.has(path.posix.extname(lowerBaseName))) {
      return 'ignored local database, dump, or backup file';
    }

    if (isEnvFile(normalized) && !options.includeEnv) {
      return 'ignored environment file';
    }
  }

  if (isDeletedItem(item) && !options.includeDeleted) {
    return 'deleted file requires --include-deleted';
  }

  if (isUnmergedItem(item)) {
    return 'unmerged Git status requires manual resolution';
  }

  for (const filePath of paths) {
    const absolutePath = path.join(repoRoot, filePath);

    if (fs.existsSync(absolutePath) && fs.statSync(absolutePath).isDirectory()) {
      return 'directory status could not be expanded to files';
    }
  }

  return null;
}

function isEnvFile(filePath) {
  const baseName = path.posix.basename(filePath);
  return (baseName === '.env' || baseName.startsWith('.env.')) && !ENV_ALLOWLIST.has(baseName);
}

function isDeletedItem(item) {
  return item.type !== 'rename' && item.status.includes('D');
}

function isUnmergedItem(item) {
  return ['DD', 'AU', 'UD', 'UA', 'DU', 'AA', 'UU'].includes(item.status);
}

function getSecretReason(repoRoot, item) {
  if (isDeletedItem(item)) {
    return null;
  }

  const pathsToScan = item.type === 'rename' ? [item.path] : item.paths;

  for (const filePath of pathsToScan) {
    const absolutePath = path.join(repoRoot, filePath);

    if (!fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isFile()) {
      continue;
    }

    const content = readTextFileSafe(absolutePath);

    if (content === null) {
      continue;
    }

    const secretMatch = findSecret(content);

    if (secretMatch) {
      return `possible secret detected: ${secretMatch}`;
    }
  }

  return null;
}

function readTextFileSafe(absolutePath) {
  const buffer = fs.readFileSync(absolutePath);

  if (buffer.includes(0)) {
    return null;
  }

  return buffer.toString('utf8');
}

function findSecret(content) {
  for (const { name, pattern } of SECRET_PATTERNS) {
    if (pattern.test(content)) {
      return name;
    }
  }

  const lines = content.split(/\r?\n/);

  for (const line of lines) {
    const match = line.match(SECRET_ASSIGNMENT);

    if (!match) {
      continue;
    }

    const value = stripQuotes(match[2].trim());

    if (isLikelySecretValue(value)) {
      return `credential assignment for ${match[1]}`;
    }
  }

  return null;
}

function stripQuotes(value) {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }

  return value;
}

function isLikelySecretValue(value) {
  const normalized = value.trim();
  const lower = normalized.toLowerCase();

  if (!normalized || normalized.length < 16) {
    return false;
  }

  if (
    lower.includes('example') ||
    lower.includes('placeholder') ||
    lower.includes('changeme') ||
    lower.includes('change-me') ||
    lower.includes('your_') ||
    lower.includes('your-') ||
    lower.includes('localhost') ||
    lower.includes('127.0.0.1') ||
    lower.startsWith('dev-') ||
    lower.startsWith('test-') ||
    lower.startsWith('process.env')
  ) {
    return false;
  }

  if (
    /^[A-Za-z0-9_./+=:-]{24,}$/.test(normalized) &&
    /[A-Za-z]/.test(normalized) &&
    /[0-9]/.test(normalized)
  ) {
    return true;
  }

  return /^postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@/i.test(normalized) && !lower.includes('localhost');
}

function generateCommit(repoRoot, item, headExistsAtStart, options) {
  const filePath = item.path;
  const diff = getDiffText(repoRoot, item);
  const lowerDiff = diff.toLowerCase();
  const lowerPath = filePath.toLowerCase();
  const lowerFileName = path.posix.basename(filePath).toLowerCase();
  const statusKind = getStatusKind(item, headExistsAtStart);
  const domain = getParryDomain(filePath);
  const role = getFileRole(filePath);

  let type = inferCommitType({
    filePath,
    lowerPath,
    lowerFileName,
    lowerDiff,
    statusKind,
    domain,
    role,
    item,
  });

  let subject = inferSubject({
    filePath,
    lowerPath,
    lowerFileName,
    lowerDiff,
    statusKind,
    domain,
    role,
    type,
    item,
  });

  let subjectLine = normalizeSubject(`${type}: ${subject}`);
  const validationError = validateSubject(subjectLine);

  if (validationError) {
    type = fallbackTypeForPath(lowerPath);
    subject = fallbackSubjectForPath(filePath, domain, role, type, statusKind);
    subjectLine = normalizeSubject(`${type}: ${subject}`);
  }

  return {
    subject: subjectLine,
    body: buildCommitBody({
      filePath,
      statusKind,
      domain,
      role,
      type,
      lowerDiff,
      diff,
      language: options.language,
    }),
  };
}

function getDiffText(repoRoot, item) {
  const paths = item.paths.length > 0 ? item.paths : [item.path];
  const chunks = [];

  for (const filePath of paths) {
    const worktreeDiff = git(repoRoot, ['diff', '--', filePath], {
      allowFailure: true,
    }).stdout;

    const cachedDiff = git(repoRoot, ['diff', '--cached', '--', filePath], {
      allowFailure: true,
    }).stdout;

    chunks.push(worktreeDiff, cachedDiff);

    const absolutePath = path.join(repoRoot, filePath);

    if (fs.existsSync(absolutePath) && fs.statSync(absolutePath).isFile()) {
      const content = readTextFileSafe(absolutePath);

      if (content) {
        chunks.push(content);
      }
    }
  }

  return chunks.filter(Boolean).join('\n');
}

function inferCommitType(context) {
  const { filePath, lowerPath, lowerFileName, lowerDiff, statusKind, role, item } = context;

  if (statusKind !== 'added' && lowerDiff.includes('this reverts commit')) {
    return 'revert';
  }

  if (isTestPath(lowerPath, lowerFileName)) {
    return 'test';
  }

  if (isDocsPath(lowerPath, lowerFileName)) {
    return 'docs';
  }

  if (lowerPath.startsWith('.github/')) {
    return 'ci';
  }

  if (isBuildPath(lowerPath, lowerFileName)) {
    return lowerPath.startsWith('.github/') ? 'ci' : 'build';
  }

  if (isConfigPath(lowerPath, lowerFileName)) {
    return 'chore';
  }

  if (filePath.startsWith('scripts/')) {
    return lowerPath.includes('deploy') || lowerPath.includes('docker') ? 'build' : 'chore';
  }

  if (
    lowerPath.includes('rate') ||
    lowerPath.includes('ddos') ||
    lowerPath.includes('bruteforce')
  ) {
    if (hasFixSignals(lowerDiff)) {
      return 'fix';
    }

    if (hasPerformanceSignals(lowerDiff, lowerPath)) {
      return 'perf';
    }

    return statusKind === 'added' ? 'feat' : 'refactor';
  }

  if (
    role === 'detector' ||
    lowerPath.includes('detector') ||
    lowerPath.includes('sql') ||
    lowerPath.includes('nosql') ||
    lowerPath.includes('xss')
  ) {
    if (hasFixSignals(lowerDiff)) {
      return 'fix';
    }

    return statusKind === 'added' ? 'feat' : 'refactor';
  }

  if (role === 'middleware' || hasEndpointSignals(lowerDiff)) {
    if (hasFixSignals(lowerDiff)) {
      return 'fix';
    }

    return statusKind === 'added' ? 'feat' : 'refactor';
  }

  if (hasPerformanceSignals(lowerDiff, lowerPath)) {
    return 'perf';
  }

  if (hasFixSignals(lowerDiff)) {
    return 'fix';
  }

  if (item.type === 'rename') {
    return 'refactor';
  }

  if (lowerPath.startsWith('src/')) {
    return statusKind === 'added' ? 'feat' : 'refactor';
  }

  return statusKind === 'added' ? 'feat' : 'chore';
}

function inferSubject(context) {
  const { filePath, lowerPath, lowerFileName, lowerDiff, statusKind, domain, role, type, item } =
    context;

  if (type === 'revert') {
    return `revert ${domain.label} changes`;
  }

  if (item.type === 'rename') {
    return `rename ${domain.label} file`;
  }

  if (type === 'test') {
    if (lowerPath.includes('rate') || lowerPath.includes('ddos')) {
      return 'add abuse mitigation tests';
    }

    if (lowerPath.includes('sql')) {
      return 'add SQL injection detector tests';
    }

    if (lowerPath.includes('nosql')) {
      return 'add NoSQL injection detector tests';
    }

    if (lowerPath.includes('xss')) {
      return 'add XSS detector tests';
    }

    if (lowerPath.includes('middleware')) {
      return 'add middleware protection tests';
    }

    return `add ${domain.label} tests`;
  }

  if (type === 'docs') {
    if (lowerFileName === 'readme.md') {
      return 'update Parry README';
    }

    if (lowerPath.startsWith('examples/')) {
      return 'document Express usage example';
    }

    if (lowerPath.includes('aws') || lowerPath.includes('cloud')) {
      return 'document cloud deployment strategy';
    }

    if (lowerPath.includes('ddos') || lowerPath.includes('rate')) {
      return 'document abuse mitigation strategy';
    }

    return `document ${domain.area}`;
  }

  if (type === 'ci') {
    return 'update project validation workflow';
  }

  if (type === 'build') {
    if (lowerPath.includes('docker')) {
      return 'update Docker build configuration';
    }

    if (lowerPath.includes('package-lock')) {
      return 'update package lockfile';
    }

    return 'update project build configuration';
  }

  if (lowerPath === 'package.json') {
    return 'update project package scripts';
  }

  if (lowerPath === '.gitignore') {
    return 'update repository ignore rules';
  }

  if (lowerPath.includes('rate') || lowerPath.includes('ddos')) {
    if (type === 'feat') {
      return 'add application abuse mitigation controls';
    }

    if (type === 'fix') {
      return 'correct abuse mitigation behavior';
    }

    if (type === 'perf') {
      return 'optimize request throttling path';
    }

    return 'reorganize abuse mitigation controls';
  }

  if (lowerPath.includes('bruteforce') || lowerDiff.includes('brute')) {
    if (type === 'feat') {
      return 'add brute-force protection flow';
    }

    if (type === 'fix') {
      return 'correct brute-force protection behavior';
    }

    return 'reorganize brute-force protection flow';
  }

  if (lowerPath.includes('sql')) {
    return type === 'fix'
      ? 'correct SQL injection detection'
      : `${statusKind === 'added' ? 'add' : 'update'} SQL injection detector`;
  }

  if (lowerPath.includes('nosql')) {
    return type === 'fix'
      ? 'correct NoSQL injection detection'
      : `${statusKind === 'added' ? 'add' : 'update'} NoSQL injection detector`;
  }

  if (lowerPath.includes('xss')) {
    return type === 'fix'
      ? 'correct XSS detection'
      : `${statusKind === 'added' ? 'add' : 'update'} XSS detector`;
  }

  if (role === 'middleware') {
    return type === 'fix'
      ? 'correct middleware protection flow'
      : `${statusKind === 'added' ? 'add' : 'update'} middleware protection flow`;
  }

  if (role === 'detector') {
    return type === 'fix'
      ? `correct ${domain.label} behavior`
      : `${statusKind === 'added' ? 'add' : 'update'} ${domain.label}`;
  }

  if (role === 'store') {
    return type === 'fix'
      ? 'correct runtime store behavior'
      : `${statusKind === 'added' ? 'add' : 'update'} runtime store adapter`;
  }

  if (role === 'logger') {
    return type === 'fix'
      ? 'correct security logging behavior'
      : `${statusKind === 'added' ? 'add' : 'update'} security logging`;
  }

  if (role === 'entrypoint') {
    return `${statusKind === 'added' ? 'add' : 'update'} public package entrypoint`;
  }

  return fallbackSubjectForPath(filePath, domain, role, type, statusKind);
}

function fallbackSubjectForPath(filePath, domain, role, type, statusKind) {
  const readableFile = humanizeFileName(path.posix.basename(filePath));
  const action =
    statusKind === 'added'
      ? 'add'
      : statusKind === 'deleted'
        ? 'remove'
        : statusKind === 'renamed'
          ? 'rename'
          : 'update';

  if (type === 'feat') {
    return `${action} ${domain.label} capability`;
  }

  if (type === 'fix') {
    return `correct ${domain.label} behavior`;
  }

  if (type === 'refactor') {
    return `reorganize ${domain.label}`;
  }

  if (type === 'perf') {
    return `optimize ${domain.label}`;
  }

  if (type === 'chore') {
    return `${action} ${readableFile}`;
  }

  return `${action} ${domain.label}`;
}

function buildCommitBody(context) {
  return context.language === 'pt-br' ? buildPortugueseBody(context) : buildEnglishBody(context);
}

function buildEnglishBody({ filePath, statusKind, domain, role, type, lowerDiff, diff }) {
  const action = ACTION_BY_STATUS[statusKind] || 'updates';
  const highlights = inferHighlights({ lowerDiff, diff, type, domain, role });

  return [
    'Description:',
    `- ${capitalize(action)} ${filePath} as an isolated atomic change.`,
    `- Keeps the commit focused on the ${domain.area} area of Parry.`,
    `- Supports the ${domain.label} responsibility: ${domain.capability}.`,
    `- Classifies the change as ${type} to keep the repository history readable.`,
    ...highlights.map((item) => `- ${item}`),
    '',
    'Impact:',
    `- Makes future reviews easier because this commit only stages ${filePath}.`,
    '- Reduces the risk of mixing unrelated middleware, detector, configuration, or test changes.',
    '- Preserves a clean Git history for security-focused evolution of Parry_InjectionAttacks.',
  ].join('\n');
}

function buildPortugueseBody({ filePath, statusKind, domain, role, type, lowerDiff, diff }) {
  const actionByStatus = {
    added: 'Adiciona',
    modified: 'Atualiza',
    deleted: 'Remove',
    renamed: 'Renomeia',
  };

  const action = actionByStatus[statusKind] || 'Atualiza';
  const highlights = inferHighlights({ lowerDiff, diff, type, domain, role });

  return [
    'Descrição:',
    `- ${action} ${filePath} como uma alteração atômica e isolada.`,
    `- Mantém o commit focado na área de ${domain.area} do Parry.`,
    `- Reforça a responsabilidade de ${domain.label}: ${domain.capability}.`,
    `- Classifica a alteração como ${type} para manter o histórico legível.`,
    ...highlights.map((item) => `- ${translateHighlight(item)}`),
    '',
    'Impacto:',
    `- Facilita revisões futuras porque este commit versiona apenas ${filePath}.`,
    '- Reduz o risco de misturar alterações não relacionadas de middleware, detectores, configuração ou testes.',
    '- Preserva um histórico limpo para a evolução de segurança do Parry_InjectionAttacks.',
  ].join('\n');
}

function inferHighlights({ lowerDiff, type, domain, role }) {
  const highlights = [];

  if (lowerDiff.includes('rate') || lowerDiff.includes('limit') || lowerDiff.includes('bucket')) {
    highlights.push('Improves request throttling and abuse-control behavior.');
  }

  if (lowerDiff.includes('ddos') || lowerDiff.includes('flood')) {
    highlights.push('Adds context for DDoS-oriented mitigation at the application layer.');
  }

  if (lowerDiff.includes('brute') || lowerDiff.includes('login')) {
    highlights.push('Strengthens brute-force mitigation and repeated-attempt handling.');
  }

  if (lowerDiff.includes('sql')) {
    highlights.push('Improves SQL injection detection coverage.');
  }

  if (lowerDiff.includes('nosql')) {
    highlights.push('Improves NoSQL injection detection coverage.');
  }

  if (lowerDiff.includes('xss') || lowerDiff.includes('script')) {
    highlights.push('Improves XSS payload detection coverage.');
  }

  if (
    lowerDiff.includes('sanitize') ||
    lowerDiff.includes('normalize') ||
    lowerDiff.includes('decode') ||
    lowerDiff.includes('escape')
  ) {
    highlights.push('Improves payload normalization before threat analysis.');
  }

  if (lowerDiff.includes('test') || role === 'test' || type === 'test') {
    highlights.push('Adds validation coverage for safer future refactors.');
  }

  if (lowerDiff.includes('readme') || type === 'docs') {
    highlights.push('Improves project documentation and developer onboarding.');
  }

  if (lowerDiff.includes('docker') || lowerDiff.includes('aws') || lowerDiff.includes('cloud')) {
    highlights.push('Improves deployment readiness for real infrastructure usage.');
  }

  if (lowerDiff.includes('logger') || lowerDiff.includes('log')) {
    highlights.push('Improves observability around security events and blocked requests.');
  }

  if (highlights.length === 0) {
    highlights.push(`Keeps the ${domain.label} implementation easier to review and maintain.`);
  }

  return [...new Set(highlights)].slice(0, 4);
}

function translateHighlight(highlight) {
  const map = new Map([
    [
      'Improves request throttling and abuse-control behavior.',
      'Melhora o controle de requisições abusivas e limitação de tráfego.',
    ],
    [
      'Adds context for DDoS-oriented mitigation at the application layer.',
      'Adiciona suporte contextual para mitigação de DDoS na camada de aplicação.',
    ],
    [
      'Strengthens brute-force mitigation and repeated-attempt handling.',
      'Fortalece a mitigação de brute-force e o tratamento de tentativas repetidas.',
    ],
    [
      'Improves SQL injection detection coverage.',
      'Melhora a cobertura de detecção contra SQL Injection.',
    ],
    [
      'Improves NoSQL injection detection coverage.',
      'Melhora a cobertura de detecção contra NoSQL Injection.',
    ],
    [
      'Improves XSS payload detection coverage.',
      'Melhora a cobertura de detecção contra payloads XSS.',
    ],
    [
      'Improves payload normalization before threat analysis.',
      'Melhora a normalização de payloads antes da análise de ameaça.',
    ],
    [
      'Adds validation coverage for safer future refactors.',
      'Adiciona cobertura de validação para refatorações futuras mais seguras.',
    ],
    [
      'Improves project documentation and developer onboarding.',
      'Melhora a documentação do projeto e a entrada de novos desenvolvedores.',
    ],
    [
      'Improves deployment readiness for real infrastructure usage.',
      'Melhora a preparação para deploy em infraestrutura real.',
    ],
    [
      'Improves observability around security events and blocked requests.',
      'Melhora a observabilidade de eventos de segurança e requisições bloqueadas.',
    ],
  ]);

  return map.get(highlight) || highlight;
}

function getParryDomain(filePath) {
  const normalized = normalizePath(filePath);

  for (const domain of PARRY_DOMAINS) {
    if (domain.test(normalized)) {
      return domain;
    }
  }

  return {
    label: 'project file',
    area: 'project maintenance',
    capability:
      'keep the Parry_InjectionAttacks codebase organized, reviewable, and production-oriented',
  };
}

function ensureUniqueCommit(commit, item, usedSubjects) {
  const candidates = [
    commit.subject,
    withQualifier(commit.subject, qualifierFromPath(item.path)),
    withQualifier(commit.subject, humanizeFileName(path.posix.basename(item.path))),
  ].filter(Boolean);

  for (const candidate of candidates) {
    if (!usedSubjects.has(candidate) && !validateSubject(candidate)) {
      usedSubjects.add(candidate);

      return {
        ...commit,
        subject: candidate,
      };
    }
  }

  const [type, subject] = splitSubject(commit.subject);
  const suffix = qualifierFromPath(item.path)
    .replace(/\b(file|implementation)\b/g, '')
    .trim();

  const fallback = normalizeSubject(`${type}: ${subject} for ${suffix}`);

  usedSubjects.add(fallback);

  return {
    ...commit,
    subject: fallback,
  };
}

function withQualifier(subjectLine, qualifier) {
  if (!qualifier) {
    return null;
  }

  const [type, subject] = splitSubject(subjectLine);

  if (subject.toLowerCase().includes(qualifier.toLowerCase())) {
    return subjectLine;
  }

  return normalizeSubject(`${type}: ${subject} for ${qualifier}`);
}

function splitSubject(subjectLine) {
  const separatorIndex = subjectLine.indexOf(': ');

  if (separatorIndex === -1) {
    return ['chore', subjectLine];
  }

  return [subjectLine.slice(0, separatorIndex), subjectLine.slice(separatorIndex + 2)];
}

function normalizeSubject(subject) {
  return subject
    .replace(/`/g, '')
    .replace(/\s+/g, ' ')
    .replace(/\s+\//g, '/')
    .replace(/\.$/, '')
    .trim()
    .slice(0, 100);
}

function validateSubject(subjectLine) {
  const trimmed = subjectLine.trim();
  const match = trimmed.match(/^([a-z]+):\s+(.+)$/);

  if (!match) {
    return 'subject must start with a Conventional Commit prefix';
  }

  const [, type, subject] = match;

  if (!ALLOWED_TYPES.has(type)) {
    return `unsupported commit type: ${type}`;
  }

  if (subject.trim().length < 5) {
    return 'subject must include descriptive text after the prefix';
  }

  if (trimmed.length > 100) {
    return 'subject must be 100 characters or shorter';
  }

  if (!/^[a-z]+: [A-Za-z0-9][A-Za-z0-9 .,'/_-]*$/.test(trimmed)) {
    return 'subject contains unsupported characters';
  }

  return null;
}

async function promptForDecision(rl, generatedCommit) {
  let commit = generatedCommit;

  while (true) {
    const answer = (
      await rl.question('  Action [c=commit, e=edit subject, b=edit body, s=skip, q=quit]: ')
    )
      .trim()
      .toLowerCase();

    if (answer === '' || answer === 'c' || answer === 'commit') {
      const validationError = validateSubject(commit.subject);

      if (validationError) {
        console.log(`  Invalid subject: ${validationError}`);
        continue;
      }

      return {
        action: 'commit',
        commit,
      };
    }

    if (answer === 'e' || answer === 'edit') {
      const edited = (await rl.question('  Commit subject: ')).trim();
      const validationError = validateSubject(edited);

      if (validationError) {
        console.log(`  Invalid subject: ${validationError}`);
        continue;
      }

      commit = {
        ...commit,
        subject: edited,
      };

      console.log(`  Subject: ${commit.subject}`);
      continue;
    }

    if (answer === 'b' || answer === 'body') {
      console.log('  Enter body lines. Submit an empty line to finish.');

      const lines = [];

      while (true) {
        const line = await rl.question('  body> ');

        if (line === '') {
          break;
        }

        lines.push(line);
      }

      if (lines.length > 0) {
        commit = {
          ...commit,
          body: lines.join('\n'),
        };

        console.log('  Body updated.');
      }

      continue;
    }

    if (answer === 's' || answer === 'skip') {
      return {
        action: 'skip',
      };
    }

    if (answer === 'q' || answer === 'quit') {
      return {
        action: 'quit',
      };
    }

    console.log('  Choose c, e, b, s, or q.');
  }
}

function clearStaging(repoRoot) {
  if (hasHead(repoRoot)) {
    git(repoRoot, ['reset', '--quiet', '--']);
    return;
  }

  git(repoRoot, ['rm', '-r', '--cached', '--quiet', '--ignore-unmatch', '--', '.'], {
    allowFailure: true,
  });
}

function stageItem(repoRoot, item) {
  const paths = item.type === 'rename' ? item.paths : [item.path];
  git(repoRoot, ['add', '--', ...paths]);
}

function assertOnlyCurrentItemStaged(repoRoot, item) {
  const allowed = new Set(item.paths.map((filePath) => normalizePath(filePath)));
  const staged = getStagedFiles(repoRoot);
  const unexpected = staged.filter((filePath) => !allowed.has(filePath));

  if (unexpected.length > 0) {
    throw new Error(`unexpected staged files: ${unexpected.join(', ')}`);
  }
}

function getStagedFiles(repoRoot) {
  const result = git(repoRoot, ['diff', '--cached', '--name-only', '-z'], {
    allowFailure: true,
  });

  return result.stdout
    .split('\0')
    .filter(Boolean)
    .map((filePath) => normalizePath(filePath));
}

function hasStagedChanges(repoRoot) {
  return (
    git(repoRoot, ['diff', '--cached', '--quiet'], {
      allowFailure: true,
    }).status === 1
  );
}

function getStatusKind(item, headExistsAtStart) {
  if (item.type === 'rename') {
    return 'renamed';
  }

  if (item.status === '??' || item.status.includes('A') || !headExistsAtStart) {
    return 'added';
  }

  if (item.status.includes('D')) {
    return 'deleted';
  }

  return 'modified';
}

function getFileRole(filePath) {
  const baseName = path.posix.basename(filePath).toLowerCase();

  if (baseName.endsWith('.controller.js')) {
    return 'controller';
  }

  if (baseName.endsWith('.middleware.js') || baseName === 'middleware.js') {
    return 'middleware';
  }

  if (baseName.endsWith('.service.js')) {
    return 'service';
  }

  if (baseName.endsWith('.store.js') || baseName.includes('store')) {
    return 'store';
  }

  if (baseName.includes('limiter') || baseName.includes('ratelimiter')) {
    return 'limiter';
  }

  if (baseName.includes('detector') || ['sql.js', 'nosql.js', 'xss.js'].includes(baseName)) {
    return 'detector';
  }

  if (baseName.includes('logger') || baseName.includes('reporter')) {
    return 'logger';
  }

  if (baseName.endsWith('.test.js') || baseName.endsWith('.spec.js')) {
    return 'test';
  }

  if (baseName === 'index.js') {
    return 'entrypoint';
  }

  return 'file';
}

function isTestPath(lowerPath, lowerFileName) {
  return (
    lowerPath.startsWith('test/') ||
    lowerPath.startsWith('tests/') ||
    lowerFileName.includes('.spec.') ||
    lowerFileName.includes('.test.')
  );
}

function isDocsPath(lowerPath, lowerFileName) {
  return (
    lowerPath.startsWith('docs/') ||
    lowerPath.startsWith('examples/') ||
    lowerFileName === 'readme.md' ||
    lowerFileName.endsWith('.md') ||
    lowerFileName.endsWith('.mdx')
  );
}

function isBuildPath(lowerPath, lowerFileName) {
  return (
    lowerFileName === 'dockerfile' ||
    lowerPath.includes('docker-compose') ||
    lowerPath.startsWith('docker/') ||
    lowerPath.includes('/docker/') ||
    lowerPath.includes('deploy') ||
    lowerPath === 'package-lock.json'
  );
}

function isConfigPath(lowerPath, lowerFileName) {
  return (
    CONFIG_FILES.has(lowerPath) ||
    CONFIG_FILES.has(lowerFileName) ||
    isEnvExamplePath(lowerPath) ||
    lowerFileName.endsWith('.config.js') ||
    lowerFileName.endsWith('.config.cjs') ||
    lowerFileName.endsWith('.json') ||
    lowerFileName.endsWith('.yaml') ||
    lowerFileName.endsWith('.yml')
  );
}

function isEnvExamplePath(lowerPath) {
  const lowerBaseName = path.posix.basename(lowerPath);
  return ENV_ALLOWLIST.has(lowerBaseName);
}

function hasFixSignals(lowerDiff) {
  return /\b(fix|bug|correct|prevent|resolve|validate|validation|invalid|error|failure|mismatch|escape|sanitize|bypass|blocked|blocking|threshold|overflow|false positive|false negative|regression|security issue|vulnerability)\b/.test(
    lowerDiff
  );
}

function hasEndpointSignals(lowerDiff) {
  return /\b(app\.use|router|middleware|request|response|next\(|express)\b/i.test(lowerDiff);
}

function hasPerformanceSignals(lowerDiff, lowerPath) {
  if (
    !lowerPath.includes('rate') &&
    !lowerPath.includes('ddos') &&
    !lowerPath.includes('engine') &&
    !lowerPath.includes('scoring')
  ) {
    return false;
  }

  return /\b(perf|performance|optimize|optimise|cache|bucket|window|ttl|cleanup|prune|memory|aggregation|fast path)\b/.test(
    lowerDiff
  );
}

function fallbackTypeForPath(lowerPath) {
  if (lowerPath.startsWith('tests/') || lowerPath.includes('.test.')) {
    return 'test';
  }

  if (
    lowerPath.endsWith('.md') ||
    lowerPath.startsWith('docs/') ||
    lowerPath.startsWith('examples/')
  ) {
    return 'docs';
  }

  if (lowerPath.startsWith('.github/')) {
    return 'ci';
  }

  if (lowerPath === 'package-lock.json' || lowerPath.includes('docker')) {
    return 'build';
  }

  if (lowerPath.startsWith('src/')) {
    return 'refactor';
  }

  return 'chore';
}

function qualifierFromPath(filePath) {
  const domain = getParryDomain(filePath);
  const role = getFileRole(filePath);

  if (role !== 'file') {
    return domain.label.toLowerCase().includes(role) ? domain.label : `${domain.label} ${role}`;
  }

  return domain.label || humanizeFileName(path.posix.basename(filePath));
}

function printHeader(details) {
  console.log('Parry atomic commit automation');
  console.log(`Repository: ${details.repoName}`);
  console.log(`Repository root: ${details.repoRoot}`);
  console.log(`Current directory: ${details.currentDir}`);
  console.log(`HEAD exists: ${details.headExists ? 'yes' : 'no'}`);
  console.log(`Dry run: ${details.dryRun ? 'yes' : 'no'}`);
  console.log(`Auto approve: ${details.autoYes ? 'yes' : 'no'}`);
  console.log(`Commit body language: ${details.language}`);
  console.log(`Detected status entries: ${details.detectedEntries}`);
  console.log(`Detected files after expansion: ${details.detectedFiles}`);
  console.log(`Files to process: ${details.processCount}`);
  console.log(`Files ignored: ${details.ignoredCount}`);
}

function printItem(item, commit) {
  console.log(`\nFile: ${item.path}`);
  console.log(`  Git status: ${item.statusLabel}`);

  if (item.type === 'rename') {
    console.log(`  Rename: ${item.oldPath} -> ${item.path}`);
  }

  console.log(`  Subject: ${commit.subject}`);
  console.log('  Body:');

  for (const line of commit.body.split('\n')) {
    console.log(`    ${line}`);
  }
}

function printSummary(summary) {
  console.log('\nSummary:');
  console.log(`  Commits created: ${summary.committed}`);
  console.log(`  Dry-run items: ${summary.dryRun}`);
  console.log(`  Files ignored: ${summary.ignored}`);
  console.log(`  Files skipped: ${summary.skipped}`);
  console.log(`  Errors: ${summary.errors}`);
}

function isDirectory(absolutePath) {
  return fs.existsSync(absolutePath) && fs.statSync(absolutePath).isDirectory();
}

function normalizePath(filePath) {
  return filePath.replace(/\\/g, '/');
}

function humanizeToken(token) {
  return token
    .replace(/\.[^.]+$/, '')
    .replace(/[-_.]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function humanizeFileName(fileName) {
  return (
    humanizeToken(fileName)
      .replace(/\bjs\b/g, '')
      .replace(/\bjson\b/g, '')
      .replace(/\bmd\b/g, '')
      .replace(/\bd\s*ts\b/g, '')
      .replace(/\s+/g, ' ')
      .trim() || 'Parry file'
  );
}

function capitalize(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
