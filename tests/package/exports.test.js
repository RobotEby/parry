'use strict';

const { test } = require('node:test');
const nodeAssert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const pkg = require('../../package.json');

function assert(description, condition) {
  nodeAssert.ok(condition, description);
}

function runAll() {
  console.log('\n── Package — Public Exports ────────────────────────────────');

  const rootApi = require('../../src');
  assert('Root API exports Parry_DDoS', typeof rootApi.Parry_DDoS === 'function');
  assert('Root API exports createParry', typeof rootApi.createParry === 'function');
  assert('Root API exports MemoryStore', typeof rootApi.MemoryStore === 'function');
  assert('Root API exports RedisStore', typeof rootApi.RedisStore === 'function');
  assert(
    'Root API exports createParryAdminRouter',
    typeof rootApi.createParryAdminRouter === 'function'
  );

  assert(
    'package.json exports package metadata subpath',
    pkg.exports['./package.json'] === './package.json'
  );

  for (const [subpath, exportTarget] of Object.entries(pkg.exports)) {
    const requireTarget = resolveRequireTarget(exportTarget);
    if (!requireTarget) continue;

    const absoluteTarget = path.resolve(__dirname, '..', '..', requireTarget.replace(/^\.\//, ''));
    assert(`Export ${subpath} target exists`, fs.existsSync(absoluteTarget));

    if (requireTarget.endsWith('.js') || requireTarget.endsWith('.json')) {
      const loaded = require(absoluteTarget);
      assert(`Export ${subpath} can be required`, loaded !== null && loaded !== undefined);
    }
  }

  const expectedSubpathSymbols = {
    './core': ['RateLimiter', 'ThreatLogger', 'MemoryStore', 'RedisStore'],
    './detectors': ['SQLInjectionDetector', 'XSSDetector', 'NoSQLDetector'],
    './stores': ['MemoryStore', 'RedisStore'],
    './policies': ['findMatchingPolicy', 'buildPolicies'],
    './brute-force': ['checkBruteForceBlock', 'buildBruteForceKeys'],
    './events': ['EventBus', 'MemoryEventStore', 'createThreatEvent'],
    './observability': ['Metrics', 'createSnapshot'],
    './admin': ['createParryAdminRouter', 'createAdminAuthMiddleware'],
  };
  for (const [subpath, symbols] of Object.entries(expectedSubpathSymbols)) {
    const api = require(`@roboteby/parry/${subpath.slice(2)}`);
    for (const symbol of symbols) {
      assert(`${subpath} exports ${symbol}`, typeof api[symbol] !== 'undefined');
    }
  }

  verifyPackedInstall();
}

function verifyPackedInstall() {
  const root = path.resolve(__dirname, '..', '..');
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'parry-package-test-'));
  try {
    const report = JSON.parse(
      execFileSync('npm', ['pack', '--json', '--pack-destination', temporary], {
        cwd: root,
        encoding: 'utf8',
      })
    )[0];
    const archive = path.join(temporary, report.filename);
    execFileSync('tar', ['-xzf', archive, '-C', temporary]);

    const nodeModules = path.join(temporary, 'node_modules');
    const scope = path.join(nodeModules, '@roboteby');
    fs.mkdirSync(scope, { recursive: true });
    fs.renameSync(path.join(temporary, 'package'), path.join(scope, 'parry'));
    fs.symlinkSync(path.join(root, 'node_modules', 'express'), path.join(nodeModules, 'express'));
    fs.symlinkSync(
      path.join(root, 'node_modules', 'ipaddr.js'),
      path.join(nodeModules, 'ipaddr.js')
    );

    const isolatedRequire = require('module').createRequire(path.join(temporary, 'consumer.js'));
    const packedApi = isolatedRequire('@roboteby/parry');
    assert(
      'Packed tarball root loads from an isolated directory',
      typeof packedApi.createParry === 'function'
    );
    assert(
      'Packed tarball subpath loads from an isolated directory',
      typeof isolatedRequire('@roboteby/parry/detectors').XSSDetector === 'object'
    );

    const packedPaths = report.files.map((file) => file.path);
    for (const forbidden of ['tests/', 'scripts/', 'docs/', 'docker/', 'infra/', '.github/']) {
      assert(
        `Packed tarball excludes ${forbidden}`,
        packedPaths.every((file) => !file.startsWith(forbidden))
      );
    }
    for (const removed of [
      'src/middleware/index.js',
      'src/middleware/parry_ddos.js',
      'src/core/rateLimiter.js',
      'src/core/logger.js',
      'src/stores/README.md',
    ]) {
      assert(`Packed tarball excludes removed file ${removed}`, !packedPaths.includes(removed));
    }
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

function resolveRequireTarget(exportTarget) {
  if (typeof exportTarget === 'string') return exportTarget;
  if (!exportTarget || typeof exportTarget !== 'object') return null;
  if (typeof exportTarget.require === 'string') return exportTarget.require;
  if (typeof exportTarget.default === 'string') return exportTarget.default;
  return null;
}

test('Package public exports', runAll);
