'use strict';

const { test } = require('node:test');
const nodeAssert = require('node:assert/strict');

const fs = require('fs');
const path = require('path');
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
}

function resolveRequireTarget(exportTarget) {
  if (typeof exportTarget === 'string') return exportTarget;
  if (!exportTarget || typeof exportTarget !== 'object') return null;
  if (typeof exportTarget.require === 'string') return exportTarget.require;
  if (typeof exportTarget.default === 'string') return exportTarget.default;
  return null;
}

test('Package public exports', runAll);
