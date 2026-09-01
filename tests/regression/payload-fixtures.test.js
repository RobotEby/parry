'use strict';

const { test } = require('node:test');
const nodeAssert = require('node:assert/strict');
const {
  getExpectedCounts,
  loadFixtures,
  validateFixtures,
} = require('../../scripts/payloads/fixture-utils');

function assert(description, condition) {
  nodeAssert.ok(condition, description);
}

function runAll() {
  console.log('\n── Payload Fixtures ────────────────────────────────────────');

  const validation = validateFixtures();
  if (!validation.ok) {
    for (const error of validation.errors) console.error(`  - ${error}`);
  }
  assert('Payload fixture schema is valid', validation.ok);

  const expected = getExpectedCounts();
  for (const [category, count] of Object.entries(expected)) {
    assert(`${category}.json has ${count} fixtures`, validation.counts[category] === count);
  }

  const { all } = loadFixtures();
  assert('Payload fixture total is 217', all.length === 217);
  assert(
    'No fixture imports from external reference repository',
    all.every((fixture) => !String(fixture.payload).includes('external/PayloadsAllTheThings'))
  );
}

test('Payload fixture integrity', runAll);
