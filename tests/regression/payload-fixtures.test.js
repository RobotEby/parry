'use strict';

const { getExpectedCounts, loadFixtures, validateFixtures } = require('../../scripts/payloads/fixture-utils');

let passed = 0,
  failed = 0;

function assert(description, condition) {
  if (condition) {
    console.log(`  ✓ ${description}`);
    passed++;
  } else {
    console.error(`  ✗ FAILED: ${description}`);
    failed++;
  }
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
  assert('Payload fixture total is 211', all.length === 211);
  assert(
    'Command Injection fixtures are monitor-only',
    all.filter((fixture) => fixture.category === 'command-injection').every((fixture) => fixture.monitorOnly && fixture.expected.mode === 'monitor')
  );
  assert(
    'SSRF fixtures are monitor-only',
    all.filter((fixture) => fixture.category === 'ssrf').every((fixture) => fixture.monitorOnly && fixture.expected.mode === 'monitor')
  );
  assert(
    'No fixture imports from external reference repository',
    all.every((fixture) => !String(fixture.payload).includes('external/PayloadsAllTheThings'))
  );

  return { passed, failed };
}

module.exports = Promise.resolve(runAll());
