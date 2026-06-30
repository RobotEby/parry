'use strict';

const { getExpectedCounts, validateFixtures } = require('./fixture-utils');

function main() {
  const result = validateFixtures();
  const expected = getExpectedCounts();
  const errors = [...result.errors];

  for (const [category, count] of Object.entries(expected)) {
    if (result.counts[category] !== count) {
      errors.push(
        `${category}.json: expected ${count} fixtures, found ${result.counts[category] || 0}`
      );
    }
  }

  if (errors.length > 0) {
    console.error('Payload fixture validation failed:');
    for (const error of errors) console.error(`- ${error}`);
    process.exitCode = 1;
    return;
  }

  console.log(`Payload fixtures valid: ${result.total} fixtures across ${Object.keys(result.counts).length} categories.`);
}

if (require.main === module) main();

module.exports = { validateFixtures };
