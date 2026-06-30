'use strict';

async function main() {
  console.log('\n▶ Regression — Payload Fixtures');
  const fixtures = await require('./payload-fixtures.test');

  console.log('\n▶ Regression — Detector Payloads');
  const detectors = await require('./detector-regression.test');

  console.log('\n▶ Regression — Middleware Payloads');
  const middleware = await require('./middleware-regression.test');

  const passed = fixtures.passed + detectors.passed + middleware.passed;
  const failed = fixtures.failed + detectors.failed + middleware.failed;

  console.log('\n' + '─'.repeat(55));
  console.log(`  Payload regression result: ${passed} passed  |  ${failed} failed`);
  console.log('─'.repeat(55) + '\n');

  return { passed, failed };
}

if (require.main === module) {
  main()
    .then((result) => {
      process.exit(result.failed > 0 ? 1 : 0);
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
} else {
  module.exports = main();
}
