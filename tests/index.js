'use strict';

async function main() {
  console.log('═'.repeat(55));
  console.log('  Parry_DDoS — Test Suite');
  console.log('═'.repeat(55));

  console.log('\n▶ Unit — Detectors');
  const det = require('./unit/detectors.test');

  console.log('\n▶ Unit — RateLimiter');
  const rl = require('./unit/rateLimiter.test');

  console.log('\n▶ Unit — Core Engine');
  const engine = require('./unit/engine.test');

  console.log('\n▶ Integration — Middleware end-to-end');
  const integ = await require('./integration/middleware.test');

  const totalPassed = det.passed + rl.passed + engine.passed + integ.passed;
  const totalFailed = det.failed + rl.failed + engine.failed + integ.failed;

  console.log('\n' + '═'.repeat(55));
  console.log(`  Result: ${totalPassed} passed  |  ${totalFailed} failed`);
  if (totalFailed === 0) console.log('  ✓ All tests passed!');
  console.log('═'.repeat(55) + '\n');

  process.exit(totalFailed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
