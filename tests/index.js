'use strict';

async function main() {
  console.log('═'.repeat(55));
  console.log('  Parry_DDoS — Test Suite');
  console.log('═'.repeat(55));

  console.log('\n▶ Unit — Detectors');
  const det = await require('./unit/detectors.test');

  console.log('\n▶ Unit — RateLimiter');
  const rl = await require('./unit/rateLimiter.test');

  console.log('\n▶ Unit — Stores');
  const memoryStore = await require('./unit/memoryStore.test');
  const redisStore = await require('./unit/redisStore.test');

  console.log('\n▶ Unit — Policies');
  const policies = await require('./unit/policyMatcher.test');

  console.log('\n▶ Unit — Brute Force');
  const keyBuilder = await require('./unit/keyBuilder.test');
  const bruteForce = await require('./unit/bruteForceGuard.test');

  console.log('\n▶ Unit — Core Engine');
  const engine = await require('./unit/engine.test');

  console.log('\n▶ Unit — Application-Layer Guards');
  const appGuards = await require('./unit/applicationGuards.test');

  console.log('\n▶ Unit — Observability');
  const observability = await require('./unit/observability.test');

  console.log('\n▶ Integration — Middleware end-to-end');
  const integ = await require('./integration/middleware.test');

  console.log('\n▶ Integration — Observability and Admin API');
  const observabilityInteg = await require('./integration/observability.test');

  const totalPassed =
    det.passed +
    rl.passed +
    memoryStore.passed +
    redisStore.passed +
    policies.passed +
    keyBuilder.passed +
    bruteForce.passed +
    engine.passed +
    appGuards.passed +
    observability.passed +
    integ.passed +
    observabilityInteg.passed;
  const totalFailed =
    det.failed +
    rl.failed +
    memoryStore.failed +
    redisStore.failed +
    policies.failed +
    keyBuilder.failed +
    bruteForce.failed +
    engine.failed +
    appGuards.failed +
    observability.failed +
    integ.failed +
    observabilityInteg.failed;

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
