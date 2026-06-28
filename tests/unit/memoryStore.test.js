'use strict';

const { MemoryStore } = require('../../src/stores');

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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runAll() {
  console.log('\n── MemoryStore ─────────────────────────────────────────────');

  const store = new MemoryStore();
  const key = '203.0.113.10';

  const first = store.incrementRateLimit(key, 50);
  const second = store.incrementRateLimit(key, 50);
  assert('Increments rate limit counter', first.count === 1 && second.count === 2);
  assert('Stores rate limit ttl', second.ttlMs > 0 && second.resetAt > Date.now());

  await sleep(60);
  const afterWindow = store.incrementRateLimit(key, 50);
  assert('Resets counter after expiration', afterWindow.count === 1);

  const ban = store.ban(key, 100, { reason: 'test' });
  assert('ban records expiration', ban.banned && ban.banExpiresAt > Date.now());
  assert('isBanned returns active ban', store.isBanned(key).banned);

  store.unban(key);
  assert('unban removes active ban', !store.isBanned(key).banned);

  const suspicious = store.recordSuspicious(key, 100, { reason: 'test' });
  assert('recordSuspicious increments counter', suspicious.count === 1);

  const activeKey = '203.0.113.11';
  store.incrementRateLimit(activeKey, 1_000);
  store.cleanup(Date.now());
  assert('cleanup does not remove active item', store.getRateLimit(activeKey).count === 1);

  store.close();

  return { passed, failed };
}

module.exports = runAll();
