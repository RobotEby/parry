'use strict';

const { test } = require('node:test');
const nodeAssert = require('node:assert/strict');

const { RateLimiter } = require('../../src/core/rateLimiter');


function assert(description, condition) {
  nodeAssert.ok(condition, description);
}

async function runAll() {
  console.log('\n── RateLimiter ─────────────────────────────────────────────');

  const rl = new RateLimiter({
    maxRequests: 3,
    windowMs: 5_000,
    suspiciousThreshold: 2,
    banDurationMs: 1_000,
  });

  const ip = '10.0.0.1';
  const ip2 = '10.0.0.2';

  const r1 = await rl.check(ip);
  assert('First request allowed', !r1.limited && !r1.banned);
  assert('Remaining decreases correctly', r1.remaining === 2);

  await rl.check(ip);
  await rl.check(ip);
  const r4 = await rl.check(ip);
  assert('4th request is blocked by rate limit', r4.limited);

  assert('The resetAt header is a future number', r4.resetAt > Date.now());

  await rl.check(ip2);
  await rl.recordSuspicious(ip2);
  await rl.recordSuspicious(ip2);
  const banned = await rl.check(ip2);
  assert('IP banned after reaching suspiciousThreshold', banned.banned);
  assert('banExpiresAt is defined in the result', banned.banExpiresAt !== null);

  const snap = await rl.snapshot();
  assert('Snapshot returns an array', Array.isArray(snap));
  assert(
    'Snapshot contains ip2 as banned',
    snap.some((s) => s.ip === ip2 && s.banned)
  );

  await rl.unban(ip2);
  const unbanned = await rl.check(ip2);
  assert('IP unbaned manually with success', !unbanned.banned);

  rl.destroy();

  console.log('\n── RateLimiter — Store contract ───────────────────────────');
  const calls = [];
  const fakeStore = {
    async isBanned(key) {
      calls.push(['isBanned', key]);
      return { key, banned: false, banExpiresAt: null };
    },
    async incrementRateLimit(key, windowMs) {
      calls.push(['incrementRateLimit', key, windowMs]);
      return { key, count: 2, resetAt: Date.now() + windowMs, ttlMs: windowMs };
    },
    async recordSuspicious(key, ttlMs, metadata) {
      calls.push(['recordSuspicious', key, ttlMs, metadata.reason]);
      return { key, count: 1, resetAt: Date.now() + ttlMs, ttlMs };
    },
    async ban(key, ttlMs) {
      calls.push(['ban', key, ttlMs]);
      return { key, banned: true, banExpiresAt: Date.now() + ttlMs };
    },
    async unban(key) {
      calls.push(['unban', key]);
    },
    async close() {
      calls.push(['close']);
    },
  };
  const storeLimiter = new RateLimiter(
    { maxRequests: 3, windowMs: 5_000, suspiciousThreshold: 2, banDurationMs: 1_000 },
    fakeStore
  );

  const fakeResult = await storeLimiter.check('10.1.1.1');
  assert('Calls store incrementRateLimit', calls.some((call) => call[0] === 'incrementRateLimit'));
  assert('Allows when store count is under max', !fakeResult.limited && fakeResult.remaining === 1);

  await storeLimiter.recordSuspicious('10.1.1.1');
  assert('Calls store recordSuspicious', calls.some((call) => call[0] === 'recordSuspicious'));
  storeLimiter.destroy();

  const limitedStore = {
    async isBanned(key) {
      return { key, banned: false, banExpiresAt: null };
    },
    async incrementRateLimit(key, windowMs) {
      return { key, count: 4, resetAt: Date.now() + windowMs, ttlMs: windowMs };
    },
  };
  const limitedLimiter = new RateLimiter(
    { maxRequests: 3, windowMs: 5_000, suspiciousThreshold: 2, banDurationMs: 1_000 },
    limitedStore
  );
  assert('Blocks when store count exceeds max', (await limitedLimiter.check('10.1.1.2')).limited);
  limitedLimiter.destroy();

  const bannedStore = {
    async isBanned(key) {
      return { key, banned: true, banExpiresAt: Date.now() + 1_000 };
    },
    async incrementRateLimit() {
      throw new Error('should not increment banned key');
    },
  };
  const bannedLimiter = new RateLimiter(
    { maxRequests: 3, windowMs: 5_000, suspiciousThreshold: 2, banDurationMs: 1_000 },
    bannedStore
  );
  assert('Respects existing store ban', (await bannedLimiter.check('10.1.1.3')).banned);
  bannedLimiter.destroy();
}

test('RateLimiter', runAll);
