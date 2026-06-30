'use strict';

const { RedisStore } = require('../../src/stores');

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

class FakeRedisClient {
  constructor() {
    this.records = new Map();
    this.sets = new Map();
    this.calls = [];
  }

  async get(key) {
    this.calls.push(['get', key]);
    const record = this.records.get(key);
    if (!record) return null;
    if (record.expiresAt && record.expiresAt <= Date.now()) {
      this.records.delete(key);
      return null;
    }
    return record.value;
  }

  async set(key, value, options = {}) {
    this.calls.push(['set', key, value, options]);
    if (options.NX && (await this.get(key)) !== null) return null;
    this.records.set(key, {
      value: String(value),
      expiresAt: options.PX ? Date.now() + options.PX : null,
    });
    return 'OK';
  }

  async del(keys) {
    this.calls.push(['del', keys]);
    const list = Array.isArray(keys) ? keys : [keys];
    let removed = 0;
    for (const key of list) {
      if (this.records.delete(key)) removed++;
    }
    return removed;
  }

  async sAdd(key, member) {
    this.calls.push(['sAdd', key, member]);
    const set = this.sets.get(key) || new Set();
    set.add(member);
    this.sets.set(key, set);
    return 1;
  }

  async sRem(key, member) {
    this.calls.push(['sRem', key, member]);
    const set = this.sets.get(key);
    if (!set) return 0;
    const removed = set.delete(member);
    return removed ? 1 : 0;
  }

  async sScan(key, cursor) {
    this.calls.push(['sScan', key, cursor]);
    return {
      cursor: 0,
      members: [...(this.sets.get(key) || [])],
    };
  }

  async incr(key) {
    this.calls.push(['incr', key]);
    const current = Number((await this.get(key)) || 0) + 1;
    const record = this.records.get(key) || { expiresAt: null };
    this.records.set(key, { value: String(current), expiresAt: record.expiresAt });
    return current;
  }

  async pExpire(key, ttlMs) {
    this.calls.push(['pExpire', key, ttlMs]);
    const record = this.records.get(key);
    if (!record) return 0;
    record.expiresAt = Date.now() + ttlMs;
    return 1;
  }

  async pTTL(key) {
    this.calls.push(['pTTL', key]);
    const record = this.records.get(key);
    if (!record || !record.expiresAt) return -1;
    return Math.max(0, record.expiresAt - Date.now());
  }

  async eval(_script, options) {
    this.calls.push(['eval', options.keys[0], options.arguments[0]]);
    const key = options.keys[0];
    const ttlMs = Number(options.arguments[0]);
    const count = await this.incr(key);
    if (count === 1) await this.pExpire(key, ttlMs);
    return [count, await this.pTTL(key)];
  }
}

async function runAll() {
  console.log('\n── RedisStore ──────────────────────────────────────────────');

  let invalidError = null;
  try {
    new RedisStore({ client: { get() {} } });
  } catch (error) {
    invalidError = error;
  }
  assert(
    'Throws clear error when client is invalid',
    invalidError?.message.includes('pExpire/pTTL and Set index support')
  );

  const client = new FakeRedisClient();
  const store = new RedisStore({ client, prefix: 'parry-test' });
  const first = await store.incrementRateLimit('10.0.0.1', 1_000);
  const second = await store.incrementRateLimit('10.0.0.1', 1_000);

  assert('incrementRateLimit increments Redis counter', first.count === 1 && second.count === 2);
  assert(
    'incrementRateLimit uses namespaced rate limit key',
    client.calls.some((call) => call[0] === 'eval' && call[1] === 'parry-test:rl:10.0.0.1')
  );

  await store.ban('10.0.0.2', 1_000, { reason: 'test' });
  assert(
    'ban writes namespaced key with TTL',
    client.calls.some(
      (call) => call[0] === 'set' && call[1] === 'parry-test:ban:10.0.0.2' && call[3].PX === 1_000
    )
  );
  assert('isBanned reads active ban', (await store.isBanned('10.0.0.2')).banned);
  const listedBans = await store.listBans();
  assert('listBans returns indexed active ban', listedBans.some((entry) => entry.key === '10.0.0.2'));
  assert(
    'listBans uses Redis Set index without KEYS',
    client.calls.some((call) => call[0] === 'sScan' && call[1] === 'parry-test:index:bans') &&
      !client.calls.some((call) => call[0] === 'keys')
  );

  await store.unban('10.0.0.2');
  assert('unban removes ban key', !(await store.isBanned('10.0.0.2')).banned);

  const suspicious = await store.recordSuspicious('10.0.0.3', 1_000, { reason: 'test' });
  assert('recordSuspicious increments suspicious key', suspicious.count === 1);
  assert(
    'recordSuspicious uses namespaced suspicious key',
    client.calls.some((call) => call[0] === 'eval' && call[1] === 'parry-test:suspicious:10.0.0.3')
  );

  const counter = await store.incrementCounter('bf:auth-login:ip:10.0.0.4', 1_000, { reason: 'test' });
  assert('incrementCounter increments generic counter', counter.count === 1);
  assert(
    'incrementCounter uses namespaced generic key',
    client.calls.some((call) => call[0] === 'eval' && call[1] === 'parry-test:bf:auth-login:ip:10.0.0.4:count')
  );
  assert('getCounter reads generic counter', (await store.getCounter('bf:auth-login:ip:10.0.0.4')).count === 1);
  await store.resetCounter('bf:auth-login:ip:10.0.0.4');
  assert('resetCounter removes generic counter', (await store.getCounter('bf:auth-login:ip:10.0.0.4')).count === 0);

  await store.blockKey('bf:auth-login:ip:10.0.0.5', 1_000, { reason: 'test' });
  assert('blockKey marks generic key blocked', (await store.isBlocked('bf:auth-login:ip:10.0.0.5')).blocked);
  assert(
    'blockKey uses namespaced block key',
    client.calls.some((call) => call[0] === 'set' && call[1] === 'parry-test:bf:auth-login:ip:10.0.0.5:block')
  );
  const listedBlocks = await store.listBlocks();
  assert(
    'listBlocks returns indexed active block',
    listedBlocks.some((entry) => entry.key === 'bf:auth-login:ip:10.0.0.5')
  );
  assert(
    'listBlocks uses Redis Set index without KEYS',
    client.calls.some((call) => call[0] === 'sScan' && call[1] === 'parry-test:index:blocks') &&
      !client.calls.some((call) => call[0] === 'keys')
  );
  await store.unblockKey('bf:auth-login:ip:10.0.0.5');
  assert('unblockKey removes generic block', !(await store.isBlocked('bf:auth-login:ip:10.0.0.5')).blocked);

  return { passed, failed };
}

module.exports = runAll();
