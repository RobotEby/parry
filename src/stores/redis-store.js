'use strict';

const INCREMENT_WITH_TTL_SCRIPT = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
local ttl = redis.call("PTTL", KEYS[1])
return { current, ttl }
`;

class RedisStore {
  constructor(options = {}) {
    if (!options.client) {
      throw new Error('RedisStore requires a Redis client.');
    }

    this.client = options.client;
    this.prefix = options.prefix || 'parry';
    this.closeClient = options.closeClient === true;

    this._validateClient();
  }

  async incrementRateLimit(key, windowMs) {
    return this._incrementWithTtl(this._key('rl', key), normalizeKey(key), windowMs);
  }

  async getRateLimit(key) {
    const redisKey = this._key('rl', key);
    const [count, ttlMs] = await Promise.all([this.client.get(redisKey), this._pTTL(redisKey)]);

    return counterResult(normalizeKey(key), Number(count || 0), ttlMs);
  }

  async resetRateLimit(key) {
    return this.client.del(this._key('rl', key));
  }

  async ban(key, ttlMs, metadata = {}) {
    const normalizedKey = normalizeKey(key);
    const createdAt = Date.now();
    const banExpiresAt = createdAt + ttlMs;
    const payload = JSON.stringify({ metadata, createdAt, banExpiresAt });

    await this.client.set(this._key('ban', normalizedKey), payload, { PX: ttlMs });
    await this._indexAdd('bans', normalizedKey);

    return { key: normalizedKey, banned: true, createdAt, banExpiresAt, metadata };
  }

  async isBanned(key) {
    const normalizedKey = normalizeKey(key);
    const redisKey = this._key('ban', normalizedKey);
    const value = await this.client.get(redisKey);

    if (!value) return { key: normalizedKey, banned: false, banExpiresAt: null, metadata: null };

    const ttlMs = await this._pTTL(redisKey);
    if (ttlMs <= 0) {
      await this.client.del(redisKey);
      await this._indexRemove('bans', normalizedKey);
      return { key: normalizedKey, banned: false, banExpiresAt: null, metadata: null };
    }

    const parsed = parseJson(value);
    return {
      key: normalizedKey,
      banned: true,
      createdAt: parsed?.createdAt || null,
      banExpiresAt: parsed?.banExpiresAt || Date.now() + ttlMs,
      metadata: parsed?.metadata || null,
    };
  }

  async unban(key) {
    const normalizedKey = normalizeKey(key);
    await this._indexRemove('bans', normalizedKey);
    return this.client.del([
      this._key('ban', normalizedKey),
      this._key('suspicious', normalizedKey),
    ]);
  }

  async recordSuspicious(key, ttlMs, metadata = {}) {
    const result = await this._incrementWithTtl(
      this._key('suspicious', key),
      normalizeKey(key),
      ttlMs
    );
    result.metadata = metadata;
    return result;
  }

  async incrementCounter(key, ttlMs, metadata = {}) {
    const result = await this._incrementWithTtl(this._counterKey(key), normalizeKey(key), ttlMs);
    result.metadata = metadata;
    return result;
  }

  async getCounter(key) {
    const normalizedKey = normalizeKey(key);
    const redisKey = this._counterKey(normalizedKey);
    const [count, ttlMs] = await Promise.all([this.client.get(redisKey), this._pTTL(redisKey)]);

    return counterResult(normalizedKey, Number(count || 0), ttlMs);
  }

  async resetCounter(key) {
    return this.client.del(this._counterKey(key));
  }

  async blockKey(key, ttlMs, metadata = {}) {
    const normalizedKey = normalizeKey(key);
    const createdAt = Date.now();
    const blockExpiresAt = createdAt + ttlMs;
    const payload = JSON.stringify({ metadata, createdAt, blockExpiresAt });

    await this.client.set(this._blockKey(normalizedKey), payload, { PX: ttlMs });
    await this._indexAdd('blocks', normalizedKey);

    return { key: normalizedKey, blocked: true, createdAt, blockExpiresAt, metadata };
  }

  async isBlocked(key) {
    const normalizedKey = normalizeKey(key);
    const redisKey = this._blockKey(normalizedKey);
    const value = await this.client.get(redisKey);

    if (!value) return { key: normalizedKey, blocked: false, blockExpiresAt: null, metadata: null };

    const ttlMs = await this._pTTL(redisKey);
    if (ttlMs <= 0) {
      await this.client.del(redisKey);
      await this._indexRemove('blocks', normalizedKey);
      return { key: normalizedKey, blocked: false, blockExpiresAt: null, metadata: null };
    }

    const parsed = parseJson(value);
    return {
      key: normalizedKey,
      blocked: true,
      createdAt: parsed?.createdAt || null,
      blockExpiresAt: parsed?.blockExpiresAt || Date.now() + ttlMs,
      metadata: parsed?.metadata || null,
    };
  }

  async unblockKey(key) {
    const normalizedKey = normalizeKey(key);
    await this._indexRemove('blocks', normalizedKey);
    return this.client.del(this._blockKey(normalizedKey));
  }

  async listBans() {
    const keys = await this._readIndex('bans');
    const entries = [];

    for (const key of keys) {
      const ban = await this.isBanned(key);
      if (!ban.banned) continue;
      entries.push({
        key: ban.key,
        createdAt: ban.createdAt,
        banExpiresAt: ban.banExpiresAt,
        ttlMs: ban.banExpiresAt ? Math.max(0, ban.banExpiresAt - Date.now()) : null,
        metadata: ban.metadata,
      });
    }

    return entries;
  }

  async listBlocks() {
    const keys = await this._readIndex('blocks');
    const entries = [];

    for (const key of keys) {
      const block = await this.isBlocked(key);
      if (!block.blocked) continue;
      entries.push({
        key: block.key,
        createdAt: block.createdAt,
        blockExpiresAt: block.blockExpiresAt,
        ttlMs: block.blockExpiresAt ? Math.max(0, block.blockExpiresAt - Date.now()) : null,
        metadata: block.metadata,
      });
    }

    return entries;
  }

  getStoreInfo() {
    return {
      type: 'redis',
      prefix: this.prefix,
      supportsAdminListing: true,
    };
  }

  async close() {
    if (!this.closeClient) return;
    if (typeof this.client.quit === 'function') return this.client.quit();
    if (typeof this.client.disconnect === 'function') return this.client.disconnect();
  }

  _validateClient() {
    const hasRequired =
      hasMethod(this.client, 'get') &&
      hasMethod(this.client, 'set') &&
      hasMethod(this.client, 'del') &&
      hasMethod(this.client, 'incr') &&
      (hasMethod(this.client, 'pExpire') || hasMethod(this.client, 'pexpire')) &&
      (hasMethod(this.client, 'pTTL') || hasMethod(this.client, 'pttl')) &&
      hasMethod(this.client, 'sAdd') &&
      hasMethod(this.client, 'sRem') &&
      (hasMethod(this.client, 'sScan') || hasMethod(this.client, 'sMembers'));

    if (!hasRequired) {
      throw new Error(
        'RedisStore requires a Redis client with get, set, del, incr, pExpire/pTTL and Set index support.'
      );
    }

    if (!hasMethod(this.client, 'eval') && !hasMethod(this.client, 'multi')) {
      throw new Error('RedisStore requires a Redis client with eval or multi/exec support.');
    }
  }

  async _incrementWithTtl(redisKey, publicKey, windowMs) {
    if (hasMethod(this.client, 'eval')) {
      const result = await this.client.eval(INCREMENT_WITH_TTL_SCRIPT, {
        keys: [redisKey],
        arguments: [String(windowMs)],
      });
      const [count, ttlMs] = normalizeRedisArray(result);
      return counterResult(publicKey, count, ttlMs);
    }

    await this.client.set(redisKey, '0', { PX: windowMs, NX: true });

    const multi = this.client.multi();
    multi.incr(redisKey);
    if (typeof multi.pTTL === 'function') multi.pTTL(redisKey);
    else multi.pttl(redisKey);

    const result = await multi.exec();
    const [count, ttlMs] = normalizeRedisArray(result);
    return counterResult(publicKey, count, ttlMs);
  }

  _key(type, key) {
    return `${this.prefix}:${type}:${normalizeKey(key)}`;
  }

  _indexKey(type) {
    return `${this.prefix}:index:${type}`;
  }

  _indexAdd(type, key) {
    return this.client.sAdd(this._indexKey(type), normalizeKey(key));
  }

  _indexRemove(type, key) {
    return this.client.sRem(this._indexKey(type), normalizeKey(key));
  }

  async _readIndex(type) {
    const key = this._indexKey(type);
    if (hasMethod(this.client, 'sScan')) {
      const members = [];
      let cursor = 0;
      do {
        const result = await this.client.sScan(key, cursor, { COUNT: 100 });
        cursor = normalizeCursor(result);
        members.push(...normalizeMembers(result));
      } while (cursor !== 0);
      return members;
    }

    return this.client.sMembers(key);
  }

  _counterKey(key) {
    return `${this.prefix}:${normalizeKey(key)}:count`;
  }

  _blockKey(key) {
    return `${this.prefix}:${normalizeKey(key)}:block`;
  }

  _pExpire(key, ttlMs) {
    const fn = this.client.pExpire || this.client.pexpire;
    return fn.call(this.client, key, ttlMs);
  }

  _pTTL(key) {
    const fn = this.client.pTTL || this.client.pttl;
    return fn.call(this.client, key);
  }
}

function hasMethod(target, method) {
  return typeof target[method] === 'function';
}

function normalizeKey(key) {
  return String(key || 'unknown');
}

function counterResult(key, count, ttlMs) {
  const safeTtl = Number(ttlMs) > 0 ? Number(ttlMs) : 0;
  return {
    key,
    count: Number(count || 0),
    resetAt: safeTtl > 0 ? Date.now() + safeTtl : null,
    ttlMs: safeTtl,
  };
}

function normalizeRedisArray(result) {
  if (!Array.isArray(result)) return [Number(result || 0), 0];

  if (Array.isArray(result[0])) {
    return result.map((item) => Number(item[1] || 0));
  }

  return result.map((item) => Number(item || 0));
}

function normalizeCursor(result) {
  if (Array.isArray(result)) return Number(result[0] || 0);
  return Number(result?.cursor || 0);
}

function normalizeMembers(result) {
  if (Array.isArray(result)) return result[1] || [];
  return result?.members || [];
}

function parseJson(value) {
  try {
    return JSON.parse(value);
  } catch (_error) {
    return null;
  }
}

module.exports = { RedisStore };
