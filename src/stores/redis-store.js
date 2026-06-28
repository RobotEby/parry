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
    const [count, ttlMs] = await Promise.all([
      this.client.get(redisKey),
      this._pTTL(redisKey),
    ]);

    return counterResult(normalizeKey(key), Number(count || 0), ttlMs);
  }

  async resetRateLimit(key) {
    return this.client.del(this._key('rl', key));
  }

  async ban(key, ttlMs, metadata = {}) {
    const normalizedKey = normalizeKey(key);
    const banExpiresAt = Date.now() + ttlMs;
    const payload = JSON.stringify({ metadata, banExpiresAt });

    await this.client.set(this._key('ban', normalizedKey), payload, { PX: ttlMs });

    return { key: normalizedKey, banned: true, banExpiresAt, metadata };
  }

  async isBanned(key) {
    const normalizedKey = normalizeKey(key);
    const redisKey = this._key('ban', normalizedKey);
    const value = await this.client.get(redisKey);

    if (!value) return { key: normalizedKey, banned: false, banExpiresAt: null, metadata: null };

    const ttlMs = await this._pTTL(redisKey);
    if (ttlMs <= 0) {
      await this.client.del(redisKey);
      return { key: normalizedKey, banned: false, banExpiresAt: null, metadata: null };
    }

    const parsed = parseJson(value);
    return {
      key: normalizedKey,
      banned: true,
      banExpiresAt: parsed?.banExpiresAt || Date.now() + ttlMs,
      metadata: parsed?.metadata || null,
    };
  }

  async unban(key) {
    const normalizedKey = normalizeKey(key);
    return this.client.del([this._key('ban', normalizedKey), this._key('suspicious', normalizedKey)]);
  }

  async recordSuspicious(key, ttlMs, metadata = {}) {
    const result = await this._incrementWithTtl(this._key('suspicious', key), normalizeKey(key), ttlMs);
    result.metadata = metadata;
    return result;
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
      (hasMethod(this.client, 'pTTL') || hasMethod(this.client, 'pttl'));

    if (!hasRequired) {
      throw new Error(
        'RedisStore requires a Redis client with get, set, del, incr and pExpire/pTTL support.'
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

function parseJson(value) {
  try {
    return JSON.parse(value);
  } catch (_error) {
    return null;
  }
}

module.exports = { RedisStore };
