'use strict';

class MemoryStore {
  constructor() {
    this.rateLimits = new Map();
    this.bans = new Map();
    this.suspicious = new Map();
    this.counters = new Map();
    this.blocks = new Map();
  }

  incrementRateLimit(key, windowMs) {
    const now = Date.now();
    const normalizedKey = normalizeKey(key);
    const windowStart = now - windowMs;
    const entry = this.rateLimits.get(normalizedKey) || { timestamps: [] };

    entry.timestamps = entry.timestamps.filter((timestamp) => timestamp > windowStart);
    entry.timestamps.push(now);
    entry.resetAt = entry.timestamps[0] + windowMs;
    this.rateLimits.set(normalizedKey, entry);

    return formatCounterResult(normalizedKey, entry.timestamps.length, entry.resetAt, now);
  }

  getRateLimit(key) {
    const now = Date.now();
    const normalizedKey = normalizeKey(key);
    const entry = this.rateLimits.get(normalizedKey);
    if (!entry) return emptyCounterResult(normalizedKey);

    const resetAt = entry.resetAt || now;
    if (entry.timestamps.length === 0 || resetAt <= now) {
      this.rateLimits.delete(normalizedKey);
      return emptyCounterResult(normalizedKey);
    }

    return formatCounterResult(normalizedKey, entry.timestamps.length, resetAt, now);
  }

  resetRateLimit(key) {
    return this.rateLimits.delete(normalizeKey(key));
  }

  ban(key, ttlMs, metadata = {}) {
    const normalizedKey = normalizeKey(key);
    const expiresAt = Date.now() + ttlMs;
    this.bans.set(normalizedKey, { expiresAt, metadata });
    return { key: normalizedKey, banned: true, banExpiresAt: expiresAt, metadata };
  }

  isBanned(key) {
    const normalizedKey = normalizeKey(key);
    const entry = this.bans.get(normalizedKey);
    if (!entry) return { key: normalizedKey, banned: false, banExpiresAt: null, metadata: null };

    const now = Date.now();
    if (entry.expiresAt <= now) {
      this.bans.delete(normalizedKey);
      this.suspicious.delete(normalizedKey);
      this.rateLimits.delete(normalizedKey);
      return { key: normalizedKey, banned: false, banExpiresAt: null, metadata: null };
    }

    return {
      key: normalizedKey,
      banned: true,
      banExpiresAt: entry.expiresAt,
      metadata: entry.metadata || null,
    };
  }

  unban(key) {
    const normalizedKey = normalizeKey(key);
    this.suspicious.delete(normalizedKey);
    return this.bans.delete(normalizedKey);
  }

  recordSuspicious(key, ttlMs, metadata = {}) {
    const now = Date.now();
    const normalizedKey = normalizeKey(key);
    const current = this.suspicious.get(normalizedKey);
    const entry =
      current && current.resetAt > now
        ? current
        : { count: 0, resetAt: now + ttlMs, metadata: null };

    entry.count += 1;
    entry.metadata = metadata;
    this.suspicious.set(normalizedKey, entry);

    return formatCounterResult(normalizedKey, entry.count, entry.resetAt, now);
  }

  incrementCounter(key, ttlMs, metadata = {}) {
    const now = Date.now();
    const normalizedKey = normalizeKey(key);
    const current = this.counters.get(normalizedKey);
    const entry =
      current && current.resetAt > now
        ? current
        : { count: 0, resetAt: now + ttlMs, metadata: null };

    entry.count += 1;
    entry.metadata = metadata;
    this.counters.set(normalizedKey, entry);

    return formatCounterResult(normalizedKey, entry.count, entry.resetAt, now);
  }

  getCounter(key) {
    const now = Date.now();
    const normalizedKey = normalizeKey(key);
    const entry = this.counters.get(normalizedKey);
    if (!entry || entry.resetAt <= now) {
      this.counters.delete(normalizedKey);
      return emptyCounterResult(normalizedKey);
    }

    return formatCounterResult(normalizedKey, entry.count, entry.resetAt, now);
  }

  resetCounter(key) {
    return this.counters.delete(normalizeKey(key));
  }

  blockKey(key, ttlMs, metadata = {}) {
    const normalizedKey = normalizeKey(key);
    const blockExpiresAt = Date.now() + ttlMs;
    this.blocks.set(normalizedKey, { blockExpiresAt, metadata });
    return { key: normalizedKey, blocked: true, blockExpiresAt, metadata };
  }

  isBlocked(key) {
    const normalizedKey = normalizeKey(key);
    const entry = this.blocks.get(normalizedKey);
    if (!entry) return { key: normalizedKey, blocked: false, blockExpiresAt: null, metadata: null };

    const now = Date.now();
    if (entry.blockExpiresAt <= now) {
      this.blocks.delete(normalizedKey);
      return { key: normalizedKey, blocked: false, blockExpiresAt: null, metadata: null };
    }

    return {
      key: normalizedKey,
      blocked: true,
      blockExpiresAt: entry.blockExpiresAt,
      metadata: entry.metadata || null,
    };
  }

  unblockKey(key) {
    return this.blocks.delete(normalizeKey(key));
  }

  cleanup(now = Date.now()) {
    for (const [key, entry] of this.rateLimits.entries()) {
      if (!entry.timestamps.length) {
        this.rateLimits.delete(key);
        continue;
      }

      if (entry.resetAt <= now) this.rateLimits.delete(key);
    }

    for (const [key, entry] of this.bans.entries()) {
      if (entry.expiresAt <= now) this.bans.delete(key);
    }

    for (const [key, entry] of this.suspicious.entries()) {
      if (entry.resetAt <= now) this.suspicious.delete(key);
    }

    for (const [key, entry] of this.counters.entries()) {
      if (entry.resetAt <= now) this.counters.delete(key);
    }

    for (const [key, entry] of this.blocks.entries()) {
      if (entry.blockExpiresAt <= now) this.blocks.delete(key);
    }
  }

  snapshot(windowMs) {
    const now = Date.now();
    const ips = new Set([
      ...this.rateLimits.keys(),
      ...this.suspicious.keys(),
      ...this.bans.keys(),
    ]);

    return [...ips].map((ip) => {
      const rateLimitEntry = this.rateLimits.get(ip);
      const suspiciousEntry = this.suspicious.get(ip);
      const ban = this.isBanned(ip);
      const windowStart = now - windowMs;
      const requests = rateLimitEntry
        ? rateLimitEntry.timestamps.filter((timestamp) => timestamp > windowStart).length
        : 0;

      return {
        ip,
        requests,
        suspicious: suspiciousEntry && suspiciousEntry.resetAt > now ? suspiciousEntry.count : 0,
        banned: ban.banned,
        banExpiresAt: ban.banExpiresAt,
      };
    });
  }

  clear() {
    this.rateLimits.clear();
    this.bans.clear();
    this.suspicious.clear();
    this.counters.clear();
    this.blocks.clear();
  }

  close() {
    this.clear();
  }
}

function normalizeKey(key) {
  return String(key || 'unknown');
}

function emptyCounterResult(key) {
  return { key, count: 0, resetAt: null, ttlMs: 0 };
}

function formatCounterResult(key, count, resetAt, now) {
  return {
    key,
    count,
    resetAt,
    ttlMs: Math.max(0, resetAt - now),
  };
}

module.exports = { MemoryStore };
