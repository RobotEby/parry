'use strict';

const { MemoryStore } = require('../stores/memory-store');

class RateLimiter {
  /**
   * @param {{ maxRequests: number, windowMs: number, suspiciousThreshold: number, banDurationMs: number }} config
   * @param {MemoryStore} [store]
   */
  constructor(config, store = new MemoryStore()) {
    this.maxRequests = config.maxRequests;
    this.windowMs = config.windowMs;
    this.suspiciousThreshold = config.suspiciousThreshold;
    this.banDurationMs = config.banDurationMs;
    this.store = store;

    this._cleanupInterval = setInterval(() => this._cleanup(), 600_000);
    if (this._cleanupInterval.unref) this._cleanupInterval.unref();
  }

  check(ip) {
    const now = Date.now();
    const entry = this._getOrCreate(ip);

    if (entry.banUntil !== null) {
      if (now < entry.banUntil) {
        return {
          limited: false,
          banned: true,
          remaining: 0,
          resetAt: entry.banUntil,
          banExpiresAt: entry.banUntil,
        };
      }
      entry.banUntil = null;
      entry.suspicious = 0;
      entry.timestamps = [];
    }

    const windowStart = now - this.windowMs;
    entry.timestamps = entry.timestamps.filter((t) => t > windowStart);
    entry.timestamps.push(now);

    const count = entry.timestamps.length;
    const oldest = entry.timestamps[0] || now;
    const resetAt = oldest + this.windowMs;
    const remaining = Math.max(0, this.maxRequests - count);

    if (count > this.maxRequests) {
      return { limited: true, banned: false, remaining: 0, resetAt, banExpiresAt: null };
    }

    return { limited: false, banned: false, remaining, resetAt, banExpiresAt: null };
  }

  recordSuspicious(ip) {
    const entry = this._getOrCreate(ip);
    entry.suspicious += 1;
    if (entry.suspicious >= this.suspiciousThreshold) {
      entry.banUntil = Date.now() + this.banDurationMs;
    }
  }

  unban(ip) {
    const entry = this.store.get(ip);
    if (entry) {
      entry.banUntil = null;
      entry.suspicious = 0;
    }
  }

  snapshot() {
    const now = Date.now();
    return [...this.store.entries()].map(([ip, entry]) => {
      const active = entry.timestamps.filter((t) => t > now - this.windowMs).length;
      return {
        ip,
        requests: active,
        suspicious: entry.suspicious,
        banned: entry.banUntil !== null && entry.banUntil > now,
        banExpiresAt: entry.banUntil,
      };
    });
  }

  _getOrCreate(ip) {
    if (typeof this.store.getOrCreate === 'function') {
      return this.store.getOrCreate(ip, () => ({ timestamps: [], suspicious: 0, banUntil: null }));
    }

    if (!this.store.has(ip)) this.store.set(ip, { timestamps: [], suspicious: 0, banUntil: null });
    return this.store.get(ip);
  }

  _cleanup() {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    for (const [ip, entry] of this.store.entries()) {
      const active = entry.timestamps.some((t) => t > windowStart);
      const banned = entry.banUntil !== null && entry.banUntil > now;
      if (!active && !banned) this.store.delete(ip);
    }
  }

  destroy() {
    clearInterval(this._cleanupInterval);
    this.store.clear();
  }
}

module.exports = { RateLimiter };
