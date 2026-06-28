'use strict';

const { MemoryStore } = require('../stores/memory-store');
const { createRateLimitResult } = require('../core/rate-limit-result');
const { normalizeRateLimitKey } = require('./keys');

class RateLimiter {
  /**
   * @param {{
   *   rateLimit?: boolean | { enabled?: boolean, max?: number, maxRequests?: number, windowMs?: number, headers?: boolean },
   *   maxRequests?: number,
   *   windowMs?: number,
   *   suspiciousThreshold?: number,
   *   banDurationMs?: number,
   *   store?: import('../stores/memory-store').MemoryStore
   * }} config
   * @param {object} [store]
   */
  constructor(config, store) {
    const rateLimit = normalizeRateLimitOptions(config);

    this.enabled = rateLimit.enabled;
    this.maxRequests = rateLimit.maxRequests;
    this.windowMs = rateLimit.windowMs;
    this.headers = rateLimit.headers;
    this.suspiciousThreshold = config.suspiciousThreshold;
    this.banDurationMs = config.banDurationMs;
    this.suspiciousTtlMs = Math.max(this.windowMs, this.banDurationMs, 600_000);
    this.store = store || config.store || new MemoryStore();

    this._cleanupInterval = setInterval(() => this._cleanup(), 600_000);
    if (this._cleanupInterval.unref) this._cleanupInterval.unref();
  }

  async check(ip) {
    const key = normalizeRateLimitKey(ip);
    const ban = await this.store.isBanned(key);

    if (ban.banned) {
      return createRateLimitResult({
        limited: false,
        banned: true,
        remaining: 0,
        resetAt: ban.banExpiresAt,
        banExpiresAt: ban.banExpiresAt,
      });
    }

    const counter = await this.store.incrementRateLimit(key, this.windowMs);
    const remaining = Math.max(0, this.maxRequests - counter.count);

    if (counter.count > this.maxRequests) {
      return createRateLimitResult({
        limited: true,
        banned: false,
        remaining: 0,
        resetAt: counter.resetAt,
        banExpiresAt: null,
      });
    }

    return createRateLimitResult({
      limited: false,
      banned: false,
      remaining,
      resetAt: counter.resetAt,
      banExpiresAt: null,
    });
  }

  async recordSuspicious(ip) {
    const key = normalizeRateLimitKey(ip);
    const suspicious = await this.store.recordSuspicious(key, this.suspiciousTtlMs, {
      reason: 'Threat detected',
    });

    if (suspicious.count >= this.suspiciousThreshold) {
      return this.store.ban(key, this.banDurationMs, {
        reason: 'Suspicious activity threshold reached',
        suspiciousCount: suspicious.count,
      });
    }

    return suspicious;
  }

  async unban(ip) {
    return this.store.unban(normalizeRateLimitKey(ip));
  }

  async snapshot() {
    if (typeof this.store.snapshot === 'function') {
      return this.store.snapshot(this.windowMs);
    }

    return [];
  }

  async _cleanup() {
    if (typeof this.store.cleanup === 'function') {
      await this.store.cleanup();
    }
  }

  destroy() {
    clearInterval(this._cleanupInterval);
    if (typeof this.store.close === 'function') return this.store.close();
    if (typeof this.store.clear === 'function') return this.store.clear();
  }
}

function normalizeRateLimitOptions(config) {
  const option = config.rateLimit;
  const objectConfig = option && typeof option === 'object' ? option : {};

  return {
    enabled: option !== false && objectConfig.enabled !== false,
    maxRequests: objectConfig.max || objectConfig.maxRequests || config.maxRequests || 100,
    windowMs: objectConfig.windowMs || config.windowMs || 60_000,
    headers: objectConfig.headers !== false,
  };
}

module.exports = { RateLimiter, normalizeRateLimitOptions };
