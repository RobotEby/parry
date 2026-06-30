'use strict';

class Metrics {
  constructor() {
    this.startedAt = new Date().toISOString();
    this.startedAtMs = Date.now();
    this.counters = {
      totalRequests: 0,
      allowedRequests: 0,
      blockedRequests: 0,
      rateLimitedRequests: 0,
      bruteForceBlocks: 0,
    };
    this.eventsByType = {};
    this.eventsBySeverity = {};
    this.eventsByDetector = {};
    this.eventsByAction = {};
  }

  increment(name, value = 1) {
    this.counters[name] = (this.counters[name] || 0) + value;
  }

  recordRequest(action) {
    if (action === 'started') this.increment('totalRequests');
    if (action === 'allowed') this.increment('allowedRequests');
    if (action === 'blocked') this.increment('blockedRequests');
  }

  recordEvent(event) {
    incrementMap(this.eventsByType, event.type);
    incrementMap(this.eventsBySeverity, event.severity);
    incrementMap(this.eventsByDetector, event.detector);
    incrementMap(this.eventsByAction, event.action);

    if (event.type === 'RATE_LIMIT_EXCEEDED' || event.type === 'ROUTE_RATE_LIMIT_EXCEEDED') {
      this.increment('rateLimitedRequests');
    }
    if (event.type === 'BRUTE_FORCE_BLOCKED') this.increment('bruteForceBlocks');
  }

  snapshot(extra = {}) {
    return {
      startedAt: this.startedAt,
      uptimeMs: Date.now() - this.startedAtMs,
      ...this.counters,
      activeBans: extra.activeBans || 0,
      eventsByType: { ...this.eventsByType },
      eventsBySeverity: { ...this.eventsBySeverity },
      eventsByDetector: { ...this.eventsByDetector },
      eventsByAction: { ...this.eventsByAction },
    };
  }
}

function incrementMap(map, key) {
  if (!key) return;
  map[key] = (map[key] || 0) + 1;
}

module.exports = { Metrics };
