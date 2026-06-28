'use strict';

function createSnapshot(context) {
  return {
    metrics: context.metrics.snapshot({ activeBans: countActiveBans(context.store) }),
    policies: sanitizePolicies(context.policies || []),
    store: describeStore(context.store),
    events: context.eventBus.getRecentEvents({ limit: 10 }),
  };
}

function describeStore(store) {
  if (!store) return 'unknown';
  if (store.constructor && store.constructor.name) return store.constructor.name.replace(/Store$/, '').toLowerCase();
  return 'custom';
}

function countActiveBans(store) {
  if (store && typeof store.listBans === 'function') return store.listBans().length;
  return 0;
}

function sanitizePolicies(policies) {
  return policies.map((policy) => ({
    name: policy.name,
    match: policy.match,
    inheritGlobalRateLimit: policy.inheritGlobalRateLimit,
    rateLimit: policy.rateLimit,
    bruteForce: policy.bruteForce
      ? {
          enabled: policy.bruteForce.enabled,
          maxAttempts: policy.bruteForce.maxAttempts,
          windowMs: policy.bruteForce.windowMs,
          blockDurationMs: policy.bruteForce.blockDurationMs,
          keyTypes: (policy.bruteForce.keys || []).map((key) => (typeof key === 'function' ? 'custom' : key)),
          resetOnSuccess: policy.bruteForce.resetOnSuccess,
        }
      : undefined,
  }));
}

module.exports = { createSnapshot, describeStore, sanitizePolicies, countActiveBans };
