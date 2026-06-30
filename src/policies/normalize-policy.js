'use strict';

const { getPresetPolicies } = require('./presets');

const BRUTE_FORCE_DEFAULTS = {
  enabled: false,
  maxAttempts: 5,
  windowMs: 15 * 60_000,
  blockDurationMs: 10 * 60_000,
  keys: ['ip'],
  failureStatusCodes: [400, 401, 403],
  successStatusCodes: [200, 201, 204],
  blockedStatusCode: 429,
  resetOnSuccess: true,
};

function buildPolicies(options = {}) {
  const presetName = options.preset || 'off';
  const presetPolicies = options.bruteForce === false ? [] : getPresetPolicies(presetName);
  const explicitPolicies = Array.isArray(options.policies) ? options.policies : [];
  const merged = mergePolicies(presetPolicies, explicitPolicies);

  return merged.map((policy) => normalizePolicy(policy, options));
}

function normalizePolicy(policy, options = {}) {
  if (!policy || !policy.name) {
    throw new Error('Parry policy requires a name.');
  }

  const bruteForceDisabled =
    options.bruteForce === false ||
    (options.bruteForce &&
      typeof options.bruteForce === 'object' &&
      options.bruteForce.enabled === false);

  return {
    name: String(policy.name),
    match: policy.match || {},
    inheritGlobalRateLimit: policy.inheritGlobalRateLimit !== false,
    rateLimit: normalizeRateLimit(policy.rateLimit),
    bruteForce: normalizeBruteForce(policy.bruteForce, bruteForceDisabled),
  };
}

function normalizeRateLimit(rateLimit) {
  if (!rateLimit || rateLimit.enabled === false) return { enabled: false };

  return {
    enabled: true,
    max: rateLimit.max || rateLimit.maxRequests || 10,
    windowMs: rateLimit.windowMs || 60_000,
    key: rateLimit.key || 'ip',
  };
}

function normalizeBruteForce(bruteForce, forceDisabled) {
  if (forceDisabled || !bruteForce || bruteForce.enabled === false) {
    return { ...BRUTE_FORCE_DEFAULTS, enabled: false };
  }

  return {
    ...BRUTE_FORCE_DEFAULTS,
    ...bruteForce,
    enabled: true,
    keys:
      Array.isArray(bruteForce.keys) && bruteForce.keys.length > 0
        ? bruteForce.keys
        : BRUTE_FORCE_DEFAULTS.keys,
    failureStatusCodes: normalizeStatusList(
      bruteForce.failureStatusCodes,
      BRUTE_FORCE_DEFAULTS.failureStatusCodes
    ),
    successStatusCodes: normalizeStatusList(
      bruteForce.successStatusCodes,
      BRUTE_FORCE_DEFAULTS.successStatusCodes
    ),
    resetOnSuccess: bruteForce.resetOnSuccess !== false,
  };
}

function normalizeStatusList(value, fallback) {
  if (!Array.isArray(value) || value.length === 0) return fallback;
  return value.map((status) => Number(status)).filter((status) => Number.isInteger(status));
}

function mergePolicies(presetPolicies, explicitPolicies) {
  const byName = new Map();
  for (const policy of presetPolicies) byName.set(policy.name, policy);
  for (const policy of explicitPolicies) byName.set(policy.name, policy);
  return [...byName.values()];
}

module.exports = { buildPolicies, normalizePolicy, BRUTE_FORCE_DEFAULTS };
