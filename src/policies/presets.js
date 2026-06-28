'use strict';

const COMMON_AUTH_PATHS = ['/login', '/signin', '/auth/login', '/api/login', '/api/auth/login'];

function getPresetPolicies(name) {
  if (!name || name === 'off') return [];
  if (name === 'recommended') return createAuthPolicies('recommended', 10, 10 * 60_000, 20);
  if (name === 'strict') return createAuthPolicies('strict', 5, 15 * 60_000, 10);

  throw new Error(`Unknown Parry_DDoS preset: ${name}`);
}

function createAuthPolicies(prefix, maxAttempts, blockDurationMs, routeMax) {
  return COMMON_AUTH_PATHS.map((path) => ({
    name: `${prefix}-auth-${path.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '')}`,
    match: { method: 'POST', path },
    rateLimit: {
      enabled: true,
      max: routeMax,
      windowMs: 60_000,
      key: 'ip',
    },
    bruteForce: {
      enabled: true,
      maxAttempts,
      windowMs: 15 * 60_000,
      blockDurationMs,
      keys: ['ip', 'body.email', 'ip+body.email', 'body.username', 'ip+body.username'],
      resetOnSuccess: true,
    },
  }));
}

module.exports = { getPresetPolicies };
