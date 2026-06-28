'use strict';

const DEFAULTS = {
  sql: true,
  xss: true,
  nosql: true,

  hpp: {
    enabled: false,
    allowDuplicateParamsFor: [],
  },
  prototypePollution: {
    enabled: true,
  },
  pathTraversal: {
    enabled: true,
  },
  requestShape: {
    enabled: true,
    maxDepth: 8,
    maxKeys: 500,
    maxArrayLength: 100,
    maxStringLength: 10_000,
  },

  rateLimit: true,
  maxRequests: 100,
  windowMs: 60_000,
  store: null,
  storeFailureMode: 'fail-open',
  policies: [],
  preset: 'off',
  bruteForce: {
    enabled: false,
  },

  suspiciousThreshold: 5,
  banDurationMs: 300_000,

  logThreats: true,

  onThreat: null,

  maxObjectDepth: 5,
};

module.exports = { DEFAULTS };
