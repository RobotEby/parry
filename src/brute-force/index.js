'use strict';

const {
  createBruteForceContext,
  attachParryRequestApi,
  checkBruteForceBlock,
  observeAuthenticationResult,
  finalizeAuthenticationResult,
  createBruteForceEvent,
} = require('./brute-force-guard');
const { buildBruteForceKeys, buildRouteRateLimitKey, buildKey, resolveValue } = require('./key-builder');
const { createBlockedResponse, retryAfterSeconds } = require('./result');

module.exports = {
  createBruteForceContext,
  attachParryRequestApi,
  checkBruteForceBlock,
  observeAuthenticationResult,
  finalizeAuthenticationResult,
  createBruteForceEvent,
  buildBruteForceKeys,
  buildRouteRateLimitKey,
  buildKey,
  resolveValue,
  createBlockedResponse,
  retryAfterSeconds,
};
