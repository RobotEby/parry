'use strict';

function createBlockedResponse(blocked) {
  const retryAfter = retryAfterSeconds(blocked);
  return {
    statusCode: blocked.statusCode || 429,
    headers: { 'Retry-After': retryAfter },
    body: {
      error: 'Too many authentication attempts',
      code: 'BRUTE_FORCE_BLOCKED',
      retryAfter,
    },
  };
}

function retryAfterSeconds(blocked) {
  const now = Date.now();
  const until = blocked.blockExpiresAt || blocked.banExpiresAt || now;
  return Math.max(1, Math.ceil((until - now) / 1000));
}

function createAllowedResult(context = {}) {
  return { allowed: true, blocked: false, ...context };
}

function createBlockedResult(context) {
  return { allowed: false, blocked: true, ...context };
}

module.exports = { createBlockedResponse, createAllowedResult, createBlockedResult, retryAfterSeconds };
