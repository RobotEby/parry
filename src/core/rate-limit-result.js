'use strict';

function createRateLimitResult({ limited, banned, remaining, resetAt, banExpiresAt }) {
  return {
    limited: Boolean(limited),
    banned: Boolean(banned),
    remaining: Math.max(0, Number(remaining || 0)),
    resetAt: resetAt || null,
    banExpiresAt: banExpiresAt || null,
  };
}

module.exports = { createRateLimitResult };
