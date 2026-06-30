'use strict';

function normalizeRateLimitKey(value) {
  return String(value || 'unknown');
}

module.exports = { normalizeRateLimitKey };
