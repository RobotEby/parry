'use strict';

function createThreatEvent({ ip, timestamp, method, url, threats }) {
  return {
    type: 'THREAT',
    ip,
    timestamp,
    method,
    url,
    threats,
  };
}

function createBanEvent({ ip, timestamp }) {
  return {
    type: 'BAN',
    ip,
    reason: 'Ban for suspicious activity',
    timestamp,
  };
}

function createRateLimitEvent({ ip, timestamp }) {
  return { type: 'RATE_LIMIT', ip, timestamp };
}

module.exports = { createThreatEvent, createBanEvent, createRateLimitEvent };
