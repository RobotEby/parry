'use strict';

function createThreatEvent({ ip, timestamp, method, url, path, threats, requestId, userAgent }) {
  const firstThreat = threats?.[0] || {};
  return {
    type: 'THREAT',
    detector: firstThreat.detector,
    severity: firstThreat.severity,
    reason: firstThreat.reason,
    target: firstThreat.field,
    ip,
    timestamp,
    method,
    url,
    path,
    requestId,
    userAgent,
    threats,
  };
}

function createBanEvent({ ip, timestamp, method, path, requestId, userAgent }) {
  return {
    type: 'BAN',
    ip,
    reason: 'Ban for suspicious activity',
    timestamp,
    method,
    path,
    requestId,
    userAgent,
  };
}

function createRateLimitEvent({ ip, timestamp, method, path, requestId, userAgent }) {
  return { type: 'RATE_LIMIT', ip, timestamp, method, path, requestId, userAgent };
}

function createStoreFailureEvent({
  ip,
  timestamp,
  error,
  mode,
  method,
  path,
  requestId,
  userAgent,
  module,
}) {
  return {
    type: 'STORE_FAILURE',
    module,
    ip,
    timestamp,
    reason: error && error.message ? error.message : String(error),
    mode,
    method,
    path,
    requestId,
    userAgent,
  };
}

module.exports = {
  createThreatEvent,
  createBanEvent,
  createRateLimitEvent,
  createStoreFailureEvent,
};
