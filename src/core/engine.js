'use strict';

const {
  SQLInjectionDetector,
  XSSDetector,
  NoSQLDetector,
  HPPDetector,
  PrototypePollutionDetector,
  PathTraversalDetector,
  RequestShapeGuard,
} = require('../detectors');
const { safeStringify } = require('../utils/normalize');
const { severityForThreats } = require('./scoring');
const { createThreatEvent, createBanEvent, createRateLimitEvent } = require('./threat-event');

function analyzeRequest(requestData, context) {
  const { config, rateLimiter } = context;
  const timestamp = requestData.timestamp || new Date().toISOString();
  const rateLimit = config.rateLimit && rateLimiter ? rateLimiter.check(requestData.ip) : null;

  if (rateLimit?.banned) {
    return {
      allowed: false,
      blocked: true,
      reason: 'BAN',
      statusCode: 429,
      message: 'Too many suspicious requests. IP temporarily banned.',
      severity: 'high',
      detector: null,
      threats: [],
      event: createBanEvent({ ip: requestData.ip, timestamp }),
      rateLimit,
      responseExtra: { banExpiresAt: rateLimit.banExpiresAt },
    };
  }

  if (rateLimit?.limited) {
    return {
      allowed: false,
      blocked: true,
      reason: 'RATE_LIMIT',
      statusCode: 429,
      message: 'Request limit reached. Please try again shortly.',
      severity: 'medium',
      detector: null,
      threats: [],
      event: createRateLimitEvent({ ip: requestData.ip, timestamp }),
      rateLimit,
      responseExtra: {},
    };
  }

  const threats = [
    ...scanApplicationLayerGuards(requestData, config),
    ...scanTargets(requestData.targets || [], config),
  ];

  if (threats.length > 0) {
    if (config.rateLimit && rateLimiter) rateLimiter.recordSuspicious(requestData.ip);
    const normalizedThreats = enrichThreats(threats);

    const event = createThreatEvent({
      ip: requestData.ip,
      timestamp,
      method: requestData.method,
      url: requestData.url,
      threats: normalizedThreats,
    });

    return {
      allowed: false,
      blocked: true,
      reason: 'THREAT',
      statusCode: 400,
      message: 'Request blocked: malicious pattern detected.',
      severity: severityForThreats(normalizedThreats),
      detector: normalizedThreats[0].detector,
      threats: normalizedThreats,
      event,
      rateLimit,
      responseExtra: {
        threats: normalizedThreats.map(toResponseThreat),
      },
    };
  }

  return {
    allowed: true,
    blocked: false,
    reason: null,
    statusCode: null,
    message: null,
    severity: 'none',
    detector: null,
    threats: [],
    event: null,
    rateLimit,
    responseExtra: {},
  };
}

function scanApplicationLayerGuards(requestData, config) {
  const threats = [];
  const surfaces = {
    query: requestData.query || {},
    params: requestData.params || {},
    body: requestData.body,
  };

  if (config.requestShape?.enabled) {
    const hit = RequestShapeGuard.scan(surfaces, config.requestShape);
    if (hit) return [hit];
  }

  if (config.hpp?.enabled) {
    const hit = HPPDetector.scan(surfaces.query, config.hpp);
    if (hit) threats.push(hit);
  }

  if (config.prototypePollution?.enabled) {
    const hit = PrototypePollutionDetector.scan(surfaces);
    if (hit) threats.push(hit);
  }

  if (config.pathTraversal?.enabled) {
    const hit = PathTraversalDetector.scan(requestData.targets || []);
    if (hit) threats.push(hit);
  }

  return threats;
}

function scanTargets(targets, config) {
  const threats = [];

  for (const { label, value, stringValue } of targets) {
    const str = stringValue != null ? stringValue : safeStringify(value);

    if (config.sql) {
      const hit = SQLInjectionDetector.scan(str);
      if (hit) threats.push({ detector: 'SQL_INJECTION', field: label, pattern: hit });
    }

    if (config.xss) {
      const hit = XSSDetector.scan(str);
      if (hit) threats.push({ detector: 'XSS', field: label, pattern: hit });
    }

    if (config.nosql) {
      const hit = NoSQLDetector.scan(value);
      if (hit) threats.push({ detector: 'NOSQL_INJECTION', field: label, pattern: hit });
    }
  }

  return threats;
}

function enrichThreats(threats) {
  return threats.map((threat) => ({
    ...threat,
    severity: threat.severity || severityForThreats([threat]),
  }));
}

function toResponseThreat(threat) {
  const responseThreat = {
    detector: threat.detector,
    field: threat.field,
  };

  if (threat.reason) responseThreat.reason = threat.reason;
  return responseThreat;
}

module.exports = { analyzeRequest, scanTargets, scanApplicationLayerGuards };
