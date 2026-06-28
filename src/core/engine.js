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
const {
  createThreatEvent,
  createBanEvent,
  createRateLimitEvent,
  createStoreFailureEvent,
} = require('./threat-event');

async function analyzeRequest(requestData, context) {
  const { config, rateLimiter, logger } = context;
  const timestamp = requestData.timestamp || new Date().toISOString();
  const rateLimit = await checkRateLimit(requestData, { config, rateLimiter, logger, timestamp });

  if (rateLimit?.storeFailure && rateLimit.failClosed) {
    return {
      allowed: false,
      blocked: true,
      reason: 'STORE_FAILURE',
      statusCode: 503,
      message: 'Rate limit store unavailable.',
      severity: 'medium',
      detector: null,
      threats: [],
      event: rateLimit.event,
      rateLimit: null,
      responseExtra: {},
    };
  }

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
      event: createBanEvent(createRequestEventContext(requestData, timestamp)),
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
      event: createRateLimitEvent(createRequestEventContext(requestData, timestamp)),
      rateLimit,
      responseExtra: {},
    };
  }

  const threats = [
    ...scanApplicationLayerGuards(requestData, config),
    ...scanTargets(requestData.targets || [], config),
  ];

  if (threats.length > 0) {
    if (config.rateLimit && rateLimiter) {
      await recordSuspicious(requestData, { config, rateLimiter, logger, timestamp });
    }
    const normalizedThreats = enrichThreats(threats);

    const event = createThreatEvent({
      ip: requestData.ip,
      timestamp,
      method: requestData.method,
      url: requestData.url,
      path: requestData.path,
      requestId: requestData.requestId,
      userAgent: requestData.userAgent,
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

async function checkRateLimit(requestData, context) {
  const { config, rateLimiter, logger, timestamp } = context;
  if (!config.rateLimit || !rateLimiter) return null;

  try {
    return await rateLimiter.check(requestData.ip);
  } catch (error) {
    const mode = config.storeFailureMode === 'fail-closed' ? 'fail-closed' : 'fail-open';
    const event = createStoreFailureEvent({
      ...createRequestEventContext(requestData, timestamp),
      error,
      mode,
      module: 'rate-limit',
    });
    if (logger && typeof logger.logStoreError === 'function') logger.logStoreError(error, event);

    if (mode === 'fail-open') return null;

    return { storeFailure: true, failClosed: true, event };
  }
}

async function recordSuspicious(requestData, context) {
  const { config, rateLimiter, logger, timestamp } = context;

  try {
    const result = await rateLimiter.recordSuspicious(requestData.ip);
    if (result?.banned && logger && typeof logger.log === 'function') {
      logger.log({
        type: 'TEMPORARY_BAN_CREATED',
        module: 'rate-limit',
        severity: 'high',
        action: 'created',
        reason: 'Suspicious activity threshold reached',
        ...createRequestEventContext(requestData, timestamp),
        metadata: {
          banExpiresAt: result.banExpiresAt,
        },
      });
    }
  } catch (error) {
    const mode = config.storeFailureMode === 'fail-closed' ? 'fail-closed' : 'fail-open';
    const event = createStoreFailureEvent({
      ...createRequestEventContext(requestData, timestamp),
      error,
      mode,
      module: 'rate-limit',
    });
    if (logger && typeof logger.logStoreError === 'function') logger.logStoreError(error, event);
  }
}

function createRequestEventContext(requestData, timestamp) {
  return {
    ip: requestData.ip,
    timestamp,
    method: requestData.method,
    path: requestData.path,
    requestId: requestData.requestId,
    userAgent: requestData.userAgent,
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
