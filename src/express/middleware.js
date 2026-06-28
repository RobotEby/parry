'use strict';

const { DEFAULTS } = require('../../config/defaults');
const { analyzeRequest } = require('../core/engine');
const { RateLimiter } = require('../rate-limit/limiter');
const { ThreatLogger } = require('../logger/console-reporter');
const { buildPolicies, findMatchingPolicy } = require('../policies');
const {
  attachParryRequestApi,
  buildRouteRateLimitKey,
  checkBruteForceBlock,
  createBlockedResponse,
  createBruteForceContext,
  observeAuthenticationResult,
} = require('../brute-force');
const { resolveClientIP } = require('./ip-resolver');
const { collectRequestTargets } = require('./request-targets');
const { setRateLimitHeaders, respond } = require('./response');

/**
 * Detects SQL Injection, XSS and NoSQL Injection in real-time.
 * Applies intelligent Rate Limiting with automatic banning for suspicious behavior.
 *
 * @param {import('../../types/index').Parry_DDoSOptions} options
 * @returns {import('express').RequestHandler}
 */
function Parry_DDoS(options = {}) {
  const config = mergeConfig(options);
  const rateLimiter = new RateLimiter(config, config.store);
  const logger = new ThreatLogger(config.logThreats);

  return function Parry_DDoSMiddleware(req, res, next) {
    return handleRequest(req, res, next, { config, rateLimiter, logger, store: rateLimiter.store }).catch(next);
  };
}

async function handleRequest(req, res, next, context) {
  const { config, rateLimiter, logger, store } = context;
  const ip = resolveClientIP(req);
  const timestamp = new Date().toISOString();
  const url = req.originalUrl || req.url;
  const requestData = {
    ip,
    timestamp,
    method: req.method,
    url,
    path: stripQuery(url || '/'),
    headers: req.headers || {},
    query: req.query || {},
    params: req.params || {},
    body: req.body,
    targets: collectRequestTargets(req, config.maxObjectDepth),
  };

  const policy = findMatchingPolicy(config.policies, requestData);
  const bruteForceContext = createBruteForceContext({
    policy,
    requestData,
    req,
    res,
    store,
    config,
    logger,
  });
  attachParryRequestApi(req, bruteForceContext);

  const bruteForce = await checkBruteForceBlock(bruteForceContext);
  if (bruteForce.blocked) {
    if (bruteForce.storeFailure) {
      return respond(res, bruteForce.statusCode, 'Rate limit store unavailable.');
    }

    const response = createBlockedResponse(bruteForce);
    setHeaders(res, response.headers);
    return res.status(response.statusCode).json(response.body);
  }

  const routeRateLimit = await checkRouteRateLimit({ policy, requestData, store, config, logger, req, res });
  if (routeRateLimit?.blocked) {
    if (routeRateLimit.storeFailure) {
      return respond(res, routeRateLimit.statusCode, 'Rate limit store unavailable.');
    }

    setRateLimitHeaders(res, routeRateLimit.headerConfig, routeRateLimit.rateLimit);
    return respond(res, 429, 'Request limit reached. Please try again shortly.');
  }

  observeAuthenticationResult(bruteForceContext);

  const engineConfig = policy && policy.inheritGlobalRateLimit === false ? { ...config, rateLimit: false } : config;
  const decision = await analyzeRequest(requestData, { config: engineConfig, rateLimiter, logger });

  if (engineConfig.rateLimit && engineConfig.rateLimitConfig.headers && decision.rateLimit) {
    setRateLimitHeaders(res, engineConfig, decision.rateLimit);
  }

  if (!decision.blocked) return next();

  if (decision.event) logger.log(decision.event);

  if (decision.reason === 'THREAT' && config.onThreat) {
    try {
      config.onThreat(decision.event, req, res);
    } catch (error) {
      logger.logHookError(error, decision.event);
    }
  }

  return respond(res, decision.statusCode, decision.message, decision.responseExtra);
}

function mergeConfig(options) {
  const config = { ...DEFAULTS, ...options };

  for (const key of ['hpp', 'prototypePollution', 'pathTraversal', 'requestShape']) {
    config[key] = {
      ...DEFAULTS[key],
      ...(options[key] || {}),
    };
  }

  config.rateLimitConfig = normalizeRateLimitConfig(config, options);
  config.rateLimit = config.rateLimitConfig.enabled;
  config.maxRequests = config.rateLimitConfig.maxRequests;
  config.windowMs = config.rateLimitConfig.windowMs;
  config.storeFailureMode = options.storeFailureMode === 'fail-closed' ? 'fail-closed' : 'fail-open';
  config.policies = buildPolicies(options);
  config.bruteForce =
    options.bruteForce === false
      ? false
      : {
          ...DEFAULTS.bruteForce,
          ...(options.bruteForce || {}),
        };

  return config;
}

function normalizeRateLimitConfig(config, options) {
  const rateLimitOption = options.rateLimit;
  const nested = rateLimitOption && typeof rateLimitOption === 'object' ? rateLimitOption : {};

  return {
    enabled: rateLimitOption !== false && nested.enabled !== false,
    maxRequests: nested.max || nested.maxRequests || config.maxRequests,
    windowMs: nested.windowMs || config.windowMs,
    headers: nested.headers !== false,
  };
}

async function checkRouteRateLimit(context) {
  const { policy, requestData, store, config, logger, req, res } = context;
  if (!policy?.rateLimit?.enabled) return null;

  const key = buildRouteRateLimitKey(policy, requestData);
  if (!key) return null;

  try {
    const counter = await store.incrementCounter(key.key, policy.rateLimit.windowMs, {
      policyName: policy.name,
      keyType: key.type,
      reason: 'route_rate_limit',
    });

    const remaining = Math.max(0, policy.rateLimit.max - counter.count);
    const rateLimit = {
      limited: counter.count > policy.rateLimit.max,
      banned: false,
      remaining,
      resetAt: counter.resetAt,
      banExpiresAt: null,
    };

    if (!rateLimit.limited) return { blocked: false, rateLimit };

    const event = createRouteRateLimitEvent({ policy, requestData, keyTypes: [key.type] });
    emitPolicyEvent({ config, logger, event, req, res });

    return {
      blocked: true,
      rateLimit,
      headerConfig: {
        maxRequests: policy.rateLimit.max,
        rateLimitConfig: { maxRequests: policy.rateLimit.max },
      },
    };
  } catch (error) {
    const mode = config.storeFailureMode === 'fail-closed' ? 'fail-closed' : 'fail-open';
    const event = {
      type: 'STORE_FAILURE',
      module: 'route-rate-limit',
      policyName: policy.name,
      ip: requestData.ip,
      method: requestData.method,
      path: requestData.path,
      timestamp: new Date().toISOString(),
      reason: error && error.message ? error.message : String(error),
      mode,
    };
    if (logger && typeof logger.logStoreError === 'function') logger.logStoreError(error, event);
    if (mode === 'fail-open') return null;
    return { blocked: true, storeFailure: true, statusCode: 503, event };
  }
}

function createRouteRateLimitEvent({ policy, requestData, keyTypes }) {
  return {
    type: 'ROUTE_RATE_LIMIT_EXCEEDED',
    module: 'route-policy',
    detector: 'ROUTE_RATE_LIMIT',
    policyName: policy.name,
    ip: requestData.ip,
    method: requestData.method,
    path: requestData.path,
    keyTypes,
    severity: 'medium',
    reason: 'route_rate_limit_exceeded',
    timestamp: new Date().toISOString(),
    requestId: requestData.headers?.['x-request-id'],
    userAgent: requestData.headers?.['user-agent'],
  };
}

function emitPolicyEvent({ config, logger, event, req, res }) {
  if (logger && typeof logger.log === 'function') logger.log(event);

  if (config.onThreat) {
    try {
      config.onThreat(event, req, res);
    } catch (error) {
      if (logger && typeof logger.logHookError === 'function') logger.logHookError(error, event);
    }
  }
}

function setHeaders(res, headers) {
  for (const [key, value] of Object.entries(headers || {})) {
    res.setHeader(key, value);
  }
}

function stripQuery(value) {
  const path = String(value || '/');
  const index = path.indexOf('?');
  return index === -1 ? path : path.slice(0, index);
}

module.exports = { Parry_DDoS };
