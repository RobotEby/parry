'use strict';

const { DEFAULTS } = require('../../config/defaults');
const { analyzeRequest } = require('../core/engine');
const { RateLimiter } = require('../rate-limit/limiter');
const { ThreatLogger } = require('../logger/console-reporter');
const { EventBus, MemoryEventStore } = require('../events');
const { Metrics } = require('../observability');
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
  return createParry(options).middleware();
}

function createParry(options = {}) {
  const config = mergeConfig(options);
  const rateLimiter = new RateLimiter(config, config.store);
  const eventStore = new MemoryEventStore({ maxEvents: config.events.maxEvents });
  const eventBus = new EventBus({ eventStore });
  const metrics = new Metrics();
  const consoleReporter = new ThreatLogger(config.logThreats);

  eventBus.onThreat((event) => consoleReporter.log(event));
  eventBus.onThreat((event) => metrics.recordEvent(event));
  if (typeof config.onThreat === 'function') eventBus.onThreat(config.onThreat);
  if (typeof config.onEvent === 'function') eventBus.onThreat(config.onEvent);
  if (typeof config.onStoreError === 'function') {
    eventBus.onThreat((event) => {
      if (event.type !== 'STORE_ERROR') return;
      config.onStoreError(new Error(event.reason || 'Store error'), event);
    });
  }

  const eventReporter = createEventReporter(eventBus);
  const context = {
    config,
    rateLimiter,
    logger: eventReporter,
    store: rateLimiter.store,
    eventBus,
    eventStore,
    metrics,
    policies: config.policies,
  };

  const middleware = function Parry_DDoSMiddleware(req, res, next) {
    return handleRequest(req, res, next, context).catch(next);
  };
  Object.defineProperty(middleware, '__parryContext', {
    value: context,
    enumerable: false,
  });

  return {
    middleware() {
      return middleware;
    },
    eventBus,
    metrics,
    eventStore,
    store: rateLimiter.store,
    policies: config.policies,
    getContext() {
      return context;
    },
  };
}

async function handleRequest(req, res, next, context) {
  const { config, rateLimiter, logger, store, eventBus, metrics } = context;
  metrics.recordRequest('started');
  const ip = resolveClientIP(req);
  const timestamp = new Date().toISOString();
  const url = req.originalUrl || req.url;
  const requestId = resolveRequestId(req, res, config.requestId);
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
    requestId,
    userAgent: getHeader(req.headers || {}, 'user-agent'),
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
    eventBus,
  });
  attachParryRequestApi(req, bruteForceContext);
  req.parry.requestId = requestId;

  const bruteForce = await checkBruteForceBlock(bruteForceContext);
  if (bruteForce.blocked) {
    if (bruteForce.storeFailure) {
      return respond(res, bruteForce.statusCode, 'Rate limit store unavailable.');
    }

    const response = createBlockedResponse(bruteForce);
    setHeaders(res, response.headers);
    metrics.recordRequest('blocked');
    return res.status(response.statusCode).json(response.body);
  }

  const routeRateLimit = await checkRouteRateLimit({ policy, requestData, store, config, logger, eventBus, req, res });
  if (routeRateLimit?.blocked) {
    if (routeRateLimit.storeFailure) {
      return respond(res, routeRateLimit.statusCode, 'Rate limit store unavailable.');
    }

    setRateLimitHeaders(res, routeRateLimit.headerConfig, routeRateLimit.rateLimit);
    metrics.recordRequest('blocked');
    return respond(res, 429, 'Request limit reached. Please try again shortly.');
  }

  observeAuthenticationResult(bruteForceContext);

  const engineConfig = policy && policy.inheritGlobalRateLimit === false ? { ...config, rateLimit: false } : config;
  const decision = await analyzeRequest(requestData, { config: engineConfig, rateLimiter, logger });

  if (engineConfig.rateLimit && engineConfig.rateLimitConfig.headers && decision.rateLimit) {
    setRateLimitHeaders(res, engineConfig, decision.rateLimit);
  }

  if (!decision.blocked) {
    metrics.recordRequest('allowed');
    return next();
  }

  if (decision.event) eventBus.emitThreat({ ...decision.event, statusCode: decision.statusCode }, { req, res });
  metrics.recordRequest('blocked');

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

  for (const key of ['events', 'admin', 'requestId']) {
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
    emitPolicyEvent({ eventBus: context.eventBus, logger, event, req, res });

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
    requestId: requestData.requestId,
    userAgent: requestData.userAgent,
  };
}

function emitPolicyEvent({ eventBus, logger, event, req, res }) {
  if (eventBus && typeof eventBus.emitThreat === 'function') {
    eventBus.emitThreat(event, { req, res });
    return;
  }

  if (logger && typeof logger.log === 'function') logger.log(event);
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

function createEventReporter(eventBus) {
  return {
    log(event, context = {}) {
      return eventBus.emitThreat(event, context);
    },
    logStoreError(error, event = {}) {
      return eventBus.emitThreat(
        {
          ...event,
          type: 'STORE_ERROR',
          severity: event.severity || 'medium',
          action: 'error',
          reason: error && error.message ? error.message : String(error),
        },
        {}
      );
    },
    logHookError(error, event = {}) {
      return eventBus.emitThreat(
        {
          type: 'HOOK_ERROR',
          module: 'hook',
          severity: 'low',
          action: 'error',
          reason: error && error.message ? error.message : String(error),
          ip: event.ip,
          method: event.method,
          path: event.path,
          requestId: event.requestId,
          metadata: { sourceEventId: event.id, sourceType: event.type },
        },
        {}
      );
    },
  };
}

function resolveRequestId(req, res, config) {
  if (!config || config.enabled === false) return undefined;

  const headerName = config.header || 'x-request-id';
  const requestId = getHeader(req.headers || {}, headerName) || createRequestId();

  if (config.responseHeader) {
    res.setHeader(config.responseHeader, requestId);
  }

  return requestId;
}

function createRequestId() {
  return `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function getHeader(headers, name) {
  if (!headers || !name) return undefined;
  const lower = String(name).toLowerCase();
  const match = Object.keys(headers).find((key) => key.toLowerCase() === lower);
  return match ? headers[match] : undefined;
}

module.exports = { Parry_DDoS, createParry, mergeConfig };
