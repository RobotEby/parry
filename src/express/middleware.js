'use strict';

const { DEFAULTS } = require('../../config/defaults');
const { analyzeRequest } = require('../core/engine');
const { RateLimiter } = require('../rate-limit/limiter');
const { ThreatLogger } = require('../logger/console-reporter');
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
    return handleRequest(req, res, next, { config, rateLimiter, logger }).catch(next);
  };
}

async function handleRequest(req, res, next, context) {
  const { config, rateLimiter, logger } = context;
  const ip = resolveClientIP(req);
  const timestamp = new Date().toISOString();
  const requestData = {
    ip,
    timestamp,
    method: req.method,
    url: req.originalUrl || req.url,
    query: req.query || {},
    params: req.params || {},
    body: req.body,
    targets: collectRequestTargets(req, config.maxObjectDepth),
  };

  const decision = await analyzeRequest(requestData, { config, rateLimiter, logger });

  if (config.rateLimit && config.rateLimitConfig.headers && decision.rateLimit) {
    setRateLimitHeaders(res, config, decision.rateLimit);
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

module.exports = { Parry_DDoS };
