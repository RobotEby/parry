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
  const rateLimiter = new RateLimiter(config);
  const logger = new ThreatLogger(config.logThreats);

  return function Parry_DDoSMiddleware(req, res, next) {
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

    const decision = analyzeRequest(requestData, { config, rateLimiter });

    if (config.rateLimit && decision.rateLimit) {
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
  };
}

function mergeConfig(options) {
  const config = { ...DEFAULTS, ...options };

  for (const key of ['hpp', 'prototypePollution', 'pathTraversal', 'requestShape']) {
    config[key] = {
      ...DEFAULTS[key],
      ...(options[key] || {}),
    };
  }

  return config;
}

module.exports = { Parry_DDoS };
