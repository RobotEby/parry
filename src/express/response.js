'use strict';

function setRateLimitHeaders(res, config, rateLimitResult) {
  const limit = config.rateLimitConfig?.maxRequests || config.maxRequests;
  res.setHeader('X-RateLimit-Limit', limit);
  res.setHeader('X-RateLimit-Remaining', rateLimitResult.remaining);
  res.setHeader('X-RateLimit-Reset', rateLimitResult.resetAt);
}

function respond(res, status, message, extra = {}) {
  return res.status(status).json({ error: true, message, ...extra });
}

module.exports = { setRateLimitHeaders, respond };
