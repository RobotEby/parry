'use strict';

function setRateLimitHeaders(res, config, rateLimitResult) {
  res.setHeader('X-RateLimit-Limit', config.maxRequests);
  res.setHeader('X-RateLimit-Remaining', rateLimitResult.remaining);
  res.setHeader('X-RateLimit-Reset', rateLimitResult.resetAt);
}

function respond(res, status, message, extra = {}) {
  return res.status(status).json({ error: true, message, ...extra });
}

module.exports = { setRateLimitHeaders, respond };
