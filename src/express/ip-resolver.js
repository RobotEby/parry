'use strict';

function resolveClientIP(req) {
  const headers = req.headers || {};
  return (
    (headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    req.ip ||
    'unknown'
  );
}

module.exports = { resolveClientIP };
