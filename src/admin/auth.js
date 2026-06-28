'use strict';

const { unauthorized } = require('./response');

function requireAdminAuth(options = {}) {
  return async function parryAdminAuth(req, res, next) {
    if (!options.requireAuth && typeof options.auth !== 'function') return next();

    if (typeof options.auth !== 'function') return unauthorized(res);

    try {
      const allowed = await options.auth(req);
      if (!allowed) return unauthorized(res);
      return next();
    } catch (_error) {
      return unauthorized(res);
    }
  };
}

module.exports = { requireAdminAuth };
