'use strict';

const { getClientIp } = require('../../../express/ip-resolver');

function success(req, strategy, details = {}, options = {}) {
  const ip = details.ip || getClientIp(req, options);

  return {
    ok: true,
    admin: {
      authenticated: true,
      strategy,
      subject: details.subject || strategy,
      email: details.email || null,
      roles: Array.isArray(details.roles) ? details.roles : [],
      ip,
    },
  };
}

function unauthorized() {
  return {
    ok: false,
    statusCode: 401,
    code: 'ADMIN_UNAUTHORIZED',
    message: 'Admin API authentication required',
  };
}

function forbidden() {
  return {
    ok: false,
    statusCode: 403,
    code: 'ADMIN_FORBIDDEN',
    message: 'Admin API access denied',
  };
}

module.exports = { success, unauthorized, forbidden };
