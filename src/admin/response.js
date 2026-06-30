'use strict';

function json(res, statusCode, body) {
  return res.status(statusCode).json(body);
}

function ok(res, body) {
  return json(res, 200, body);
}

function unauthorized(res) {
  return json(res, 401, {
    error: {
      code: 'ADMIN_UNAUTHORIZED',
      message: 'Admin API authentication required',
    },
    code: 'ADMIN_UNAUTHORIZED',
    message: 'Admin API authentication required',
  });
}

function forbidden(res) {
  return json(res, 403, {
    error: {
      code: 'ADMIN_FORBIDDEN',
      message: 'Admin API access denied',
    },
    code: 'ADMIN_FORBIDDEN',
    message: 'Admin API access denied',
  });
}

function notFound(res) {
  return json(res, 404, {
    error: 'Not found',
    code: 'ADMIN_NOT_FOUND',
    message: 'Not found',
  });
}

module.exports = { json, ok, unauthorized, forbidden, notFound };
