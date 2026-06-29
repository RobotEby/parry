'use strict';

function json(res, statusCode, body) {
  return res.status(statusCode).json(body);
}

function ok(res, body) {
  return json(res, 200, body);
}

function unauthorized(res) {
  return json(res, 401, {
    error: 'Unauthorized',
    code: 'ADMIN_UNAUTHORIZED',
    message: 'Unauthorized',
  });
}

function notFound(res) {
  return json(res, 404, {
    error: 'Not found',
    code: 'ADMIN_NOT_FOUND',
    message: 'Not found',
  });
}

module.exports = { json, ok, unauthorized, notFound };
