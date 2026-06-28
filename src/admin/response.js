'use strict';

function json(res, statusCode, body) {
  return res.status(statusCode).json(body);
}

function ok(res, body) {
  return json(res, 200, body);
}

function unauthorized(res) {
  return json(res, 401, { error: true, message: 'Unauthorized' });
}

function notFound(res) {
  return json(res, 404, { error: true, message: 'Not found' });
}

module.exports = { json, ok, unauthorized, notFound };
