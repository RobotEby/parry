'use strict';

const { getHeader } = require('../../../express/ip-resolver');

function readHeader(req, name) {
  return getHeader(req.headers || {}, name);
}

function hasHeader(req, name) {
  const value = readHeader(req, name);
  return typeof value === 'string' && value.length > 0;
}

function headerEquals(req, name, expected) {
  const actual = readHeader(req, name);
  return String(actual || '') === String(expected || '');
}

function sanitizeHeaderValue(value, maxLength = 200) {
  return String(value || '')
    .replace(/[\r\n]/g, ' ')
    .trim()
    .slice(0, maxLength);
}

function parseRoles(value) {
  return String(value || '')
    .split(',')
    .map((role) => sanitizeHeaderValue(role, 80))
    .filter(Boolean);
}

module.exports = {
  readHeader,
  hasHeader,
  headerEquals,
  sanitizeHeaderValue,
  parseRoles,
};
