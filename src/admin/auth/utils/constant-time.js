'use strict';

const crypto = require('crypto');

function safeCompare(expected, actual) {
  if (typeof expected !== 'string' || typeof actual !== 'string') return false;
  if (!expected || !actual) return false;

  const expectedHash = hash(expected);
  const actualHash = hash(actual);
  return crypto.timingSafeEqual(expectedHash, actualHash);
}

function hash(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

module.exports = { safeCompare };
