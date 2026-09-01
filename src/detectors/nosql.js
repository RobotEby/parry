'use strict';

const {
  NOSQL_DANGEROUS_OPERATORS,
  NOSQL_SUSPICIOUS_OPERATORS,
  NOSQL_STRING_PATTERNS,
} = require('../../constants/patterns');

const NoSQLDetector = {
  /** @param {*} value @returns {string|null} */
  scan(value, options = {}) {
    return this.inspect(value, options)?.pattern || null;
  },

  inspect(value, options = {}) {
    const rootPath = options.rootPath || 'value';
    const allowedOperators = options.allowedOperators || {};
    if (value !== null && typeof value === 'object') {
      return _scanObject(value, rootPath, allowedOperators);
    }
    if (typeof value === 'string') return _scanString(value, rootPath, allowedOperators);
    return null;
  },
};

function _scanObject(obj, path, allowedOperators, depth = 0, seen = new WeakSet()) {
  if (depth > 8 || seen.has(obj)) return null;
  seen.add(obj);
  for (const key of Object.keys(obj)) {
    if (NOSQL_DANGEROUS_OPERATORS.has(key)) {
      return { pattern: `Operador perigoso: ${key}`, path: `${path}.${key}` };
    }
    if (NOSQL_SUSPICIOUS_OPERATORS.has(key) && !isAllowed(path, key, allowedOperators)) {
      return { pattern: `Operador suspeito: ${key}`, path: `${path}.${key}` };
    }
    const val = obj[key];
    const childPath = Array.isArray(obj) ? `${path}[${key}]` : `${path}.${key}`;
    if (val && typeof val === 'object') {
      const nested = _scanObject(val, childPath, allowedOperators, depth + 1, seen);
      if (nested) return nested;
    }
    if (typeof val === 'string') {
      const hit = _scanString(val, childPath, allowedOperators);
      if (hit) return hit;
    }
  }
  return null;
}

function _scanString(value, path, allowedOperators) {
  if (!value || value.trim() === '') return null;
  if (value.trim().startsWith('{') || value.trim().startsWith('[')) {
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === 'object') {
        const hit = _scanObject(parsed, path, allowedOperators);
        if (hit) return hit;
      }
    } catch (_) {
      // Non-JSON strings are checked by the bounded patterns below.
    }
  }
  for (const pattern of NOSQL_STRING_PATTERNS) {
    if (pattern.test(value)) return { pattern: pattern.toString(), path };
  }
  return null;
}

function isAllowed(path, operator, allowedOperators) {
  return Array.isArray(allowedOperators[path]) && allowedOperators[path].includes(operator);
}

module.exports = { NoSQLDetector };
