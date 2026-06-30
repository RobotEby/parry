'use strict';

const { SQL_PATTERNS } = require('../../constants/patterns');
const { decodeSqlValue } = require('../utils/decode');

const SQLInjectionDetector = {
  /** @param {string} value @returns {string|null} */
  scan(value) {
    if (typeof value !== 'string' || value.trim() === '') return null;
    const decoded = decodeSqlValue(value);
    for (const pattern of SQL_PATTERNS) {
      if (pattern.test(decoded)) return pattern.toString();
    }
    return null;
  },
};

module.exports = { SQLInjectionDetector };
