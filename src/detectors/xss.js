'use strict';

const { XSS_PATTERNS } = require('../../constants/patterns');
const { decodeXssValue } = require('../utils/decode');

const XSSDetector = {
  /** @param {string} value @returns {string|null} */
  scan(value) {
    if (typeof value !== 'string' || value.trim() === '') return null;
    const decoded = decodeXssValue(value);
    for (const pattern of XSS_PATTERNS) {
      if (pattern.test(decoded)) return pattern.toString();
    }
    return null;
  },
};

module.exports = { XSSDetector };
