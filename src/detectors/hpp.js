'use strict';

const HPPDetector = {
  scan(query, options = {}) {
    if (!query || typeof query !== 'object') return null;

    const allowed = new Set(options.allowDuplicateParamsFor || []);

    try {
      for (const [key, value] of Object.entries(query)) {
        if (allowed.has(key)) continue;

        if (Array.isArray(value) && value.length > 1) {
          return {
            detector: 'HTTP_PARAMETER_POLLUTION',
            field: `query.${key}`,
            pattern: 'duplicate-query-param',
            reason: `Duplicate query parameter: ${key}`,
          };
        }
      }
    } catch (_) {
      return null;
    }

    return null;
  },
};

module.exports = { HPPDetector };
