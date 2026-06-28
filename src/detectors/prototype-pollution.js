'use strict';

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const PrototypePollutionDetector = {
  scan(surfaces) {
    const seen = new WeakSet();

    for (const [surface, value] of Object.entries(surfaces || {})) {
      const hit = scanValue(value, surface, seen);
      if (hit) return hit;
    }

    return null;
  },
};

function scanValue(value, path, seen) {
  if (!value || typeof value !== 'object') return null;
  if (seen.has(value)) return null;
  seen.add(value);

  let keys;
  try {
    keys = Reflect.ownKeys(value);
  } catch (_) {
    return null;
  }

  for (const key of keys) {
    if (typeof key !== 'string') continue;

    const childPath = Array.isArray(value) ? `${path}[${key}]` : `${path}.${key}`;
    if (DANGEROUS_KEYS.has(key)) {
      return {
        detector: 'PROTOTYPE_POLLUTION',
        field: childPath,
        pattern: key,
        reason: `Dangerous object key: ${key}`,
      };
    }

    const nested = scanValue(value[key], childPath, seen);
    if (nested) return nested;
  }

  return null;
}

module.exports = { PrototypePollutionDetector };
