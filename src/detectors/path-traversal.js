'use strict';

const { decodeUrlValue } = require('../utils/decode');

const TRAVERSAL_PATTERN = /(^|[\\/])\.\.([\\/]|$)/;

const PathTraversalDetector = {
  scan(targets) {
    for (const target of targets || []) {
      const hit = scanTarget(target);
      if (hit) return hit;
    }
    return null;
  },
};

function scanTarget(target) {
  if (!target || !isRequestValueTarget(target.label)) return null;

  const strings = collectStrings(target.value, target.label);
  for (const item of strings) {
    const normalized = normalizePathCandidate(item.value);
    if (TRAVERSAL_PATTERN.test(normalized)) {
      return {
        detector: 'PATH_TRAVERSAL',
        field: item.label,
        pattern: 'path-traversal-segment',
        reason: 'Path traversal sequence detected',
      };
    }
  }

  return null;
}

function isRequestValueTarget(label) {
  return (
    label === 'body' ||
    label.startsWith('body.') ||
    label.startsWith('query.') ||
    label.startsWith('params.')
  );
}

function collectStrings(value, label, seen = new WeakSet()) {
  if (typeof value === 'string') return [{ label, value }];
  if (!value || typeof value !== 'object') return [];
  if (seen.has(value)) return [];
  seen.add(value);

  const strings = [];
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      strings.push(...collectStrings(value[i], `${label}[${i}]`, seen));
    }
    return strings;
  }

  try {
    for (const [key, child] of Object.entries(value)) {
      strings.push(...collectStrings(child, `${label}.${key}`, seen));
    }
  } catch (_) {
    // Ignore objects that cannot expose enumerable values.
  }

  return strings;
}

function normalizePathCandidate(value) {
  return decodeUrlValue(value, 2).replace(/\\/g, '/');
}

module.exports = { PathTraversalDetector };
