'use strict';

const RequestShapeGuard = {
  scan(surfaces, options) {
    const limits = {
      maxDepth: options.maxDepth,
      maxKeys: options.maxKeys,
      maxArrayLength: options.maxArrayLength,
      maxStringLength: options.maxStringLength,
    };
    const state = { keyCount: 0, seen: new WeakSet() };

    for (const [surface, value] of Object.entries(surfaces || {})) {
      const hit = scanValue(value, surface, 0, limits, state);
      if (hit) return hit;
    }

    return null;
  },
};

function scanValue(value, path, depth, limits, state) {
  if (typeof value === 'string' && value.length > limits.maxStringLength) {
    return shapeThreat(path, 'maxStringLength', `String length exceeds ${limits.maxStringLength}`);
  }

  if (!value || typeof value !== 'object') return null;
  if (state.seen.has(value)) return null;
  state.seen.add(value);

  if (depth > limits.maxDepth) {
    return shapeThreat(path, 'maxDepth', `Object depth exceeds ${limits.maxDepth}`);
  }

  if (Array.isArray(value)) {
    if (value.length > limits.maxArrayLength) {
      return shapeThreat(path, 'maxArrayLength', `Array length exceeds ${limits.maxArrayLength}`);
    }

    for (let i = 0; i < value.length; i++) {
      const hit = scanValue(value[i], `${path}[${i}]`, depth + 1, limits, state);
      if (hit) return hit;
    }
    return null;
  }

  let entries;
  try {
    entries = Object.entries(value);
  } catch (_) {
    return null;
  }

  state.keyCount += entries.length;
  if (state.keyCount > limits.maxKeys) {
    return shapeThreat(path, 'maxKeys', `Object key count exceeds ${limits.maxKeys}`);
  }

  for (const [key, child] of entries) {
    const hit = scanValue(child, `${path}.${key}`, depth + 1, limits, state);
    if (hit) return hit;
  }

  return null;
}

function shapeThreat(field, pattern, reason) {
  return {
    detector: 'REQUEST_SHAPE',
    field,
    pattern,
    reason,
  };
}

module.exports = { RequestShapeGuard };
