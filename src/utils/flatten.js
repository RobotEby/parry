'use strict';

function flattenObject(obj, prefix, maxDepth, depth = 0, seen = new WeakSet()) {
  if (depth >= maxDepth) return [];
  if (!obj || typeof obj !== 'object') return [];
  if (seen.has(obj)) return [];
  seen.add(obj);

  const targets = [];
  try {
    for (const [key, val] of Object.entries(obj)) {
      const path = `${prefix}.${key}`;
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        targets.push({ label: path, value: val });
        targets.push(...flattenObject(val, path, maxDepth, depth + 1, seen));
      } else {
        targets.push({ label: path, value: val });
      }
    }
  } catch (_) {
    return targets;
  }

  return targets;
}

module.exports = { flattenObject };
