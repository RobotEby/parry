'use strict';

function flattenObject(obj, prefix, maxDepth, depth = 0) {
  if (depth >= maxDepth) return [];

  const targets = [];
  for (const [key, val] of Object.entries(obj)) {
    const path = `${prefix}.${key}`;
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      targets.push({ label: path, value: val });
      targets.push(...flattenObject(val, path, maxDepth, depth + 1));
    } else {
      targets.push({ label: path, value: val });
    }
  }

  return targets;
}

module.exports = { flattenObject };
