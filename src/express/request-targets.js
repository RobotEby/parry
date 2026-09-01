'use strict';

const { normalizeTarget } = require('../utils/normalize');

function collectRequestTargets(req, options = {}) {
  const targets = [];
  const headers = req.headers || {};
  const maxDepth = typeof options === 'number' ? options : (options.maxObjectDepth ?? 8);
  const headersToScan =
    typeof options === 'number' || !options.headers
      ? ['user-agent', 'referer', 'x-forwarded-for', 'cookie']
      : options.headers.scan;
  const seen = new WeakSet();

  const add = (label, value) => {
    if (value == null) return;
    const type = typeof value;
    if (type === 'string' || type === 'number' || type === 'boolean' || type === 'bigint') {
      targets.push(normalizeTarget({ label, value }));
    }
  };

  const collect = (value, label, depth) => {
    if (value == null || typeof value !== 'object') return add(label, value);
    if (depth > maxDepth || seen.has(value)) return;
    seen.add(value);

    for (const [key, child] of Object.entries(value)) {
      collect(child, Array.isArray(value) ? `${label}[${key}]` : `${label}.${key}`, depth + 1);
    }
  };

  collect(req.query || {}, 'query', 0);
  collect(req.params || {}, 'params', 0);
  collect(req.body, 'body', 0);

  for (const header of headersToScan || []) {
    const key = Object.keys(headers).find((name) => name.toLowerCase() === header);
    if (key) collect(headers[key], `header.${header}`, 0);
  }

  return targets;
}

module.exports = { collectRequestTargets };
