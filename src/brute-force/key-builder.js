'use strict';

const FORBIDDEN_SEGMENTS = new Set([
  'password',
  'pass',
  'token',
  'authorization',
  'cookie',
  'secret',
]);

function buildBruteForceKeys(policy, requestData) {
  const bruteForce = policy?.bruteForce || {};
  return buildKeys({
    policyName: policy.name,
    specs: bruteForce.keys || [],
    requestData,
    namespace: 'bf',
  });
}

function buildRouteRateLimitKey(policy, requestData) {
  const spec = policy?.rateLimit?.key || 'ip';
  const keys = buildKeys({
    policyName: policy.name,
    specs: [spec],
    requestData,
    namespace: 'route-rl',
  });

  return keys[0] || null;
}

function buildKeys({ policyName, specs, requestData, namespace }) {
  const result = [];
  for (const spec of specs) {
    const key = buildKey(policyName, spec, requestData, namespace);
    if (key) result.push(key);
  }
  return result;
}

function buildKey(policyName, spec, requestData, namespace) {
  if (typeof spec === 'function') {
    return buildCustomKey(policyName, spec, requestData, namespace);
  }

  const type = String(spec || '').trim();
  if (!type || containsForbiddenSegment(type)) return null;

  const parts = type
    .split('+')
    .map((part) => part.trim())
    .filter(Boolean);
  const values = [];

  for (const part of parts) {
    const value = resolveValue(part, requestData);
    if (!value) return null;
    values.push(value);
  }

  const normalizedValue = values.join(':');
  return createKey(namespace, policyName, type, normalizedValue);
}

function buildCustomKey(policyName, spec, requestData, namespace) {
  const value = spec(requestData);
  if (value == null) return null;

  if (typeof value === 'object') {
    const type = sanitizeType(value.type || value.keyType || spec.name || 'custom');
    const normalizedValue = normalizeScalar(value.value);
    if (!normalizedValue) return null;
    return createKey(namespace, policyName, type, normalizedValue);
  }

  const normalizedValue = normalizeScalar(value);
  if (!normalizedValue) return null;
  return createKey(namespace, policyName, sanitizeType(spec.name || 'custom'), normalizedValue);
}

function createKey(namespace, policyName, type, value) {
  const keyType = sanitizeType(type);
  return {
    type: keyType,
    value,
    key: `${namespace}:${sanitizeType(policyName)}:${keyType}:${value}`,
  };
}

function resolveValue(path, requestData) {
  switch (path) {
    case 'ip':
      return normalizeScalar(requestData.ip);
    case 'userAgent':
      return normalizeScalar(
        requestData.headers?.['user-agent'] || requestData.headers?.['User-Agent']
      );
    case 'method':
      return normalizeScalar(requestData.method).toUpperCase();
    case 'path':
      return normalizePath(requestData.path || requestData.url);
    default:
      return resolvePathValue(path, requestData);
  }
}

function resolvePathValue(path, requestData) {
  if (containsForbiddenSegment(path)) return null;

  const segments = String(path || '').split('.');
  if (segments.length < 2) return null;

  let current = requestData[segments[0]];
  for (const segment of segments.slice(1)) {
    if (current == null || typeof current !== 'object') return null;
    current = current[segment];
  }

  return normalizeValueForPath(path, current);
}

function normalizeValueForPath(path, value) {
  const normalized = normalizeScalar(value);
  if (!normalized) return null;

  if (/(email|username|login)$/i.test(path)) return normalized.toLowerCase();
  return normalized;
}

function normalizeScalar(value) {
  if (value == null) return null;
  if (Array.isArray(value)) return normalizeScalar(value[0]);
  if (typeof value === 'object') return null;

  const normalized = String(value).trim();
  return normalized.length > 0 ? normalized : null;
}

function normalizePath(value) {
  const normalized = normalizeScalar(value) || '/';
  const queryIndex = normalized.indexOf('?');
  return queryIndex === -1 ? normalized : normalized.slice(0, queryIndex);
}

function containsForbiddenSegment(path) {
  return String(path || '')
    .split(/[.+]/)
    .some((segment) => FORBIDDEN_SEGMENTS.has(segment.toLowerCase()));
}

function sanitizeType(value) {
  return String(value || 'unknown')
    .trim()
    .replace(/[^a-zA-Z0-9_.+-]/g, '-');
}

module.exports = {
  buildBruteForceKeys,
  buildRouteRateLimitKey,
  buildKey,
  resolveValue,
};
