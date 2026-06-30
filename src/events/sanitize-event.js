'use strict';

const SENSITIVE_KEYS = new Set([
  'authorization',
  'cookie',
  'credentials',
  'password',
  'secret',
  'token',
]);

function sanitizeEvent(value) {
  return sanitizeValue(value, new WeakSet());
}

function sanitizeValue(value, seen) {
  if (value == null) return value;
  if (typeof value !== 'object') return value;
  if (seen.has(value)) return '[Circular]';
  seen.add(value);

  if (Array.isArray(value)) return value.map((item) => sanitizeValue(item, seen));

  const output = {};
  for (const [key, entry] of Object.entries(value)) {
    if (isSensitiveKey(key)) {
      output[key] = '[REDACTED]';
      continue;
    }

    if (key === 'body' || key === 'rawBody') {
      output[key] = '[REDACTED]';
      continue;
    }

    output[key] = sanitizeValue(entry, seen);
  }

  return output;
}

function isSensitiveKey(key) {
  const normalized = String(key || '').toLowerCase();
  return [...SENSITIVE_KEYS].some((sensitive) => normalized.includes(sensitive));
}

function sanitizeUserAgent(value) {
  if (!value) return undefined;
  return String(value)
    .replace(/[\r\n]/g, ' ')
    .slice(0, 200);
}

module.exports = { sanitizeEvent, sanitizeUserAgent, isSensitiveKey };
