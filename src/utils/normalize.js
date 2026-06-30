'use strict';

function safeStringify(value) {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

function normalizeTarget(target) {
  return {
    label: target.label,
    value: target.value,
    stringValue: safeStringify(target.value),
  };
}

module.exports = { safeStringify, normalizeTarget };
