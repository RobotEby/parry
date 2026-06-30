'use strict';

const { sanitizeEvent } = require('../events/sanitize-event');

function normalizeAdminBanEntry(entry = {}, source = 'ban', now = Date.now()) {
  const sanitized = sanitizeEvent(entry) || {};
  const metadata = sanitizeEvent(sanitized.metadata || {}) || {};
  const rawKey = String(sanitized.key || 'unknown');
  const type = inferType(rawKey, metadata, source);
  const expiresAtMs = pickNumber(
    sanitized.expiresAt,
    sanitized.banExpiresAt,
    sanitized.blockExpiresAt
  );
  const ttlMs =
    pickNumber(sanitized.ttlMs) ?? (expiresAtMs ? Math.max(0, expiresAtMs - now) : null);
  const createdAtMs =
    pickNumber(sanitized.createdAt, metadata.createdAt) ??
    (expiresAtMs && ttlMs ? expiresAtMs - ttlMs : now);

  return {
    key: normalizePublicKey(rawKey, type),
    type,
    reason: String(metadata.reason || sanitized.reason || defaultReason(source)),
    policyName: metadata.policyName || sanitized.policyName || inferPolicyName(rawKey) || null,
    createdAt: toIso(createdAtMs),
    expiresAt: expiresAtMs ? toIso(expiresAtMs) : null,
    ttlMs,
  };
}

async function listAdminBanEntries(store, options = {}) {
  const now = Date.now();
  const bans = store && typeof store.listBans === 'function' ? await store.listBans(options) : [];
  const blocks =
    store && typeof store.listBlocks === 'function' ? await store.listBlocks(options) : [];

  return [
    ...bans.map((entry) => normalizeAdminBanEntry(entry, 'ban', now)),
    ...blocks.map((entry) => normalizeAdminBanEntry(entry, 'block', now)),
  ];
}

function inferType(key, metadata, source) {
  if (source === 'block' && key.startsWith('bf:')) return 'brute-force';
  if (String(metadata.keyType || '').startsWith('body.email')) return 'identity';
  if (key.startsWith('ip:') || isIpLike(key)) return 'ip';
  if (key.includes('body.email') || looksLikeEmail(key)) return 'identity';
  if (source === 'block') return 'brute-force';
  return 'generic';
}

function normalizePublicKey(key, type) {
  if (type === 'ip' && !key.startsWith('ip:')) return `ip:${key}`;
  return key;
}

function inferPolicyName(key) {
  const parts = String(key || '').split(':');
  if (parts[0] === 'bf' && parts[1]) return parts[1];
  if (parts[0] === 'route-rl' && parts[1]) return parts[1];
  return null;
}

function defaultReason(source) {
  return source === 'block'
    ? 'Temporary application-layer block'
    : 'Temporary application-layer ban';
}

function pickNumber(...values) {
  for (const value of values) {
    if (value == null || value === '') continue;
    const parsed =
      typeof value === 'string' && Number.isNaN(Number(value)) ? Date.parse(value) : Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function toIso(value) {
  const parsed = pickNumber(value) || Date.now();
  return new Date(parsed).toISOString();
}

function isIpLike(value) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || /^[0-9a-f:]+$/i.test(value);
}

function looksLikeEmail(value) {
  return /[^\s:@]+@[^\s:@]+\.[^\s:@]+/.test(value);
}

module.exports = {
  listAdminBanEntries,
  normalizeAdminBanEntry,
  inferType,
};
