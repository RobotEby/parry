'use strict';

const { getClientIp, getDirectIp, isTrustedProxy } = require('../../../express/ip-resolver');
const { safeCompare } = require('./constant-time');
const { readHeader, sanitizeHeaderValue } = require('./header-utils');
const { unauthorized, forbidden } = require('./result');

function authenticateTrustedBoundary(req, config = {}) {
  const trustedProxies = Array.isArray(config.trustedProxies) ? config.trustedProxies : [];
  const hasTrustedProxyBoundary = trustedProxies.length > 0;
  const hasSharedSecretBoundary = hasNonEmptyString(config.proxySharedSecret);

  if (!hasTrustedProxyBoundary && !hasSharedSecretBoundary) return forbidden();

  const directIp = getDirectIp(req);
  const trustedProxyMatched = hasTrustedProxyBoundary && isTrustedProxy(directIp, trustedProxies);

  if (trustedProxyMatched) {
    const supplied = hasSharedSecretBoundary
      ? readHeader(req, config.proxySharedSecretHeader || 'x-parry-proxy-secret')
      : '';
    if (supplied && !safeCompare(String(config.proxySharedSecret), String(supplied))) {
      return forbidden();
    }
    return {
      ok: true,
      ip: getClientIp(req, {
        ...config,
        trustProxyHeaders: true,
      }),
    };
  }

  if (hasSharedSecretBoundary) {
    const headerName = config.proxySharedSecretHeader || 'x-parry-proxy-secret';
    const supplied = readHeader(req, headerName);
    if (!supplied) return unauthorized();
    if (!safeCompare(String(config.proxySharedSecret), String(supplied))) return forbidden();
    return {
      ok: true,
      ip: getClientIp(req, {
        ...config,
        trustProxyHeaders: true,
      }),
    };
  }

  return forbidden();
}

function normalizeEmail(value) {
  const email = sanitizeHeaderValue(value, 320).toLowerCase();
  if (!email) return '';

  const atIndex = email.indexOf('@');
  if (atIndex <= 0 || atIndex !== email.lastIndexOf('@') || atIndex === email.length - 1) {
    return '';
  }

  return email;
}

function normalizeSubject(value) {
  return sanitizeHeaderValue(value, 256);
}

function normalizeList(values, options = {}) {
  const lowercase = options.lowercase !== false;
  const list = Array.isArray(values) ? values : [];
  return list
    .map((value) => sanitizeHeaderValue(value, 320))
    .map((value) => (lowercase ? value.toLowerCase() : value))
    .filter(Boolean);
}

function emailMatchesAllowlist(email, config = {}) {
  const normalizedEmail = normalizeEmail(email);
  const allowedEmails = normalizeList(config.allowedEmails);
  const allowedDomains = normalizeList(config.allowedDomains).map((domain) =>
    domain.startsWith('@') ? domain.slice(1) : domain
  );
  const hasEmailRules = allowedEmails.length > 0 || allowedDomains.length > 0;

  if (!hasEmailRules) return true;
  if (!normalizedEmail) return false;
  if (allowedEmails.includes(normalizedEmail)) return true;

  const domain = normalizedEmail.slice(normalizedEmail.indexOf('@') + 1);
  return allowedDomains.includes(domain);
}

function subjectMatchesAllowlist(subject, allowedSubjects) {
  const normalizedSubject = normalizeSubject(subject);
  const allowed = normalizeList(allowedSubjects, { lowercase: false });
  if (allowed.length === 0) return true;
  if (!normalizedSubject) return false;
  return allowed.includes(normalizedSubject);
}

function hasEmailAllowlist(config = {}) {
  return (
    (Array.isArray(config.allowedEmails) && config.allowedEmails.length > 0) ||
    (Array.isArray(config.allowedDomains) && config.allowedDomains.length > 0)
  );
}

function decodeJwtClaimsUnsafe(jwt) {
  const raw = String(jwt || '').trim();
  if (!raw || raw.length > 32_768) return null;

  const parts = raw.split('.');
  if (parts.length < 2) return null;

  try {
    const payload = base64UrlDecode(parts[1]);
    if (payload.length > 16_384) return null;
    const parsed = JSON.parse(payload);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch (_error) {
    return null;
  }
}

function extractEmailFromClaims(claims) {
  if (!claims || typeof claims !== 'object') return '';

  return (
    normalizeEmail(claims.email) ||
    normalizeEmail(claims.upn) ||
    normalizeEmail(claims.preferred_username)
  );
}

function base64UrlDecode(value) {
  const normalized = String(value || '')
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=');
  return Buffer.from(padded, 'base64').toString('utf8');
}

function hasNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

module.exports = {
  authenticateTrustedBoundary,
  normalizeEmail,
  normalizeSubject,
  normalizeList,
  emailMatchesAllowlist,
  subjectMatchesAllowlist,
  hasEmailAllowlist,
  decodeJwtClaimsUnsafe,
  extractEmailFromClaims,
};
