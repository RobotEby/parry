'use strict';

function resolveClientIP(req, options = {}) {
  const headers = req.headers || {};
  const directIp = normalizeIp(req.socket?.remoteAddress || req.ip || 'unknown');

  if (!options.trustProxyHeaders) return directIp;

  if (!isTrustedProxy(directIp, options.trustedProxies || [])) return directIp;

  const forwarded = getHeader(headers, 'x-forwarded-for');
  const firstForwarded = forwarded ? forwarded.split(',')[0].trim() : '';
  return normalizeIp(firstForwarded || directIp);
}

function isTrustedProxy(ip, trustedProxies) {
  if (!ip || ip === 'unknown') return false;
  return trustedProxies.map(normalizeIp).includes(normalizeIp(ip));
}

function getHeader(headers, name) {
  const lower = name.toLowerCase();
  return (
    headers[lower] ||
    headers[name] ||
    headers[Object.keys(headers).find((key) => key.toLowerCase() === lower)]
  );
}

function normalizeIp(value) {
  const ip = String(value || 'unknown').trim();
  if (!ip) return 'unknown';
  if (ip.startsWith('::ffff:')) return ip.slice('::ffff:'.length);
  if (ip.startsWith('[') && ip.endsWith(']')) return ip.slice(1, -1);
  return ip;
}

module.exports = { resolveClientIP, isTrustedProxy, normalizeIp };
