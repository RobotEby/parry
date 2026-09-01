'use strict';

const ipaddr = require('ipaddr.js');
const MAX_PROXY_HOPS = 20;

function getClientIp(req, options = {}) {
  const headers = req.headers || {};
  const directIp = getDirectIp(req);

  if (!options.trustProxyHeaders) return directIp;

  if (!isTrustedProxy(directIp, options.trustedProxies || [])) return directIp;

  const forwarded = getHeader(headers, 'x-forwarded-for');
  if (forwarded) {
    const rawHops = String(forwarded).split(',');
    if (rawHops.length === 0 || rawHops.length > MAX_PROXY_HOPS) return directIp;
    const hops = rawHops.map((hop) => parseIp(hop));
    if (hops.some((hop) => !hop)) return directIp;

    for (let index = hops.length - 1; index >= 0; index -= 1) {
      const hop = hops[index].toString();
      if (!isTrustedProxy(hop, options.trustedProxies || [])) return hop;
    }

    return hops[0]?.toString() || directIp;
  }

  const realIp = getHeader(headers, 'x-real-ip');
  return realIp && parseIp(realIp) ? normalizeIp(realIp) : directIp;
}

function resolveClientIP(req, options = {}) {
  return getClientIp(req, options);
}

function getDirectIp(req) {
  return normalizeIp(req?.socket?.remoteAddress || req?.connection?.remoteAddress || req?.ip);
}

function isTrustedProxy(ip, trustedProxies) {
  return isIpAllowed(ip, trustedProxies);
}

function isIpAllowed(clientIp, allowedIps = []) {
  const parsedClientIp = parseIp(clientIp);
  if (!parsedClientIp || !Array.isArray(allowedIps) || allowedIps.length === 0) return false;

  return allowedIps.some((entry) => {
    const rule = String(entry || '').trim();
    if (!rule) return false;

    try {
      if (rule.includes('/')) {
        const [range, bits] = ipaddr.parseCIDR(rule);
        return parsedClientIp.match(range, bits);
      }

      const parsedRule = parseIp(rule);
      return parsedRule ? parsedClientIp.toString() === parsedRule.toString() : false;
    } catch (_error) {
      return false;
    }
  });
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
  const parsed = parseIp(value);
  return parsed ? parsed.toString() : 'unknown';
}

function parseIp(value) {
  const cleaned = cleanIpInput(value);
  if (!cleaned) return null;

  try {
    return ipaddr.process(cleaned);
  } catch (_error) {
    return null;
  }
}

function cleanIpInput(value) {
  let ip = String(value || '').trim();
  if (!ip || ip === 'unknown') return '';

  if (ip.startsWith('[')) {
    const end = ip.indexOf(']');
    if (end !== -1) ip = ip.slice(1, end);
  }

  const zoneIndex = ip.indexOf('%');
  if (zoneIndex !== -1) ip = ip.slice(0, zoneIndex);

  if (ip.startsWith('::ffff:')) return ip;

  const colonCount = (ip.match(/:/g) || []).length;
  if (colonCount === 1 && ip.includes('.')) {
    const [host] = ip.split(':');
    return host;
  }

  return ip;
}

module.exports = {
  getClientIp,
  resolveClientIP,
  getDirectIp,
  isTrustedProxy,
  isIpAllowed,
  normalizeIp,
  getHeader,
};
