'use strict';

const { getClientIp, getDirectIp, isTrustedProxy } = require('../../../express/ip-resolver');
const { safeCompare } = require('../utils/constant-time');
const {
  readHeader,
  hasHeader,
  headerEquals,
  sanitizeHeaderValue,
  parseRoles,
} = require('../utils/header-utils');
const { success, unauthorized, forbidden } = require('../utils/result');

function authenticateTrustedProxy(req, config) {
  const directIp = getDirectIp(req);
  if (!isTrustedProxy(directIp, config.trustedProxies || [])) return forbidden();

  const requiredHeaders = config.requiredHeaders || {};
  for (const [headerName, expectedValue] of Object.entries(requiredHeaders)) {
    if (!hasHeader(req, headerName)) return unauthorized();
    if (!headerEquals(req, headerName, expectedValue)) return forbidden();
  }

  if (config.proxySharedSecret) {
    const headerName = config.proxySharedSecretHeader || 'x-parry-proxy-secret';
    const supplied = readHeader(req, headerName);
    if (!supplied) return unauthorized();
    if (!safeCompare(String(config.proxySharedSecret), String(supplied))) return forbidden();
  }

  const user = sanitizeHeaderValue(readHeader(req, config.userHeader || 'x-parry-admin-user'));
  const email = sanitizeHeaderValue(readHeader(req, config.emailHeader || 'x-parry-admin-email'));
  const roles = parseRoles(readHeader(req, config.rolesHeader || 'x-parry-admin-roles'));
  const clientIp = getClientIp(req, {
    ...config,
    trustProxyHeaders: true,
  });

  return success(
    req,
    'trusted-proxy',
    {
      subject: user ? `proxy:${user}` : email ? `proxy:${email}` : `proxy:${clientIp}`,
      email: email || null,
      roles,
      ip: clientIp,
    },
    config
  );
}

module.exports = { authenticateTrustedProxy };
