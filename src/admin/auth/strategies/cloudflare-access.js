'use strict';

const { readHeader } = require('../utils/header-utils');
const { success, unauthorized, forbidden } = require('../utils/result');
const {
  authenticateTrustedBoundary,
  normalizeEmail,
  emailMatchesAllowlist,
} = require('../utils/external-identity');

function authenticateCloudflareAccess(req, config) {
  const boundary = authenticateTrustedBoundary(req, config);
  if (!boundary.ok) return boundary;

  const emailHeader = config.emailHeader || 'cf-access-authenticated-user-email';
  const email = normalizeEmail(readHeader(req, emailHeader));
  if (!email) return unauthorized();

  if (!emailMatchesAllowlist(email, config)) return forbidden();

  return success(
    req,
    'cloudflare-access',
    {
      subject: email,
      email,
      roles: [],
      ip: boundary.ip,
    },
    config
  );
}

module.exports = { authenticateCloudflareAccess };
