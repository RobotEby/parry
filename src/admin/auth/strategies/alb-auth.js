'use strict';

const { readHeader } = require('../utils/header-utils');
const { success, unauthorized, forbidden } = require('../utils/result');
const {
  authenticateTrustedBoundary,
  normalizeEmail,
  normalizeSubject,
  emailMatchesAllowlist,
  subjectMatchesAllowlist,
  hasEmailAllowlist,
  decodeJwtClaimsUnsafe,
  extractEmailFromClaims,
} = require('../utils/external-identity');

function authenticateAlbAuth(req, config) {
  const boundary = authenticateTrustedBoundary(req, config);
  if (!boundary.ok) return boundary;

  const userHeader = config.userHeader || 'x-amzn-oidc-identity';
  const dataHeader = config.dataHeader || 'x-amzn-oidc-data';
  const subject = normalizeSubject(readHeader(req, userHeader));
  if (!subject) return unauthorized();

  if (!subjectMatchesAllowlist(subject, config.allowedSubjects)) return forbidden();

  const claims = decodeJwtClaimsUnsafe(readHeader(req, dataHeader));
  const email =
    extractEmailFromClaims(claims) ||
    normalizeEmail(readHeader(req, config.emailHeader || 'x-amzn-oidc-email'));

  if (hasEmailAllowlist(config) && !emailMatchesAllowlist(email, config)) return forbidden();

  const strategy = config.mode === 'cognito-alb' ? 'cognito-alb' : 'alb-auth';

  return success(
    req,
    strategy,
    {
      subject,
      email: email || null,
      roles: [],
      ip: boundary.ip,
    },
    config
  );
}

module.exports = { authenticateAlbAuth };
