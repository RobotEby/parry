'use strict';

const { unauthorized, forbidden } = require('../response');
const { authenticateToken } = require('./strategies/token');
const { authenticateIpAllowlist } = require('./strategies/ip-allowlist');
const { authenticateTrustedProxy } = require('./strategies/trusted-proxy');
const { authenticateCombined } = require('./strategies/combined');
const { authenticateNone } = require('./strategies/none');

function requireAdminAuth(options = {}, context = null) {
  if (typeof options.auth === 'function') return createLegacyCallbackMiddleware(options.auth);

  if (options.requireAuth && !options.auth) {
    return function missingAuthMiddleware(_req, res) {
      return unauthorized(res);
    };
  }

  const contextAuth = context?.config?.admin?.auth;
  const authConfig = isAuthConfig(options.auth) ? options.auth : contextAuth;
  if (!authConfig) return (_req, _res, next) => next();

  return createAdminAuthMiddleware(authConfig, {
    ...context,
    admin: context?.config?.admin,
  });
}

function createAdminAuthMiddleware(config, context = {}) {
  validateAdminAuthConfig(config, context);

  return function adminAuthMiddleware(req, res, next) {
    return Promise.resolve(authenticateAdminRequest(req, config, context))
      .then((result) => {
        if (result.ok) {
          req.parryAdmin = result.admin;
          return next();
        }

        if (result.statusCode === 403) return forbidden(res);
        return unauthorized(res);
      })
      .catch((error) => next(error));
  };
}

async function authenticateAdminRequest(req, config, context = {}) {
  const mode = normalizeMode(config?.mode);

  if (mode === 'token') return authenticateToken(req, config, context);
  if (mode === 'ip-allowlist') return authenticateIpAllowlist(req, config, context);
  if (mode === 'trusted-proxy') return authenticateTrustedProxy(req, config, context);
  if (mode === 'combined') return authenticateCombined(req, config, context);
  if (mode === 'none') return authenticateNone(req, config, context);

  throw new Error(`Unsupported Admin API auth mode: ${mode}`);
}

function validateAdminAuthConfig(config, context = {}) {
  const mode = normalizeMode(config?.mode);

  if (mode === 'token' && !hasNonEmptyString(config.token)) {
    throw new Error('Admin API token auth requires a non-empty token.');
  }

  if (mode === 'ip-allowlist' && !hasNonEmptyArray(config.allowedIps)) {
    throw new Error('Admin API ip-allowlist auth requires allowedIps.');
  }

  if (mode === 'trusted-proxy' && !hasNonEmptyArray(config.trustedProxies)) {
    throw new Error('Admin API trusted-proxy auth requires trustedProxies.');
  }

  if (mode === 'combined') {
    const hasAllowAny = hasNonEmptyArray(config.allowAny);
    const hasRequireAll = hasNonEmptyArray(config.requireAll);
    if (hasAllowAny && hasRequireAll) {
      throw new Error('Admin API combined auth accepts either allowAny or requireAll, not both.');
    }
    if (!hasAllowAny && !hasRequireAll) {
      throw new Error('Admin API combined auth requires allowAny or requireAll.');
    }
    const children = hasAllowAny ? config.allowAny : config.requireAll;
    for (const child of children) {
      if (normalizeMode(child?.mode) === 'combined') {
        throw new Error('Admin API combined auth cannot contain nested combined strategies.');
      }
      validateAdminAuthConfig(child, context);
    }
  }

  if (
    mode === 'none' &&
    process.env.NODE_ENV === 'production' &&
    !config.allowInsecureAdminApi &&
    !context?.admin?.allowInsecureAdminApi
  ) {
    throw new Error('Admin API auth mode "none" is not allowed in production.');
  }
}

function createLegacyCallbackMiddleware(authCallback) {
  return async function legacyAdminAuthMiddleware(req, res, next) {
    try {
      const allowed = await authCallback(req);
      if (!allowed) return unauthorized(res);

      req.parryAdmin = {
        authenticated: true,
        strategy: 'callback',
        subject: 'callback',
        email: null,
        roles: [],
        ip: req.ip || req.socket?.remoteAddress || 'unknown',
      };
      return next();
    } catch (_error) {
      return unauthorized(res);
    }
  };
}

function isAuthConfig(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function normalizeMode(mode) {
  return String(mode || 'token')
    .trim()
    .toLowerCase();
}

function hasNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function hasNonEmptyArray(value) {
  return Array.isArray(value) && value.length > 0;
}

module.exports = {
  createAdminAuthMiddleware,
  authenticateAdminRequest,
  requireAdminAuth,
  validateAdminAuthConfig,
  normalizeMode,
};
