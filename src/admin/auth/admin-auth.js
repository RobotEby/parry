'use strict';

const { unauthorized, forbidden } = require('../response');
const { authenticateToken } = require('./strategies/token');
const { authenticateIpAllowlist } = require('./strategies/ip-allowlist');
const { authenticateTrustedProxy } = require('./strategies/trusted-proxy');
const { authenticateCombined } = require('./strategies/combined');
const { authenticateNone, warnInsecureAdminApi } = require('./strategies/none');
const { authenticateCloudflareAccess } = require('./strategies/cloudflare-access');
const { authenticateAlbAuth } = require('./strategies/alb-auth');
const { validateHeaderName, validateTrustedProxies } = require('../../../config/validate');

const SUPPORTED_MODES = new Set([
  'token',
  'ip-allowlist',
  'trusted-proxy',
  'cloudflare-access',
  'alb-auth',
  'cognito-alb',
  'combined',
  'none',
]);

function requireAdminAuth(options = {}, context = null) {
  if (typeof options.auth === 'function') return createLegacyCallbackMiddleware(options.auth);

  const contextAuth = context?.config?.admin?.auth;
  const authConfig = isAuthConfig(options.auth) ? options.auth : contextAuth;
  if (authConfig) {
    return createAdminAuthMiddleware(authConfig, {
      ...context,
      admin: context?.config?.admin,
    });
  }

  const insecureOptIn =
    options.allowInsecureAdminApi === true ||
    options.requireAuth === false ||
    context?.config?.admin?.allowInsecureAdminApi === true;

  if (insecureOptIn) {
    return createAdminAuthMiddleware(
      { mode: 'none', allowInsecureAdminApi: true },
      { ...context, admin: context?.config?.admin }
    );
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error('Admin API requires an authentication strategy in production.');
  }

  if (options.requireAuth === true) {
    return function missingAuthMiddleware(_req, res) {
      return unauthorized(res);
    };
  }

  throw new Error(
    'Admin API requires authentication. Configure auth or explicitly allow insecure local access.'
  );
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
  if (mode === 'cloudflare-access') {
    return authenticateCloudflareAccess(req, { ...config, mode }, context);
  }
  if (mode === 'alb-auth' || mode === 'cognito-alb') {
    return authenticateAlbAuth(req, { ...config, mode }, context);
  }
  if (mode === 'combined') return authenticateCombined(req, config, context);
  if (mode === 'none') return authenticateNone(req, config, context);

  throw new Error(`Unsupported Admin API auth mode: ${mode}`);
}

function validateAdminAuthConfig(config, context = {}) {
  const mode = normalizeMode(config?.mode);

  if (!SUPPORTED_MODES.has(mode)) {
    throw new Error(`Unsupported Admin API auth mode: ${mode}`);
  }

  if (mode === 'token' && !hasNonEmptyString(config.token)) {
    throw new Error('Admin API token auth requires a non-empty token.');
  }
  if (mode === 'token' && config.header !== undefined) {
    validateHeaderName(config.header, 'auth.header');
  }

  if (mode === 'ip-allowlist' && !hasNonEmptyArray(config.allowedIps)) {
    throw new Error('Admin API ip-allowlist auth requires allowedIps.');
  }
  if (mode === 'ip-allowlist') validateTrustedProxies(config.allowedIps, 'auth.allowedIps');

  if (mode === 'trusted-proxy' && !hasNonEmptyArray(config.trustedProxies)) {
    throw new Error('Admin API trusted-proxy auth requires trustedProxies.');
  }
  if (config.trustedProxies !== undefined) {
    validateTrustedProxies(config.trustedProxies, 'auth.trustedProxies');
  }

  for (const field of [
    'proxySharedSecretHeader',
    'userHeader',
    'emailHeader',
    'rolesHeader',
    'jwtHeader',
    'dataHeader',
  ]) {
    if (config[field] !== undefined) validateHeaderName(config[field], `auth.${field}`);
  }
  if (config.requiredHeaders !== undefined) {
    if (
      !config.requiredHeaders ||
      typeof config.requiredHeaders !== 'object' ||
      Array.isArray(config.requiredHeaders)
    ) {
      throw new TypeError('auth.requiredHeaders must be an object');
    }
    for (const header of Object.keys(config.requiredHeaders)) {
      validateHeaderName(header, 'auth.requiredHeaders');
    }
  }

  if (mode === 'cloudflare-access' || mode === 'alb-auth' || mode === 'cognito-alb') {
    validateExternalAuthConfig(mode, config);
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

  if (mode === 'none') {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Admin API auth mode "none" is not allowed in production.');
    }
    warnInsecureAdminApi();
  }
}

function validateExternalAuthConfig(mode, config) {
  if (config.verifyJwt === true) {
    throw new Error(
      `Admin API auth mode "${mode}" does not implement cryptographic JWT/JWKS verification in this version.`
    );
  }

  const hasTrustedProxies = hasNonEmptyArray(config.trustedProxies);
  const hasSharedSecret = hasNonEmptyString(config.proxySharedSecret);

  if (!hasTrustedProxies && !hasSharedSecret) {
    throw new Error(`Admin API auth mode "${mode}" requires trustedProxies or proxySharedSecret.`);
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
  const normalized = String(mode || 'token')
    .trim()
    .toLowerCase();
  if (normalized === 'alb-cognito') return 'cognito-alb';
  return normalized;
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
