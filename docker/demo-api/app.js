'use strict';

const express = require('express');
const { createParry, createParryAdminRouter } = require('../../src');

function createDemoApp(options = {}) {
  const env = options.env || process.env;
  const store = options.store || null;
  const startedAt = options.startedAt || new Date();
  const adminPath = env.PARRY_ADMIN_PATH || '/_parry';
  const adminAuth = buildAdminAuthConfig(env);
  const adminEnabled = env.PARRY_ADMIN_ENABLED !== 'false';
  const app = express();

  app.disable('x-powered-by');
  mountCors(app, env);
  app.use(express.json({ limit: '64kb' }));
  app.use(express.urlencoded({ extended: true, limit: '64kb' }));

  const parry = createParry({
    preset: env.PARRY_PRESET || 'recommended',
    store: store || undefined,
    storeFailureMode: env.PARRY_STORE_FAILURE_MODE || 'fail-open',
    trustProxyHeaders:
      env.PARRY_TRUST_PROXY_HEADERS === 'true' ||
      env.PARRY_ADMIN_TRUST_PROXY_HEADERS === 'true',
    trustedProxies: parseCsv(env.PARRY_TRUSTED_PROXIES || env.PARRY_ADMIN_TRUSTED_PROXIES),
    admin: {
      enabled: adminEnabled,
      path: adminPath,
      auth: adminAuth,
    },
    rateLimit: {
      enabled: env.PARRY_RATE_LIMIT_ENABLED !== 'false',
      max: Number(env.PARRY_RATE_LIMIT_MAX || 120),
      windowMs: Number(env.PARRY_RATE_LIMIT_WINDOW_MS || 60_000),
      headers: true,
    },
    hpp: {
      enabled: env.PARRY_HPP_ENABLED === 'true',
      allowDuplicateParamsFor: ['tags', 'filters'],
    },
    requestId: {
      enabled: true,
      header: 'x-request-id',
      responseHeader: 'X-Parry-Request-Id',
    },
    logThreats: env.PARRY_LOG_THREATS !== 'false',
  });

  app.use(parry.middleware());
  mountAdminApi(app, parry, { enabled: adminEnabled, path: adminPath, auth: adminAuth });
  mountRoutes(app, {
    env,
    storeType: store ? 'redis' : 'memory',
    startedAt,
  });

  return { app, parry };
}

function mountCors(app, env) {
  const allowedOrigin = String(env.PARRY_ADMIN_CORS_ORIGIN || '').trim();
  if (!allowedOrigin) return;

  app.use((req, res, next) => {
    if (req.headers.origin === allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'content-type,x-parry-admin-token,x-request-id');
    }

    if (req.method === 'OPTIONS') return res.status(204).end();
    return next();
  });
}

function mountAdminApi(app, parry, admin) {
  if (!admin.enabled) return;

  app.use(
    admin.path,
    createParryAdminRouter(parry, {
      auth: admin.auth,
    })
  );
}

function mountRoutes(app, options) {
  const { env, storeType, startedAt } = options;

  app.get('/health', (_req, res) => {
    res.json({
      ok: true,
      name: 'parry-demo-api',
      store: storeType,
      uptimeMs: Date.now() - startedAt.getTime(),
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/search', (req, res) => {
    res.json({
      ok: true,
      query: req.query.q || '',
      results: [],
    });
  });

  app.post('/echo', (req, res) => {
    res.json({
      ok: true,
      received: req.body || {},
    });
  });

  app.post('/login', (req, res) => {
    const expectedEmail = String(env.DEMO_USER_EMAIL || 'demo@example.com').trim().toLowerCase();
    const expectedPassword = String(env.DEMO_USER_PASSWORD || 'password123');
    const email = String(req.body.email || req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (email !== expectedEmail || password !== expectedPassword) {
      if (req.parry && typeof req.parry.recordAuthFailure === 'function') {
        req.parry.recordAuthFailure('invalid_credentials');
      }
      return res.status(401).json({ ok: false, message: 'Invalid credentials' });
    }

    if (req.parry && typeof req.parry.recordAuthSuccess === 'function') {
      req.parry.recordAuthSuccess();
    }

    return res.json({ ok: true });
  });
}

function parseCsv(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function buildAdminAuthConfig(env) {
  const mode = String(env.PARRY_ADMIN_AUTH_MODE || 'token').trim().toLowerCase();

  if (mode === 'token') {
    return {
      mode,
      token: env.PARRY_ADMIN_TOKEN || 'change-me',
      trustProxyHeaders: env.PARRY_ADMIN_TRUST_PROXY_HEADERS === 'true',
      trustedProxies: parseCsv(env.PARRY_ADMIN_TRUSTED_PROXIES),
    };
  }

  if (mode === 'ip-allowlist') {
    return {
      mode,
      allowedIps: parseCsv(env.PARRY_ADMIN_ALLOWED_IPS),
      trustProxyHeaders: env.PARRY_ADMIN_TRUST_PROXY_HEADERS === 'true',
      trustedProxies: parseCsv(env.PARRY_ADMIN_TRUSTED_PROXIES),
    };
  }

  if (mode === 'trusted-proxy') {
    const requiredHeader = parseRequiredHeader(env.PARRY_ADMIN_REQUIRED_HEADER);
    return {
      mode,
      trustedProxies: parseCsv(env.PARRY_ADMIN_TRUSTED_PROXIES),
      requiredHeaders: requiredHeader ? { [requiredHeader.name]: requiredHeader.value } : {},
      userHeader: 'x-parry-admin-user',
      emailHeader: 'x-parry-admin-email',
      rolesHeader: 'x-parry-admin-roles',
      proxySharedSecretHeader: env.PARRY_PROXY_SHARED_SECRET_HEADER || 'x-parry-proxy-secret',
      proxySharedSecret: env.PARRY_PROXY_SHARED_SECRET || undefined,
    };
  }

  if (mode === 'cloudflare-access') {
    return {
      mode,
      ...buildExternalAdminAuthConfig(env),
      emailHeader: env.PARRY_CLOUDFLARE_EMAIL_HEADER || 'cf-access-authenticated-user-email',
      jwtHeader: env.PARRY_CLOUDFLARE_JWT_HEADER || 'cf-access-jwt-assertion',
      verifyJwt: env.PARRY_CLOUDFLARE_VERIFY_JWT === 'true',
    };
  }

  if (mode === 'alb-auth' || mode === 'cognito-alb') {
    return {
      mode,
      ...buildExternalAdminAuthConfig(env),
      userHeader: env.PARRY_ALB_USER_HEADER || 'x-amzn-oidc-identity',
      dataHeader: env.PARRY_ALB_DATA_HEADER || 'x-amzn-oidc-data',
      verifyJwt: env.PARRY_ALB_VERIFY_JWT === 'true',
    };
  }

  if (mode === 'none') {
    return {
      mode,
      allowInsecureAdminApi: true,
    };
  }

  throw new Error(`Unsupported PARRY_ADMIN_AUTH_MODE: ${mode}`);
}

function buildExternalAdminAuthConfig(env) {
  return {
    trustedProxies: parseCsv(env.PARRY_ADMIN_TRUSTED_PROXIES),
    proxySharedSecretHeader: env.PARRY_PROXY_SHARED_SECRET_HEADER || 'x-parry-proxy-secret',
    proxySharedSecret: env.PARRY_PROXY_SHARED_SECRET || undefined,
    allowedEmails: parseCsv(env.PARRY_ADMIN_ALLOWED_EMAILS),
    allowedDomains: parseCsv(env.PARRY_ADMIN_ALLOWED_DOMAINS),
    allowedSubjects: parseCsv(env.PARRY_ADMIN_ALLOWED_SUBJECTS),
  };
}

function parseRequiredHeader(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  const index = raw.indexOf(':');
  if (index === -1) return null;
  const name = raw.slice(0, index).trim().toLowerCase();
  const headerValue = raw.slice(index + 1).trim();
  if (!name || !headerValue) return null;
  return { name, value: headerValue };
}

module.exports = { createDemoApp, buildAdminAuthConfig };
