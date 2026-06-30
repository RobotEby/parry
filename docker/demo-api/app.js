'use strict';

const express = require('express');
const { createParry, createParryAdminRouter } = require('../../src');

function createDemoApp(options = {}) {
  const env = options.env || process.env;
  const store = options.store || null;
  const startedAt = options.startedAt || new Date();
  const app = express();

  app.disable('x-powered-by');
  mountCors(app, env);
  app.use(express.json({ limit: '64kb' }));
  app.use(express.urlencoded({ extended: true, limit: '64kb' }));

  const parry = createParry({
    preset: env.PARRY_PRESET || 'recommended',
    store: store || undefined,
    storeFailureMode: env.PARRY_STORE_FAILURE_MODE || 'fail-open',
    trustProxyHeaders: env.PARRY_TRUST_PROXY_HEADERS === 'true',
    trustedProxies: parseCsv(env.PARRY_TRUSTED_PROXIES),
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
  mountAdminApi(app, parry, env);
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

function mountAdminApi(app, parry, env) {
  const adminToken = env.PARRY_ADMIN_TOKEN;
  if (!adminToken) return;

  app.use(
    '/_parry',
    createParryAdminRouter(parry, {
      requireAuth: true,
      auth(req) {
        return req.headers['x-parry-admin-token'] === adminToken;
      },
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

module.exports = { createDemoApp };
