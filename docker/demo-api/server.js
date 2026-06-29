'use strict';

const express = require('express');
const { createParry, createParryAdminRouter, RedisStore } = require('../../src');

const app = express();
const port = Number(process.env.PORT || 3000);
const startedAt = new Date();

app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: true, limit: '64kb' }));

main().catch((error) => {
  console.error('[parry-demo] fatal startup error', error);
  process.exit(1);
});

async function main() {
  const store = await createStore();
  const parry = createParry({
    preset: process.env.PARRY_PRESET || 'recommended',
    store: store || undefined,
    storeFailureMode: process.env.PARRY_STORE_FAILURE_MODE || 'fail-open',
    rateLimit: {
      enabled: process.env.PARRY_RATE_LIMIT_ENABLED !== 'false',
      max: Number(process.env.PARRY_RATE_LIMIT_MAX || 120),
      windowMs: Number(process.env.PARRY_RATE_LIMIT_WINDOW_MS || 60_000),
      headers: true,
    },
    hpp: {
      enabled: process.env.PARRY_HPP_ENABLED === 'true',
      allowDuplicateParamsFor: ['tags', 'filters'],
    },
    requestId: {
      enabled: true,
      header: 'x-request-id',
      responseHeader: 'X-Parry-Request-Id',
    },
    logThreats: process.env.PARRY_LOG_THREATS !== 'false',
  });

  app.use(parry.middleware());

  mountAdminApi(parry);
  mountRoutes(store ? 'redis' : 'memory');

  const server = app.listen(port, () => {
    console.log(`[parry-demo] listening on port ${port}`);
  });

  process.on('SIGTERM', () => shutdown(server, store));
  process.on('SIGINT', () => shutdown(server, store));
}

async function createStore() {
  if (process.env.PARRY_STORE !== 'redis') return null;

  if (!process.env.REDIS_URL) {
    console.warn(
      '[parry-demo] PARRY_STORE=redis set without REDIS_URL; falling back to MemoryStore'
    );
    return null;
  }

  const { createClient } = require('redis');
  const client = createClient({
    url: process.env.REDIS_URL,
    password: process.env.REDIS_AUTH_TOKEN || undefined,
  });

  client.on('error', (error) => {
    console.error('[parry-demo] redis client error', error.message);
  });

  try {
    await client.connect();
    return new RedisStore({
      client,
      prefix: process.env.PARRY_REDIS_PREFIX || 'parry',
      closeClient: true,
    });
  } catch (error) {
    console.error('[parry-demo] redis unavailable; falling back to MemoryStore', error.message);
    return null;
  }
}

function mountAdminApi(parry) {
  const adminToken = process.env.PARRY_ADMIN_TOKEN;
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

function mountRoutes(storeType) {
  app.get('/health', (req, res) => {
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

  app.post('/login', (req, res) => {
    const email = String(req.body.email || req.body.username || '')
      .trim()
      .toLowerCase();
    const password = String(req.body.password || '');

    if (!email || password !== 'demo-password') {
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

function shutdown(server, store) {
  server.close(async () => {
    if (store && typeof store.close === 'function') {
      await store.close();
    }
    process.exit(0);
  });
}
