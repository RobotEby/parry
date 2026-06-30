'use strict';

const express = require('express');
const pkg = require('../../package.json');
const { requireAdminAuth } = require('./auth');
const { ok, notFound } = require('./response');
const { listAdminBanEntries } = require('./ban-normalizer');
const { describeStore, sanitizePolicies } = require('../observability');

function createParryAdminRouter(parry, options = {}) {
  const context = resolveParryContext(parry);
  if (!context) {
    throw new Error('createParryAdminRouter requires a Parry instance or middleware.');
  }

  const router = express.Router();
  router.use(requireAdminAuth(options, context));

  router.get('/health', (_req, res) =>
    ok(res, {
      ok: true,
      name: 'parry',
      version: pkg.version,
      uptimeMs: context.metrics.snapshot().uptimeMs,
      store: describeStore(context.store),
    })
  );

  router.get(
    '/metrics',
    asyncRoute(async (_req, res) => {
      const activeBans = (await listAdminBanEntries(context.store)).length;
      return ok(res, context.metrics.snapshot({ activeBans }));
    })
  );

  router.get('/events', (req, res) => {
    const result = context.eventBus.getRecentEvents({
      limit: req.query.limit,
      offset: req.query.offset,
      type: req.query.type,
      severity: req.query.severity,
      action: req.query.action,
      detector: req.query.detector,
      ip: req.query.ip,
      path: req.query.path,
      policyName: req.query.policyName,
    });
    return ok(res, result);
  });

  router.get('/events/:id', (req, res) => {
    const event = context.eventBus.getEventById(req.params.id);
    if (!event) return notFound(res);
    return ok(res, event);
  });

  router.get(
    '/bans',
    asyncRoute(async (req, res) => {
      const data = await listAdminBanEntries(context.store, req.query);
      return ok(res, paginateList(data, req.query));
    })
  );

  router.get('/policies', (req, res) =>
    ok(res, paginateList(sanitizePolicies(context.policies || []), req.query))
  );

  return router;
}

function resolveParryContext(parry) {
  if (!parry) return null;
  if (typeof parry.getContext === 'function') return parry.getContext();
  if (parry.__parryContext) return parry.__parryContext;
  return null;
}

function paginateList(data, query = {}) {
  const limit = clampNumber(query.limit, 50, 1, 500);
  const offset = clampNumber(query.offset, 0, 0, data.length);

  return {
    data: data.slice(offset, offset + limit),
    pagination: {
      limit,
      offset,
      total: data.length,
    },
  };
}

function clampNumber(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
}

function asyncRoute(handler) {
  return function routeHandler(req, res, next) {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

module.exports = { createParryAdminRouter, resolveParryContext };
