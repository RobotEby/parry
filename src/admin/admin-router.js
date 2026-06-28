'use strict';

const express = require('express');
const pkg = require('../../package.json');
const { requireAdminAuth } = require('./auth');
const { ok, notFound } = require('./response');
const { describeStore, sanitizePolicies, countActiveBans } = require('../observability');

function createParryAdminRouter(parry, options = {}) {
  const context = resolveParryContext(parry);
  if (!context) {
    throw new Error('createParryAdminRouter requires a Parry instance or middleware.');
  }

  const router = express.Router();
  router.use(requireAdminAuth(options));

  router.get('/health', (_req, res) =>
    ok(res, {
      ok: true,
      name: 'parry',
      version: pkg.version,
      uptimeMs: context.metrics.snapshot().uptimeMs,
      store: describeStore(context.store),
    })
  );

  router.get('/metrics', (_req, res) =>
    ok(res, context.metrics.snapshot({ activeBans: countActiveBans(context.store) }))
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

  router.get('/bans', (_req, res) => {
    const data = context.store && typeof context.store.listBans === 'function'
      ? context.store.listBans()
      : [];
    return ok(res, { data });
  });

  router.get('/policies', (_req, res) => ok(res, { data: sanitizePolicies(context.policies || []) }));

  return router;
}

function resolveParryContext(parry) {
  if (!parry) return null;
  if (typeof parry.getContext === 'function') return parry.getContext();
  if (parry.__parryContext) return parry.__parryContext;
  return null;
}

module.exports = { createParryAdminRouter, resolveParryContext };
