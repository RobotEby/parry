'use strict';

const { test } = require('node:test');
const nodeAssert = require('node:assert/strict');

const { EventEmitter } = require('events');
const { EventBus, MemoryEventStore, createThreatEvent } = require('../../src/events');
const { Metrics } = require('../../src/observability');
const { requireAdminAuth } = require('../../src/admin/auth');
const { ok, notFound, unauthorized } = require('../../src/admin/response');


function assert(description, condition) {
  nodeAssert.ok(condition, description);
}

function mockRes() {
  const emitter = new EventEmitter();
  const res = { _status: 200, _body: null, _headers: {} };
  res.statusCode = 200;
  res.status = (statusCode) => {
    res._status = statusCode;
    res.statusCode = statusCode;
    return res;
  };
  res.json = (body) => {
    res._body = body;
    return res;
  };
  res.setHeader = (key, value) => {
    res._headers[key] = value;
  };
  res.on = emitter.on.bind(emitter);
  res.emit = emitter.emit.bind(emitter);
  return res;
}

function runAuth(middleware, req = {}) {
  return new Promise((resolve, reject) => {
    const res = mockRes();
    let nextCalled = false;
    Promise.resolve(
      middleware(req, res, (error) => {
        if (error) return reject(error);
        nextCalled = true;
      })
    )
      .then(() => resolve({ res, nextCalled }))
      .catch(reject);
  });
}

async function runAll() {
  console.log('\n── Observability — ThreatEvent ─────────────────────────────');

  const event = createThreatEvent({
    type: 'THREAT',
    detector: 'SQL_INJECTION',
    ip: '127.0.0.1',
    method: 'POST',
    url: '/login?debug=true',
    userAgent: 'Unit\r\nTest',
    metadata: {
      password: 'secret-password',
      nested: { token: 'secret-token' },
      headers: {
        authorization: 'Bearer secret',
        cookie: 'sid=secret',
      },
      body: { email: 'user@example.com' },
    },
  });

  assert('ThreatEvent creates id', typeof event.id === 'string' && event.id.startsWith('evt_'));
  assert('ThreatEvent creates timestamp', !Number.isNaN(Date.parse(event.timestamp)));
  assert('ThreatEvent applies canonical type', event.type === 'SQL_INJECTION_BLOCKED');
  assert('ThreatEvent exposes detector slug', event.detector === 'sql');
  assert('ThreatEvent preserves detectorType', event.detectorType === 'SQL_INJECTION');
  assert('ThreatEvent applies severity default', event.severity === 'high');
  assert('ThreatEvent applies action default', event.action === 'blocked');
  assert('ThreatEvent derives path from url', event.path === '/login');
  assert('ThreatEvent sanitizes user-agent', event.userAgent === 'Unit  Test');
  assert(
    'ThreatEvent sanitizes sensitive metadata',
    event.metadata.password === '[REDACTED]' &&
      event.metadata.nested.token === '[REDACTED]' &&
      event.metadata.headers.authorization === '[REDACTED]' &&
      event.metadata.headers.cookie === '[REDACTED]' &&
      event.metadata.body === '[REDACTED]'
  );

  console.log('\n── Observability — MemoryEventStore ────────────────────────');

  const store = new MemoryEventStore({ maxEvents: 2 });
  const low = store.add(
    createThreatEvent({ type: 'XSS_BLOCKED', severity: 'low', ip: '10.0.0.1' })
  );
  const high = store.add(
    createThreatEvent({ type: 'SQL_INJECTION_BLOCKED', severity: 'high', ip: '10.0.0.2' })
  );
  store.add(createThreatEvent({ type: 'RATE_LIMIT_EXCEEDED', severity: 'medium', ip: '10.0.0.3' }));

  assert(
    'MemoryEventStore keeps maxEvents',
    store.getRecentEvents({ limit: 10 }).data.length === 2
  );
  assert('MemoryEventStore drops oldest event', !store.getById(low.id) && store.getById(high.id));
  assert(
    'MemoryEventStore filters by severity',
    store.getRecentEvents({ severity: 'high' }).pagination.total === 1
  );
  assert(
    'MemoryEventStore paginates results',
    store.getRecentEvents({ limit: 1, offset: 1 }).data.length === 1 &&
      store.getRecentEvents({ limit: 1, offset: 1 }).pagination.total === 2
  );

  console.log('\n── Observability — EventBus ────────────────────────────────');

  const bus = new EventBus({ eventStore: new MemoryEventStore({ maxEvents: 10 }) });
  let listenerEvent = null;
  bus.onThreat((entry) => {
    listenerEvent = entry;
  });
  const emitted = bus.emitThreat({ type: 'XSS_BLOCKED', severity: 'medium', ip: '10.0.0.4' });
  assert('EventBus emits normalized event', listenerEvent?.id === emitted.id);
  assert('EventBus stores recent event', bus.getEventById(emitted.id)?.type === 'XSS_BLOCKED');

  bus.onThreat(() => {
    throw new Error('listener failed');
  });
  bus.emitThreat({ type: 'NOSQL_INJECTION_BLOCKED', severity: 'high', ip: '10.0.0.5' });
  assert('EventBus listener error does not break emit', true);
  assert(
    'EventBus stores HOOK_ERROR on listener failure',
    bus.getRecentEvents({ type: 'HOOK_ERROR' }).pagination.total === 1
  );
  assert(
    'EventBus filters events',
    bus.getRecentEvents({ severity: 'high' }).pagination.total === 1
  );

  console.log('\n── Observability — Metrics ─────────────────────────────────');

  const metrics = new Metrics();
  metrics.recordRequest('started');
  metrics.recordRequest('allowed');
  metrics.recordEvent({
    type: 'SQL_INJECTION_BLOCKED',
    severity: 'high',
    detector: 'sql',
    action: 'blocked',
  });
  metrics.recordEvent({
    type: 'RATE_LIMIT_EXCEEDED',
    severity: 'medium',
    detector: 'RATE_LIMIT',
    action: 'blocked',
  });
  metrics.recordEvent({
    type: 'BRUTE_FORCE_BLOCKED',
    severity: 'high',
    detector: 'BRUTE_FORCE',
    action: 'blocked',
  });
  const snapshot = metrics.snapshot();

  assert('Metrics increments totalRequests once per started request', snapshot.totalRequests === 1);
  assert('Metrics increments allowedRequests', snapshot.allowedRequests === 1);
  assert('Metrics records events by type', snapshot.eventsByType.SQL_INJECTION_BLOCKED === 1);
  assert('Metrics records events by severity', snapshot.eventsBySeverity.high === 2);
  assert('Metrics records events by detector slug', snapshot.eventsByDetector.sql === 1);
  assert('Metrics records events by action', snapshot.eventsByAction.blocked === 3);
  assert('Metrics tracks rate limited requests', snapshot.rateLimitedRequests === 1);
  assert('Metrics tracks brute force blocks', snapshot.bruteForceBlocks === 1);
  assert('Metrics snapshot returns uptime', snapshot.uptimeMs >= 0);

  console.log('\n── Admin — Auth and Response Helpers ───────────────────────');

  const resOk = mockRes();
  ok(resOk, { ok: true });
  assert('Admin ok helper returns JSON 200', resOk._status === 200 && resOk._body.ok);

  const resNotFound = mockRes();
  notFound(resNotFound);
  assert(
    'Admin notFound helper returns stable 404 error shape',
    resNotFound._status === 404 &&
      resNotFound._body.error === 'Not found' &&
      resNotFound._body.code === 'ADMIN_NOT_FOUND'
  );

  const resUnauthorized = mockRes();
  unauthorized(resUnauthorized);
  assert(
    'Admin unauthorized helper returns stable 401 error shape',
    resUnauthorized._status === 401 &&
      resUnauthorized._body.error.code === 'ADMIN_UNAUTHORIZED' &&
      resUnauthorized._body.code === 'ADMIN_UNAUTHORIZED'
  );

  const openAuth = await runAuth(requireAdminAuth({}));
  assert('Admin auth allows when no auth is required', openAuth.nextCalled);

  const requiredWithoutCallback = await runAuth(requireAdminAuth({ requireAuth: true }));
  assert(
    'Admin auth blocks when required callback is missing',
    requiredWithoutCallback.res._status === 401
  );

  const failedCallback = await runAuth(requireAdminAuth({ auth: () => false }));
  assert('Admin auth callback blocks when it returns false', failedCallback.res._status === 401);

  const passedCallback = await runAuth(requireAdminAuth({ auth: () => true }));
  assert('Admin auth callback allows when it returns true', passedCallback.nextCalled);
}

test('Observability units', runAll);
