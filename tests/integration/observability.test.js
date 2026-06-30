'use strict';

const { EventEmitter } = require('events');
const { Parry_DDoS, createParry, createParryAdminRouter } = require('../../src');

let passed = 0,
  failed = 0;

function assert(description, condition) {
  if (condition) {
    console.log(`  ✓ ${description}`);
    passed++;
  } else {
    console.error(`  ✗ FAILED: ${description}`);
    failed++;
  }
}

function mockReq(overrides = {}) {
  return {
    method: 'POST',
    url: '/test',
    originalUrl: '/test',
    ip: '127.0.0.1',
    headers: {},
    query: {},
    body: {},
    params: {},
    socket: { remoteAddress: '127.0.0.1' },
    ...overrides,
  };
}

function mockRes(onJson) {
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
    if (onJson) onJson(res);
    return res;
  };
  res.setHeader = (key, value) => {
    res._headers[key] = value;
  };
  res.getHeader = (key) => res._headers[key];
  res.on = emitter.on.bind(emitter);
  res.emit = emitter.emit.bind(emitter);
  return res;
}

function run(mw, req) {
  return new Promise((resolve, reject) => {
    const res = mockRes();
    let called = false;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      resolve({ req, res, next: called });
    };
    const maybePromise = mw(req, res, (error) => {
      if (error) return reject(error);
      called = true;
      finish();
    });
    Promise.resolve(maybePromise).then(finish).catch(reject);
  });
}

function runWithRoute(mw, req, routeHandler) {
  return new Promise((resolve, reject) => {
    const res = mockRes();
    let called = false;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      resolve({ req, res, next: called });
    };
    const maybePromise = mw(req, res, async (error) => {
      if (error) return reject(error);
      called = true;
      try {
        await routeHandler(req, res);
        res.emit('finish');
        await new Promise((done) => setTimeout(done, 0));
        finish();
      } catch (routeError) {
        reject(routeError);
      }
    });
    Promise.resolve(maybePromise)
      .then(() => {
        if (!called) finish();
      })
      .catch(reject);
  });
}

function runRouter(router, path, options = {}) {
  return new Promise((resolve, reject) => {
    const req = {
      method: options.method || 'GET',
      url: path,
      originalUrl: path,
      headers: options.headers || {},
      query: options.query || {},
      params: {},
    };
    const res = mockRes((response) => resolve({ req, res: response }));
    router.handle(req, res, (error) => {
      if (error) return reject(error);
      resolve({ req, res, next: true });
    });
  });
}

function loginPolicy(overrides = {}) {
  return {
    name: 'auth-login',
    match: { method: 'POST', path: '/login' },
    bruteForce: {
      enabled: true,
      maxAttempts: 2,
      windowMs: 60_000,
      blockDurationMs: 60_000,
      keys: ['ip', 'body.email', 'ip+body.email'],
      resetOnSuccess: true,
    },
    ...overrides,
  };
}

function loginReq(ip, body = {}) {
  return mockReq({
    method: 'POST',
    url: '/login',
    originalUrl: '/login',
    ip,
    headers: { 'user-agent': 'Integration Test' },
    body: { email: 'USER@example.com', password: 'super-secret', ...body },
    query: {},
    params: {},
  });
}

async function runAll() {
  console.log('\n── Observability Integration — Middleware ─────────────────');

  const cleanParry = createParry({ rateLimit: false, logThreats: false });
  const cleanRun = await run(
    cleanParry.middleware(),
    mockReq({ ip: '10.50.0.1', body: { name: 'alice' } })
  );
  const cleanMetrics = cleanParry.metrics.snapshot();
  assert('Allowed request reaches next()', cleanRun.next);
  assert('Allowed request increments totalRequests', cleanMetrics.totalRequests === 1);
  assert('Allowed request increments allowedRequests', cleanMetrics.allowedRequests === 1);

  let structuredThreat = null;
  const threatParry = createParry({
    rateLimit: false,
    logThreats: false,
    requestId: { enabled: true, header: 'x-request-id', responseHeader: 'X-Parry-Request-Id' },
    onThreat(event) {
      structuredThreat = event;
    },
  });
  const threatReq = mockReq({
    ip: '10.50.0.2',
    headers: {
      'x-request-id': 'req-integration-1',
      authorization: 'Bearer should-not-leak',
      cookie: 'sid=should-not-leak',
    },
    body: {
      username: "' OR 1=1 --",
      password: 'should-not-leak',
      token: 'should-not-leak',
    },
  });
  const threatRun = await run(threatParry.middleware(), threatReq);
  const threatEvents = threatParry.eventBus.getRecentEvents({ type: 'SQL_INJECTION_BLOCKED' });
  const threatText = JSON.stringify(threatEvents.data[0] || {});

  assert(
    'Blocked request returns current response',
    threatRun.res._status === 400 && !threatRun.next
  );
  assert('Blocked request generates structured event', threatEvents.pagination.total === 1);
  assert('onThreat receives structured event', structuredThreat?.type === 'SQL_INJECTION_BLOCKED');
  assert('Structured event exposes detector slug', structuredThreat?.detector === 'sql');
  assert('Structured event preserves detectorType', structuredThreat?.detectorType === 'SQL_INJECTION');
  assert(
    'Structured event includes request id',
    structuredThreat?.requestId === 'req-integration-1'
  );
  assert(
    'Request id response header is optional and configurable',
    threatRun.res._headers['X-Parry-Request-Id'] === 'req-integration-1'
  );
  assert(
    'Events do not leak password, token, cookie, or authorization',
    !threatText.includes('should-not-leak') && !threatText.includes('Bearer')
  );

  const hookParry = createParry({
    rateLimit: false,
    logThreats: false,
    onThreat() {
      throw new Error('hook failed');
    },
  });
  const hookRun = await run(
    hookParry.middleware(),
    mockReq({ body: { q: '<script>alert(1)</script>' } })
  );
  assert('onThreat error does not break request', hookRun.res._status === 400 && !hookRun.next);
  assert(
    'onThreat error generates HOOK_ERROR',
    hookParry.eventBus.getRecentEvents({ type: 'HOOK_ERROR' }).pagination.total === 1
  );

  const rateParry = createParry({
    rateLimit: { enabled: true, max: 1, windowMs: 60_000 },
    logThreats: false,
  });
  await run(rateParry.middleware(), mockReq({ ip: '10.50.0.3' }));
  const rateRun = await run(rateParry.middleware(), mockReq({ ip: '10.50.0.3' }));
  assert('Rate limit still blocks with 429', rateRun.res._status === 429);
  assert(
    'Rate limit generates RATE_LIMIT_EXCEEDED',
    rateParry.eventBus.getRecentEvents({ type: 'RATE_LIMIT_EXCEEDED' }).pagination.total === 1
  );

  const banParry = createParry({
    rateLimit: true,
    maxRequests: 100,
    windowMs: 60_000,
    suspiciousThreshold: 1,
    banDurationMs: 60_000,
    logThreats: false,
  });
  await run(banParry.middleware(), mockReq({ ip: '10.50.0.33', body: { q: "' OR 1=1 --" } }));
  const banHit = await run(banParry.middleware(), mockReq({ ip: '10.50.0.33', body: {} }));
  assert(
    'Suspicious threshold generates TEMPORARY_BAN_CREATED',
    banParry.eventBus.getRecentEvents({ type: 'TEMPORARY_BAN_CREATED' }).pagination.total === 1
  );
  assert('Temporary ban hit still returns 429', banHit.res._status === 429);
  assert(
    'Temporary ban hit generates TEMPORARY_BAN_HIT',
    banParry.eventBus.getRecentEvents({ type: 'TEMPORARY_BAN_HIT' }).pagination.total === 1
  );

  const routeRateParry = createParry({
    rateLimit: { enabled: true, max: 100, windowMs: 60_000 },
    logThreats: false,
    policies: [
      {
        name: 'login-route-rate',
        match: { method: 'POST', path: '/login' },
        rateLimit: { enabled: true, max: 1, windowMs: 60_000, key: 'ip' },
      },
    ],
  });
  await runWithRoute(routeRateParry.middleware(), loginReq('10.50.0.4'), (_req, res) =>
    res.status(200).json({ ok: true })
  );
  const routeRateRun = await runWithRoute(
    routeRateParry.middleware(),
    loginReq('10.50.0.4'),
    (_req, res) => res.status(200).json({ ok: true })
  );
  assert('Route rate limit blocks separately from global limit', routeRateRun.res._status === 429);
  assert(
    'Route rate limit generates ROUTE_RATE_LIMIT_EXCEEDED',
    routeRateParry.eventBus.getRecentEvents({ type: 'ROUTE_RATE_LIMIT_EXCEEDED' }).pagination
      .total === 1
  );

  const bruteParry = createParry({
    rateLimit: false,
    logThreats: false,
    policies: [loginPolicy()],
  });
  const invalidLogin = (_req, res) => res.status(401).json({ success: false });
  await runWithRoute(bruteParry.middleware(), loginReq('10.50.0.5'), invalidLogin);
  await runWithRoute(bruteParry.middleware(), loginReq('10.50.0.5'), invalidLogin);
  const bruteRun = await runWithRoute(bruteParry.middleware(), loginReq('10.50.0.5'), invalidLogin);
  assert('Brute force block still returns 429', bruteRun.res._status === 429);
  assert(
    'Brute force block generates BRUTE_FORCE_BLOCKED',
    bruteParry.eventBus.getRecentEvents({ type: 'BRUTE_FORCE_BLOCKED' }).pagination.total >= 1
  );

  const wrapperMiddleware = Parry_DDoS({ rateLimit: false, logThreats: false });
  const wrapperRouter = createParryAdminRouter(wrapperMiddleware);
  const wrapperHealth = await runRouter(wrapperRouter, '/health');
  assert(
    'Admin router can resolve context from Parry_DDoS middleware wrapper',
    wrapperHealth.res._status === 200
  );

  const notMountedParry = createParry({ rateLimit: false, logThreats: false });
  const notMounted = await run(
    notMountedParry.middleware(),
    mockReq({ method: 'GET', url: '/_parry/health', originalUrl: '/_parry/health' })
  );
  assert(
    'Admin API is not mounted automatically',
    notMounted.next && notMounted.res._status === 200
  );

  console.log('\n── Observability Integration — Admin API ───────────────────');

  const adminParry = createParry({
    rateLimit: false,
    logThreats: false,
    policies: [loginPolicy()],
  });
  await run(
    adminParry.middleware(),
    mockReq({ ip: '10.50.0.6', body: { q: "' UNION SELECT password FROM users" } })
  );
  adminParry.store.ban('10.50.0.7', 60_000, { reason: 'admin-test' });
  const routeEvent = adminParry.eventBus.emitThreat({
    type: 'ROUTE_RATE_LIMIT_EXCEEDED',
    detector: 'ROUTE_RATE_LIMIT',
    module: 'route-policy',
    severity: 'medium',
    action: 'blocked',
    reason: 'Route policy rate limit exceeded',
    ip: '10.50.0.8',
    method: 'POST',
    path: '/login',
    statusCode: 429,
    policyName: 'auth-login',
    metadata: {
      password: 'admin-event-secret',
      token: 'admin-event-secret',
      rawBody: { password: 'admin-event-secret' },
      headers: {
        authorization: 'Bearer admin-event-secret',
        cookie: 'sid=admin-event-secret',
      },
    },
  });

  const adminRouter = createParryAdminRouter(adminParry);
  const health = await runRouter(adminRouter, '/health');
  assert('GET /health returns ok', health.res._status === 200 && health.res._body.ok === true);
  assert('GET /health includes store metadata', health.res._body.store === 'memory');

  const metrics = await runRouter(adminRouter, '/metrics');
  assert(
    'GET /metrics returns snapshot',
    metrics.res._body.totalRequests >= 1 && metrics.res._body.blockedRequests >= 1
  );

  const events = await runRouter(adminRouter, '/events', { query: { limit: '10' } });
  const firstEvent = events.res._body.data[0];
  assert(
    'GET /events returns paginated list',
    Array.isArray(events.res._body.data) && events.res._body.pagination.total >= 1
  );
  assert(
    'GET /events exposes dashboard-safe event fields',
    typeof firstEvent.id === 'string' &&
      typeof firstEvent.type === 'string' &&
      typeof firstEvent.severity === 'string' &&
      typeof firstEvent.action === 'string' &&
      typeof firstEvent.timestamp === 'string' &&
      typeof firstEvent.ip === 'string' &&
      typeof firstEvent.path === 'string' &&
      typeof firstEvent.method === 'string' &&
      (typeof firstEvent.detector === 'string' || typeof firstEvent.module === 'string')
  );
  assert(
    'GET /events does not expose sensitive metadata values',
    !JSON.stringify(events.res._body).includes('admin-event-secret')
  );

  const filtered = await runRouter(adminRouter, '/events', { query: { severity: 'high' } });
  assert(
    'GET /events filters by severity',
    filtered.res._body.data.every((event) => event.severity === 'high')
  );

  const filteredByContract = await runRouter(adminRouter, '/events', {
    query: {
      limit: '5',
      offset: '0',
      type: 'ROUTE_RATE_LIMIT_EXCEEDED',
      severity: 'medium',
      action: 'blocked',
      detector: 'ROUTE_RATE_LIMIT',
      ip: '10.50.0.8',
      path: '/login',
      policyName: 'auth-login',
    },
  });
  assert(
    'GET /events accepts documented filters',
    filteredByContract.res._body.pagination.total === 1 &&
      filteredByContract.res._body.data[0].id === routeEvent.id
  );

  const byId = await runRouter(adminRouter, `/events/${firstEvent.id}`);
  assert(
    'GET /events/:id returns event by id',
    byId.res._status === 200 && byId.res._body.id === firstEvent.id
  );

  const missing = await runRouter(adminRouter, '/events/missing-event');
  assert(
    'GET /events/:id returns stable 404 for missing event',
    missing.res._status === 404 && missing.res._body.code === 'ADMIN_NOT_FOUND'
  );

  const bans = await runRouter(adminRouter, '/bans');
  assert(
    'GET /bans returns normalized active bans for MemoryStore',
    bans.res._body.data.some(
      (ban) =>
        ban.key === 'ip:10.50.0.7' &&
        ban.type === 'ip' &&
        typeof ban.reason === 'string' &&
        typeof ban.createdAt === 'string' &&
        typeof ban.expiresAt === 'string' &&
        typeof ban.ttlMs === 'number'
    )
  );
  assert('GET /bans returns pagination metadata', bans.res._body.pagination.total >= 1);

  const blockParry = createParry({
    rateLimit: false,
    logThreats: false,
    policies: [loginPolicy()],
  });
  await runWithRoute(blockParry.middleware(), loginReq('10.50.0.9'), invalidLogin);
  await runWithRoute(blockParry.middleware(), loginReq('10.50.0.9'), invalidLogin);
  const blockRouter = createParryAdminRouter(blockParry);
  const blockBans = await runRouter(blockRouter, '/bans');
  assert(
    'GET /bans includes brute force blocks',
    blockBans.res._body.data.some(
      (ban) =>
        ban.type === 'brute-force' &&
        ban.policyName === 'auth-login' &&
        ban.reason === 'max_attempts_exceeded'
    )
  );
  assert(
    'GET /bans does not expose sensitive metadata fields',
    !JSON.stringify(blockBans.res._body).includes('super-secret')
  );

  const policies = await runRouter(adminRouter, '/policies');
  assert(
    'GET /policies returns configured policies',
    policies.res._body.data.some((policy) => policy.name === 'auth-login')
  );
  assert('GET /policies returns pagination metadata', policies.res._body.pagination.total >= 1);

  const protectedRouter = createParryAdminRouter(adminParry, {
    auth: (req) => req.headers['x-admin-token'] === 'secret',
  });
  const denied = await runRouter(protectedRouter, '/health');
  assert(
    'Admin auth callback blocks with stable 401 error shape',
    denied.res._status === 401 && denied.res._body.code === 'ADMIN_UNAUTHORIZED'
  );

  const allowed = await runRouter(protectedRouter, '/health', {
    headers: { 'x-admin-token': 'secret' },
  });
  assert('Admin auth callback allows when it passes', allowed.res._status === 200);

  return { passed, failed };
}

module.exports = runAll().then(() => ({ passed, failed }));
