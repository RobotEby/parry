'use strict';

const { test } = require('node:test');
const nodeAssert = require('node:assert/strict');
const { EventEmitter } = require('events');
const { Parry_DDoS } = require('../../src/express/middleware');
const { SQL_MALICIOUS, XSS_MALICIOUS, NOSQL_MALICIOUS_OBJECTS } = require('../fixtures/payloads');
const {
  HPP_DUPLICATE_QUERY,
  HPP_ALLOWED_QUERY,
  PROTOTYPE_POLLUTION_BODY,
  PATH_TRAVERSAL_VALUES,
  PATH_TRAVERSAL_CLEAN_VALUES,
  SHAPE_LIMITS,
} = require('../fixtures/application-layer');

function assert(description, condition) {
  nodeAssert.ok(condition, description);
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

function mockRes() {
  const emitter = new EventEmitter();
  const res = { _status: 200, _body: null, _headers: {} };
  res.statusCode = 200;
  res.status = (s) => {
    res._status = s;
    res.statusCode = s;
    return res;
  };
  res.json = (b) => {
    res._body = b;
    return res;
  };
  res.setHeader = (k, v) => {
    res._headers[k] = v;
  };
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
      resolve({ res, next: called });
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
      resolve({ res, req, next: called });
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

// ── Each group uses its own IP address and instance to isolate counters ───────────

async function runAll() {
  console.log('\n── Middleware — Clean Requests ─────────────────────────');
  const mwClean = Parry_DDoS({
    sql: true,
    xss: true,
    nosql: true,
    rateLimit: false,
    logThreats: false,
  });
  const { next: cleanNext } = await run(
    mwClean,
    mockReq({ body: { username: 'alice', age: 30 }, query: { q: 'cadeira' } })
  );
  assert('Clean request reaches next()', cleanNext);

  console.log('\n── Middleware — Trusted Proxy IP Resolver ──────────────────');
  let spoofEvent = null;
  const mwNoTrustProxy = Parry_DDoS({
    rateLimit: false,
    logThreats: false,
    onThreat: (event) => {
      spoofEvent = event;
    },
  });
  await run(
    mwNoTrustProxy,
    mockReq({
      ip: '10.0.0.20',
      socket: { remoteAddress: '10.0.0.10' },
      headers: { 'x-forwarded-for': '198.51.100.10' },
      body: { username: "' OR 1=1 --" },
    })
  );
  assert('Ignores x-forwarded-for by default', spoofEvent?.ip === '10.0.0.10');

  let trustedProxyEvent = null;
  const mwTrustedProxy = Parry_DDoS({
    rateLimit: false,
    logThreats: false,
    trustProxyHeaders: true,
    trustedProxies: ['10.0.0.10'],
    onThreat: (event) => {
      trustedProxyEvent = event;
    },
  });
  await run(
    mwTrustedProxy,
    mockReq({
      socket: { remoteAddress: '10.0.0.10' },
      headers: { 'x-forwarded-for': '198.51.100.11, 10.0.0.10' },
      body: { username: "' OR 1=1 --" },
    })
  );
  assert('Uses x-forwarded-for only from trusted proxy', trustedProxyEvent?.ip === '198.51.100.11');

  let untrustedProxyEvent = null;
  const mwUntrustedProxy = Parry_DDoS({
    rateLimit: false,
    logThreats: false,
    trustProxyHeaders: true,
    trustedProxies: ['10.0.0.99'],
    onThreat: (event) => {
      untrustedProxyEvent = event;
    },
  });
  await run(
    mwUntrustedProxy,
    mockReq({
      socket: { remoteAddress: '10.0.0.10' },
      headers: { 'x-forwarded-for': '198.51.100.12' },
      body: { username: "' OR 1=1 --" },
    })
  );
  assert('Ignores x-forwarded-for from untrusted proxy', untrustedProxyEvent?.ip === '10.0.0.10');

  console.log('\n── Middleware — SQL Injection ───────────────────────────────');
  const mwSql = Parry_DDoS({ sql: true, rateLimit: false, logThreats: false });
  for (let i = 0; i < 3; i++) {
    const { res, next } = await run(mwSql, mockReq({ body: { username: SQL_MALICIOUS[i] } }));
    assert(`Blocks SQL payload #${i + 1}`, res._status === 400 && !next);
    assert(
      `Response indicates SQL_INJECTION #${i + 1}`,
      res._body?.threats?.some((t) => t.detector === 'SQL_INJECTION')
    );
  }

  console.log('\n── Middleware — XSS ─────────────────────────────────────────');
  const mwXss = Parry_DDoS({ xss: true, rateLimit: false, logThreats: false });
  for (let i = 0; i < 3; i++) {
    const { res, next } = await run(mwXss, mockReq({ query: { search: XSS_MALICIOUS[i] } }));
    assert(`Blocks XSS payload #${i + 1}`, res._status === 400 && !next);
    assert(
      `Response indicates XSS #${i + 1}`,
      res._body?.threats?.some((t) => t.detector === 'XSS')
    );
  }

  console.log('\n── Middleware — NoSQL Injection ─────────────────────────────');
  const mwNosql = Parry_DDoS({
    nosql: true,
    rateLimit: false,
    logThreats: false,
  });
  for (let i = 0; i < 3; i++) {
    const { res, next } = await run(
      mwNosql,
      mockReq({ body: { filter: NOSQL_MALICIOUS_OBJECTS[i] } })
    );
    assert(`Blocks NoSQL payload #${i + 1}`, res._status === 400 && !next);
    assert(
      `Response indicates NOSQL_INJECTION #${i + 1}`,
      res._body?.threats?.some((t) => t.detector === 'NOSQL_INJECTION')
    );
  }

  console.log('\n── Middleware — Rate Limiting ───────────────────────────────');
  const mwRl = Parry_DDoS({
    rateLimit: true,
    maxRequests: 3,
    windowMs: 5_000,
    suspiciousThreshold: 20,
    banDurationMs: 1_000,
    logThreats: false,
  });
  const rlIp = () =>
    mockReq({
      ip: '192.168.99.1',
      headers: {},
      body: {},
      query: {},
      params: {},
    });
  await run(mwRl, rlIp());
  await run(mwRl, rlIp());
  await run(mwRl, rlIp());
  const { res: limited } = await run(mwRl, rlIp());
  assert('4th request returns 429 by rate limit', limited._status === 429);

  console.log('\n── Middleware — Headers X-RateLimit ──────────────────────');
  const mwHdr = Parry_DDoS({
    rateLimit: true,
    maxRequests: 50,
    windowMs: 60_000,
    logThreats: false,
  });
  const { res: hRes } = await run(
    mwHdr,
    mockReq({ ip: '10.10.10.1', headers: {}, body: {}, query: {}, params: {} })
  );
  assert('X-RateLimit-Limit is present', 'X-RateLimit-Limit' in hRes._headers);
  assert('X-RateLimit-Remaining is present', 'X-RateLimit-Remaining' in hRes._headers);
  assert('X-RateLimit-Reset is present', 'X-RateLimit-Reset' in hRes._headers);

  const mwNestedHdr = Parry_DDoS({
    rateLimit: { enabled: true, max: 25, windowMs: 60_000, headers: true },
    logThreats: false,
  });
  const { res: nestedHdrRes } = await run(
    mwNestedHdr,
    mockReq({ ip: '10.10.10.2', headers: {}, body: {}, query: {}, params: {} })
  );
  assert(
    'Nested rateLimit config sets limit header',
    nestedHdrRes._headers['X-RateLimit-Limit'] === 25
  );

  console.log('\n── Middleware — Store Failure Modes ───────────────────────');
  const throwingStore = {
    async isBanned() {
      throw new Error('redis unavailable');
    },
    async incrementRateLimit() {
      throw new Error('redis unavailable');
    },
    async recordSuspicious() {
      throw new Error('redis unavailable');
    },
  };
  const mwFailOpen = Parry_DDoS({
    store: throwingStore,
    storeFailureMode: 'fail-open',
    logThreats: false,
  });
  const { next: failOpenNext, res: failOpenRes } = await run(
    mwFailOpen,
    mockReq({ ip: '10.10.20.1', body: {}, query: {}, params: {} })
  );
  assert(
    'fail-open allows clean request when store fails',
    failOpenNext && failOpenRes._status === 200
  );
  assert(
    'fail-open omits rate limit headers without store result',
    !('X-RateLimit-Limit' in failOpenRes._headers)
  );

  const { res: failOpenThreatRes, next: failOpenThreatNext } = await run(
    mwFailOpen,
    mockReq({ ip: '10.10.20.2', body: { q: "' OR 1=1 --" }, query: {}, params: {} })
  );
  assert(
    'fail-open keeps detectors active when store fails',
    failOpenThreatRes._status === 400 && !failOpenThreatNext
  );

  const mwFailClosed = Parry_DDoS({
    store: throwingStore,
    storeFailureMode: 'fail-closed',
    logThreats: false,
  });
  const { res: failClosedRes, next: failClosedNext } = await run(
    mwFailClosed,
    mockReq({ ip: '10.10.20.3', body: {}, query: {}, params: {} })
  );
  assert('fail-closed blocks when store fails', failClosedRes._status === 503 && !failClosedNext);

  console.log('\n── Middleware — Brute Force Policies ──────────────────────');
  const loginPolicy = {
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
  };
  const mwLogin = Parry_DDoS({
    rateLimit: false,
    logThreats: false,
    policies: [loginPolicy],
  });
  const loginReq = (ip, body = {}) =>
    mockReq({
      method: 'POST',
      url: '/login',
      originalUrl: '/login',
      ip,
      body: { email: 'USER@example.com', password: 'super-secret', ...body },
      query: {},
      params: {},
    });
  const invalidLogin = (_req, res) => res.status(401).json({ success: false });

  await runWithRoute(mwLogin, loginReq('10.20.30.1'), invalidLogin);
  await runWithRoute(mwLogin, loginReq('10.20.30.1'), invalidLogin);
  const { res: bruteBlocked, next: bruteBlockedNext } = await runWithRoute(
    mwLogin,
    loginReq('10.20.30.1'),
    invalidLogin
  );
  assert(
    'POST /login invalid credentials blocks after limit',
    bruteBlocked._status === 429 && !bruteBlockedNext
  );
  assert('Brute force block includes Retry-After', 'Retry-After' in bruteBlocked._headers);
  const blockedBody = JSON.stringify(bruteBlocked._body);
  assert(
    'Brute force response does not leak email or password',
    !blockedBody.includes('USER@example.com') && !blockedBody.includes('super-secret')
  );

  const mwLoginReset = Parry_DDoS({
    rateLimit: false,
    logThreats: false,
    policies: [loginPolicy],
  });
  await runWithRoute(mwLoginReset, loginReq('10.20.30.2'), invalidLogin);
  await runWithRoute(mwLoginReset, loginReq('10.20.30.2'), (_req, res) =>
    res.status(200).json({ success: true })
  );
  await runWithRoute(mwLoginReset, loginReq('10.20.30.2'), invalidLogin);
  const { next: resetStillAllowed } = await runWithRoute(
    mwLoginReset,
    loginReq('10.20.30.2'),
    invalidLogin
  );
  assert('POST /login success resets brute force counter', resetStillAllowed);

  const mwRouteRate = Parry_DDoS({
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
  await runWithRoute(mwRouteRate, loginReq('10.20.30.3'), (_req, res) =>
    res.status(200).json({ ok: true })
  );
  const { res: routeLimited, next: routeLimitedNext } = await runWithRoute(
    mwRouteRate,
    loginReq('10.20.30.3'),
    (_req, res) => res.status(200).json({ ok: true })
  );
  assert(
    'Policy-specific route rate limit differs from global limit',
    routeLimited._status === 429 && !routeLimitedNext
  );

  const { next: unprotectedNext } = await runWithRoute(
    mwLogin,
    mockReq({
      method: 'POST',
      url: '/profile',
      originalUrl: '/profile',
      ip: '10.20.30.4',
      body: { email: 'USER@example.com', password: 'super-secret' },
    }),
    invalidLogin
  );
  const { next: unprotectedNextAgain } = await runWithRoute(
    mwLogin,
    mockReq({
      method: 'POST',
      url: '/profile',
      originalUrl: '/profile',
      ip: '10.20.30.4',
      body: { email: 'USER@example.com', password: 'super-secret' },
    }),
    invalidLogin
  );
  assert(
    'Unprotected route is not affected by brute force guard',
    unprotectedNext && unprotectedNextAgain
  );

  const existingParryReq = loginReq('10.20.30.5', { email: 'preserve@example.com' });
  existingParryReq.parry = { traceId: 'trace-123' };
  const mwLoginPreserve = Parry_DDoS({
    rateLimit: false,
    logThreats: false,
    policies: [loginPolicy],
  });
  let preservedParry = false;
  await runWithRoute(mwLoginPreserve, existingParryReq, (req, res) => {
    preservedParry =
      req.parry.traceId === 'trace-123' &&
      typeof req.parry.recordAuthFailure === 'function' &&
      typeof req.parry.recordAuthSuccess === 'function';
    return res.status(200).json({ ok: true });
  });
  assert('req.parry preserves existing fields and adds auth helpers', preservedParry);

  console.log('\n── Middleware — Callback onThreat ───────────────────────────');
  let callbackFired = false;
  const mwCb = Parry_DDoS({
    sql: true,
    rateLimit: false,
    logThreats: false,
    onThreat: () => {
      callbackFired = true;
    },
  });
  await run(mwCb, mockReq({ body: { q: "' OR 1=1 --" } }));
  assert('onThreat callback is called when threat is detected', callbackFired);

  const mwCbThrows = Parry_DDoS({
    sql: true,
    rateLimit: false,
    logThreats: false,
    onThreat: () => {
      throw new Error('hook failed');
    },
  });
  const { res: cbThrowRes, next: cbThrowNext } = await run(
    mwCbThrows,
    mockReq({ body: { q: "' OR 1=1 --" } })
  );
  assert(
    'onThreat errors do not break blocked response',
    cbThrowRes._status === 400 && !cbThrowNext
  );

  console.log('\n── Middleware — Injection in nested body ──────────────────────');
  const mwNested = Parry_DDoS({
    sql: true,
    rateLimit: false,
    logThreats: false,
  });
  const { res: nestedRes, next: nestedNext } = await run(
    mwNested,
    mockReq({
      body: { user: { profile: { bio: "' UNION SELECT * FROM users" } } },
    })
  );
  assert(
    'Detects SQL in a nested field (body.user.profile.bio)',
    nestedRes._status === 400 && !nestedNext
  );

  console.log('\n── Middleware — Injection in query param ──────────────────────');
  const mwQp = Parry_DDoS({ xss: true, rateLimit: false, logThreats: false });
  const { res: qRes, next: qNext } = await run(
    mwQp,
    mockReq({ query: { id: '<script>alert(1)</script>' } })
  );
  assert('Detects XSS in query param', qRes._status === 400 && !qNext);

  console.log('\n── Middleware — Application-Layer Guards ───────────────────');
  let structuredEvent = null;
  const mwHpp = Parry_DDoS({
    hpp: { enabled: true },
    rateLimit: false,
    logThreats: false,
    onThreat: (entry) => {
      structuredEvent = entry;
    },
  });
  const { res: hppRes, next: hppNext } = await run(mwHpp, mockReq({ query: HPP_DUPLICATE_QUERY }));
  assert('Blocks duplicated query param when HPP is enabled', hppRes._status === 400 && !hppNext);
  assert(
    'HPP response includes detector and reason',
    hppRes._body?.threats?.some(
      (t) => t.detector === 'HTTP_PARAMETER_POLLUTION' && t.reason?.includes('Duplicate')
    )
  );
  assert(
    'Threat event includes structured top-level fields',
    structuredEvent?.detector === 'hpp' &&
      structuredEvent.detectorType === 'HTTP_PARAMETER_POLLUTION' &&
      structuredEvent.severity === 'medium' &&
      structuredEvent.reason &&
      structuredEvent.target === 'query.id' &&
      structuredEvent.ip
  );

  const mwHppAllowed = Parry_DDoS({
    hpp: { enabled: true, allowDuplicateParamsFor: ['tags'] },
    rateLimit: false,
    logThreats: false,
  });
  const { next: hppAllowedNext } = await run(mwHppAllowed, mockReq({ query: HPP_ALLOWED_QUERY }));
  assert('Allows configured duplicate query params', hppAllowedNext);

  const mwHppDisabled = Parry_DDoS({
    hpp: { enabled: false },
    rateLimit: false,
    logThreats: false,
  });
  const { next: hppDisabledNext } = await run(
    mwHppDisabled,
    mockReq({ query: HPP_DUPLICATE_QUERY })
  );
  assert('Allows duplicated query param when HPP is disabled', hppDisabledNext);

  const mwProto = Parry_DDoS({ rateLimit: false, logThreats: false });
  const { res: protoRes, next: protoNext } = await run(
    mwProto,
    mockReq({ body: PROTOTYPE_POLLUTION_BODY })
  );
  assert('Blocks Prototype Pollution payloads by default', protoRes._status === 400 && !protoNext);

  const mwProtoDisabled = Parry_DDoS({
    prototypePollution: { enabled: false },
    rateLimit: false,
    logThreats: false,
  });
  const { next: protoDisabledNext } = await run(
    mwProtoDisabled,
    mockReq({ body: PROTOTYPE_POLLUTION_BODY })
  );
  assert('Allows Prototype Pollution payload when detector is disabled', protoDisabledNext);

  const mwTraversal = Parry_DDoS({ rateLimit: false, logThreats: false });
  for (let i = 0; i < PATH_TRAVERSAL_VALUES.length; i++) {
    const { res, next } = await run(
      mwTraversal,
      mockReq({ query: { file: PATH_TRAVERSAL_VALUES[i] } })
    );
    assert(`Blocks Path Traversal payload #${i + 1}`, res._status === 400 && !next);
  }
  const { next: traversalCleanNext } = await run(
    mwTraversal,
    mockReq({ query: { note: PATH_TRAVERSAL_CLEAN_VALUES[0] } })
  );
  assert('Allows clean path-like text', traversalCleanNext);

  const mwTraversalDisabled = Parry_DDoS({
    pathTraversal: { enabled: false },
    rateLimit: false,
    logThreats: false,
  });
  const { next: traversalDisabledNext } = await run(
    mwTraversalDisabled,
    mockReq({ query: { file: PATH_TRAVERSAL_VALUES[0] } })
  );
  assert('Allows Path Traversal payload when detector is disabled', traversalDisabledNext);

  const mwShape = Parry_DDoS({
    requestShape: { ...SHAPE_LIMITS },
    rateLimit: false,
    logThreats: false,
  });
  const { res: shapeRes, next: shapeNext } = await run(
    mwShape,
    mockReq({ body: { text: 'x'.repeat(SHAPE_LIMITS.maxStringLength + 1) } })
  );
  assert('Blocks request shape limit violations', shapeRes._status === 400 && !shapeNext);
  assert(
    'Request shape response includes reason',
    shapeRes._body?.threats?.some((t) => t.detector === 'REQUEST_SHAPE' && t.reason)
  );

  const mwShapeDisabled = Parry_DDoS({
    requestShape: { enabled: false, ...SHAPE_LIMITS },
    rateLimit: false,
    logThreats: false,
  });
  const { next: shapeDisabledNext } = await run(
    mwShapeDisabled,
    mockReq({ body: { text: 'x'.repeat(SHAPE_LIMITS.maxStringLength + 1) } })
  );
  assert('Allows request shape violation when guard is disabled', shapeDisabledNext);

  console.log('\n── Middleware — Ban for suspicious activity ──────────────────');
  const mwBan = Parry_DDoS({
    sql: true,
    rateLimit: true,
    logThreats: false,
    maxRequests: 100,
    windowMs: 60_000,
    suspiciousThreshold: 2,
    banDurationMs: 5_000,
  });
  const banIp = () => mockReq({ ip: '10.0.99.1', headers: {}, body: {}, query: {}, params: {} });
  await run(mwBan, { ...banIp(), body: { u: "' OR 1=1 --" } });
  await run(mwBan, { ...banIp(), body: { u: "' OR 1=1 --" } });
  const { res: banRes } = await run(mwBan, banIp());
  assert('Banned IP returns 429 after 2 suspicious attempts', banRes._status === 429);
}

test('Middleware integration', runAll);
