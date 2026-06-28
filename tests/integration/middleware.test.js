'use strict';

const { Parry_DDoS } = require('../../src/middleware/index.js');
const { SQL_MALICIOUS, XSS_MALICIOUS, NOSQL_MALICIOUS_OBJECTS } = require('../fixtures/payloads');

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

function mockRes() {
  const res = { _status: 200, _body: null, _headers: {} };
  res.status = (s) => {
    res._status = s;
    return res;
  };
  res.json = (b) => {
    res._body = b;
    return res;
  };
  res.setHeader = (k, v) => {
    res._headers[k] = v;
  };
  return res;
}

function run(mw, req) {
  return new Promise((resolve) => {
    const res = mockRes();
    let called = false;
    mw(req, res, () => {
      called = true;
    });
    resolve({ res, next: called });
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
  assert('onThreat errors do not break blocked response', cbThrowRes._status === 400 && !cbThrowNext);

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

module.exports = runAll().then(() => ({ passed, failed }));
