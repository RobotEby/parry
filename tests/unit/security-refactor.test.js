'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createParry, createParryAdminRouter } = require('../../src');
const { createAdminAuthMiddleware } = require('../../src/admin/auth');
const {
  analyzeRequest,
  deduplicateThreats,
  scanApplicationLayerGuards,
} = require('../../src/core/engine');
const { severityForThreats } = require('../../src/core/scoring');
const { resolveClientIP } = require('../../src/express/ip-resolver');
const { mergeConfig } = require('../../src/express/middleware');
const { collectRequestTargets } = require('../../src/express/request-targets');

function request(overrides = {}) {
  return {
    ip: '127.0.0.1',
    method: 'POST',
    url: '/search',
    originalUrl: '/search',
    headers: {},
    query: {},
    params: {},
    body: {},
    socket: { remoteAddress: '127.0.0.1' },
    ...overrides,
  };
}

function response() {
  return {
    headers: {},
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
    setHeader(name, value) {
      this.headers[name] = value;
    },
  };
}

test('Admin router fails closed without authentication', () => {
  const parry = createParry({ rateLimit: false, logThreats: false });
  assert.throws(() => createParryAdminRouter(parry), /requires authentication/i);
});

test('Admin router accepts explicit local insecure opt-ins', () => {
  const parry = createParry({ rateLimit: false, logThreats: false });
  assert.doesNotThrow(() => createParryAdminRouter(parry, { allowInsecureAdminApi: true }));
  assert.doesNotThrow(() => createParryAdminRouter(parry, { requireAuth: false }));
  assert.doesNotThrow(() => createParryAdminRouter(parry, { auth: { mode: 'none' } }));
});

test('Production rejects every anonymous Admin API override', (t) => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  t.after(() => {
    process.env.NODE_ENV = previous;
  });
  const parry = createParry({ rateLimit: false, logThreats: false });

  assert.throws(
    () => createParryAdminRouter(parry, { allowInsecureAdminApi: true }),
    /not allowed in production/i
  );
  assert.throws(
    () => createParryAdminRouter(parry, { requireAuth: false }),
    /not allowed in production/i
  );
  assert.throws(
    () => createParryAdminRouter(parry, { auth: { mode: 'none' } }),
    /not allowed in production/i
  );
});

test('Admin token must be non-empty and JWT verification is never simulated', () => {
  assert.throws(
    () => createAdminAuthMiddleware({ mode: 'token', token: '  ' }),
    /non-empty token/i
  );
  assert.throws(
    () =>
      createAdminAuthMiddleware({
        mode: 'cloudflare-access',
        trustedProxies: ['127.0.0.1'],
        verifyJwt: true,
      }),
    /does not implement cryptographic JWT\/JWKS verification/i
  );
});

test('NoSQL suspicious operators are allowlisted only at an exact parent path', () => {
  const config = mergeConfig({
    rateLimit: false,
    nosql: { allowedOperators: { 'body.filters.price': ['$gt'] } },
  });
  const allowed = scanApplicationLayerGuards(
    request({ body: { filters: { price: { $gt: 10 } } } }),
    config
  );
  assert.equal(
    allowed.some((finding) => finding.detector === 'NOSQL_INJECTION'),
    false
  );

  const denied = scanApplicationLayerGuards(
    request({ body: { filters: { discount: { $gt: 10 } } } }),
    config
  );
  assert.equal(
    denied.find((finding) => finding.detector === 'NOSQL_INJECTION')?.field,
    'body.filters.discount.$gt'
  );
});

test('Dangerous NoSQL operators can never be allowlisted', () => {
  for (const operator of ['$where', '$expr', '$function', '$accumulator']) {
    assert.throws(
      () =>
        mergeConfig({
          nosql: { allowedOperators: { 'body.filters': [operator] } },
        }),
      /can never be allowlisted/i
    );
  }
});

test('Allowed NoSQL parents do not hide unauthorized nested objects', () => {
  const config = mergeConfig({
    rateLimit: false,
    nosql: { allowedOperators: { 'body.filters': ['$or'] } },
  });
  const findings = scanApplicationLayerGuards(
    request({ body: { filters: { $or: [{ price: { $gt: 10 } }] } } }),
    config
  );
  assert.match(
    findings.find((finding) => finding.detector === 'NOSQL_INJECTION')?.field || '',
    /price\.\$gt$/
  );
});

test('Header selection is normalized, deduplicated, and configurable', () => {
  const config = mergeConfig({ headers: { scan: ['X-Custom', 'x-custom', 'REFERER'] } });
  assert.deepEqual(config.headers.scan, ['x-custom', 'referer']);
  const targets = collectRequestTargets(
    request({ headers: { 'X-Custom': '<script>alert(1)</script>', referer: 'safe' } }),
    config
  );
  assert.deepEqual(
    targets.map((target) => target.label),
    ['header.x-custom', 'header.referer']
  );
  assert.equal(collectRequestTargets(request(), mergeConfig({ headers: { scan: [] } })).length, 0);
});

test('Scalar target collection serializes leaves once and skips whole objects', () => {
  const targets = collectRequestTargets(
    request({ body: { profile: { name: 'Ada', active: true }, tags: ['one', 'two'] } }),
    mergeConfig({ headers: { scan: [] } })
  );
  assert.deepEqual(
    targets.map(({ label, stringValue }) => [label, stringValue]),
    [
      ['body.profile.name', 'Ada'],
      ['body.profile.active', 'true'],
      ['body.tags[0]', 'one'],
      ['body.tags[1]', 'two'],
    ]
  );
});

test('Shape violations short-circuit all heavier scans', async () => {
  const config = mergeConfig({
    rateLimit: false,
    requestShape: { maxStringLength: 4 },
  });
  const decision = await analyzeRequest(request({ body: { payload: "' OR 1=1 --" } }), {
    config,
    rateLimiter: null,
    logger: null,
  });
  assert.deepEqual(
    decision.threats.map((finding) => finding.detector),
    ['REQUEST_SHAPE']
  );
});

test('Findings are deduplicated by detector, field, pattern, and reason', () => {
  const finding = { detector: 'XSS', field: 'body.name', pattern: '/script/i' };
  assert.deepEqual(deduplicateThreats([finding, { ...finding }]), [finding]);
  assert.equal(deduplicateThreats([finding, { ...finding, field: 'body.other' }]).length, 2);
});

test('Aggregate severity uses the most severe finding', () => {
  assert.equal(
    severityForThreats([{ detector: 'REQUEST_SHAPE' }, { detector: 'SQL_INJECTION' }]),
    'high'
  );
});

test('Request IDs use crypto.randomUUID and preserve configured input headers', async () => {
  const parry = createParry({
    rateLimit: false,
    logThreats: false,
    requestId: { responseHeader: 'x-parry-request-id' },
  });
  const generated = request();
  const generatedResponse = response();
  await parry.middleware()(generated, generatedResponse, () => {});
  assert.match(
    generated.parry.requestId,
    /^req_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
  );
  assert.equal(generatedResponse.headers['x-parry-request-id'], generated.parry.requestId);

  const preserved = request({ headers: { 'x-request-id': 'upstream-id' } });
  await parry.middleware()(preserved, response(), () => {});
  assert.equal(preserved.parry.requestId, 'upstream-id');
});

test('Forwarded headers are ignored from an untrusted direct peer', () => {
  const req = request({
    socket: { remoteAddress: '198.51.100.8' },
    headers: { 'x-forwarded-for': '203.0.113.7' },
  });
  assert.equal(
    resolveClientIP(req, { trustProxyHeaders: true, trustedProxies: ['10.0.0.0/8'] }),
    '198.51.100.8'
  );
});

test('Proxy chains are resolved from right to left across Cloudflare and ALB', () => {
  const req = request({
    socket: { remoteAddress: '173.245.48.10' },
    headers: { 'x-forwarded-for': '203.0.113.7, 10.20.30.40' },
  });
  assert.equal(
    resolveClientIP(req, {
      trustProxyHeaders: true,
      trustedProxies: ['173.245.48.0/20', '10.0.0.0/8'],
    }),
    '203.0.113.7'
  );
});

test('Proxy chains select the first untrusted hop from the right', () => {
  const req = request({
    socket: { remoteAddress: '10.0.0.2' },
    headers: { 'x-forwarded-for': '203.0.113.7, 198.51.100.20, 10.0.0.3' },
  });
  assert.equal(
    resolveClientIP(req, {
      trustProxyHeaders: true,
      trustedProxies: ['10.0.0.0/8'],
    }),
    '198.51.100.20'
  );
});

test('Malformed, empty, and overlong proxy chains fall back to the direct IP', () => {
  const options = { trustProxyHeaders: true, trustedProxies: ['10.0.0.0/8'] };
  const direct = { remoteAddress: '10.0.0.2' };
  assert.equal(
    resolveClientIP(request({ socket: direct, headers: { 'x-forwarded-for': 'bad-ip' } }), options),
    '10.0.0.2'
  );
  assert.equal(
    resolveClientIP(request({ socket: direct, headers: { 'x-forwarded-for': ' ,' } }), options),
    '10.0.0.2'
  );
  assert.equal(
    resolveClientIP(
      request({
        socket: direct,
        headers: { 'x-forwarded-for': Array.from({ length: 21 }, () => '10.0.0.3').join(',') },
      }),
      options
    ),
    '10.0.0.2'
  );
});

test('IPv6 proxy CIDRs are supported', () => {
  assert.equal(
    resolveClientIP(
      request({
        socket: { remoteAddress: '2001:db8:1::2' },
        headers: { 'x-forwarded-for': '2001:db8:ffff::9' },
      }),
      { trustProxyHeaders: true, trustedProxies: ['2001:db8:1::/48'] }
    ),
    '2001:db8:ffff::9'
  );
});

test('Invalid limits, policy matches, headers, events, and CIDRs fail during construction', () => {
  const invalidOptions = [
    { maxRequests: 0 },
    { windowMs: -1 },
    { maxObjectDepth: -1 },
    { events: { maxEvents: 0 } },
    { headers: { scan: ['bad header'] } },
    { requestId: { responseHeader: 'bad header' } },
    { admin: { path: 'missing-slash' } },
    { trustedProxies: ['not-an-ip'] },
    { policies: [{ name: 'empty-match', match: {} }] },
    { policies: [{ name: 'bad-rate', match: { path: '/' }, rateLimit: { max: 0 } }] },
  ];
  for (const options of invalidOptions) {
    assert.throws(() => createParry(options));
  }
});
