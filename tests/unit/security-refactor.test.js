'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createParry, createParryAdminRouter } = require('../../src');
const { createAdminAuthMiddleware } = require('../../src/admin/auth');
const { resolveClientIP } = require('../../src/express/ip-resolver');

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
