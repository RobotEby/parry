'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createParry, createParryAdminRouter } = require('../../src');
const { createAdminAuthMiddleware } = require('../../src/admin/auth');

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
