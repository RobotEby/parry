'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createParry } = require('../../src');

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
