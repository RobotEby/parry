'use strict';

const { test } = require('node:test');
const nodeAssert = require('node:assert/strict');

const { createParry } = require('../../src');
const { DETECTOR_TO_INTERNAL, loadFixtures } = require('../../scripts/payloads/fixture-utils');
const { mockReq, requestFromFixture, runMiddleware } = require('./fixture-helpers');


function assert(description, condition) {
  nodeAssert.ok(condition, description);
}

async function runAll() {
  console.log('\n── Middleware Payload Regression ───────────────────────────');

  const { byCategory } = loadFixtures();
  const blockedCategories = [
    'sql',
    'xss',
    'nosql',
    'hpp',
    'prototype-pollution',
    'path-traversal',
    'request-shape',
  ];

  for (const category of blockedCategories) {
    for (const fixture of byCategory[category]) {
      const result = await runBlockedFixture(fixture);
      assert(`${category} fixture ${fixture.id} returns 400`, result.res._status === 400 && !result.next);
      assert(`${category} fixture ${fixture.id} response includes detector`, responseHasDetector(result.res, fixture.expected.detector));
      assert(`${category} fixture ${fixture.id} emits structured event`, eventMatches(result.event, fixture));
      assert(`${category} fixture ${fixture.id} event does not leak secrets`, eventHasNoSecrets(result.event));
    }
  }

  for (const fixture of byCategory.benign) {
    const result = await runAllowedFixture(fixture);
    assert(`Benign fixture ${fixture.id} reaches next`, result.next && result.res._status === 200);
  }

  for (const fixture of byCategory['command-injection']) {
    const result = await runAllowedFixture(fixture);
    assert(`Command Injection monitor fixture ${fixture.id} is not executed or blocked`, result.next && result.res._status === 200);
  }

  for (const fixture of byCategory.ssrf) {
    const result = await runAllowedFixture(fixture);
    assert(`SSRF monitor fixture ${fixture.id} does not make requests or block`, result.next && result.res._status === 200);
  }

  for (const fixture of byCategory['brute-force']) {
    const blocked = await runBruteForceScenario(fixture);
    assert(`Brute force scenario ${fixture.id} matches expected block state`, blocked === fixture.expected.blocked);
  }
}

async function runBlockedFixture(fixture) {
  let event = null;
  const parry = createParry({
    rateLimit: false,
    logThreats: false,
    hpp: { enabled: true, allowDuplicateParamsFor: ['tags', 'filters'] },
    onThreat(entry) {
      event = entry;
    },
  });
  const req = requestFromFixture(fixture, { ip: `203.0.113.${Math.floor(Math.random() * 100) + 1}` });
  const result = await runMiddleware(parry.middleware(), req);
  return { ...result, event };
}

async function runAllowedFixture(fixture) {
  const parry = createParry({
    rateLimit: false,
    logThreats: false,
    hpp: { enabled: true, allowDuplicateParamsFor: ['tags', 'filters', 'sort'] },
  });
  const req = requestFromFixture(fixture);
  return runMiddleware(parry.middleware(), req);
}

function responseHasDetector(res, detectorSlug) {
  const internal = DETECTOR_TO_INTERNAL[detectorSlug];
  return res._body?.threats?.some((threat) => threat.detector === internal);
}

function eventMatches(event, fixture) {
  return Boolean(
    event &&
      event.type &&
      event.action === 'blocked' &&
      event.reason &&
      event.ip &&
      event.path &&
      event.detectorSlug === fixture.expected.detector &&
      event.severity === fixture.expected.severity
  );
}

function eventHasNoSecrets(event) {
  const text = JSON.stringify(event || {});
  return (
    !text.includes('should-not-leak') &&
    !text.toLowerCase().includes('authorization') &&
    !text.toLowerCase().includes('cookie') &&
    !text.toLowerCase().includes('password') &&
    !text.toLowerCase().includes('token')
  );
}

async function runBruteForceScenario(fixture) {
  const payload = fixture.payload || {};
  const keys = payload.keys || ['ip', 'body.email', 'ip+body.email'];
  const parry = createParry({
    rateLimit: false,
    logThreats: false,
    policies: [
      {
        name: 'auth-login',
        match: { method: 'POST', path: '/login' },
        bruteForce: {
          enabled: true,
          maxAttempts: 2,
          windowMs: 60_000,
          blockDurationMs: 60_000,
          keys,
          resetOnSuccess: true,
        },
      },
    ],
  });
  const middleware = parry.middleware();
  const ip = `198.51.100.${Math.floor(Math.random() * 100) + 1}`;
  const path = payload.path || '/login';

  if (fixture.id === 'brute-force-unprotected-001') {
    for (let i = 0; i < payload.failures; i++) {
      const result = await runMiddleware(middleware, loginReq({ ip, path, payload }), invalidLogin);
      if (!result.next) return true;
    }
    return false;
  }

  const failuresBeforeSuccess = payload.failuresBeforeSuccess || 0;
  for (let i = 0; i < failuresBeforeSuccess; i++) {
    await runMiddleware(middleware, loginReq({ ip, path, payload }), invalidLogin);
  }

  if (payload.success || payload.manualSuccess) {
    await runMiddleware(middleware, loginReq({ ip, path, payload }), (req, res) => {
      if (payload.manualSuccess) req.parry.recordAuthSuccess();
      return res.status(200).json({ success: true });
    });
  }

  const failureCount = payload.failures || payload.failuresAfterSuccess || 0;
  for (let i = 0; i < failureCount; i++) {
    await runMiddleware(
      middleware,
      loginReq({ ip, path, payload }),
      payload.manualFailure ? manualFailureLogin : invalidLogin
    );
  }

  const final = await runMiddleware(
    middleware,
    loginReq({ ip, path, payload }),
    payload.manualFailure ? manualFailureLogin : invalidLogin
  );

  if (fixture.id === 'brute-force-no-leak-001') {
    const responseText = JSON.stringify(final.res._body || {});
    return final.res._status === 429 && !responseText.includes(payload.email) && !responseText.includes(payload.password);
  }

  if (fixture.expected.blocked) {
    return final.res._status === 429 && 'Retry-After' in final.res._headers;
  }

  return final.next && final.res._status === 200;
}

function loginReq({ ip, path, payload }) {
  return mockReq({
    method: 'POST',
    url: path,
    originalUrl: path,
    ip,
    body: {
      email: payload.email || undefined,
      username: payload.username || undefined,
      password: payload.password || 'not-used',
    },
  });
}

function invalidLogin(_req, res) {
  return res.status(401).json({ success: false });
}

function manualFailureLogin(req, res) {
  req.parry.recordAuthFailure('fixture_invalid_credentials');
  return res.status(200).json({ success: false });
}

test('Middleware payload regression', runAll);
