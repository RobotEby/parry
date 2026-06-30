'use strict';

const { EventEmitter } = require('events');
const { createAdminAuthMiddleware, requireAdminAuth } = require('../../src/admin/auth');

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
    ip: '127.0.0.1',
    headers: {},
    socket: { remoteAddress: '127.0.0.1' },
    ...overrides,
  };
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

function runAuth(middleware, req = mockReq()) {
  return new Promise((resolve, reject) => {
    const res = mockRes();
    let nextCalled = false;

    Promise.resolve(
      middleware(req, res, (error) => {
        if (error) return reject(error);
        nextCalled = true;
      })
    )
      .then(() => resolve({ req, res, nextCalled }))
      .catch(reject);
  });
}

async function runAll() {
  console.log('\n── Admin Auth — Token ──────────────────────────────────────');

  const tokenAuth = createAdminAuthMiddleware({ mode: 'token', token: 'secret-token' });
  const missingToken = await runAuth(tokenAuth);
  assert(
    'Token auth returns 401 when token is absent',
    missingToken.res._status === 401 &&
      missingToken.res._body.error.code === 'ADMIN_UNAUTHORIZED'
  );

  const wrongToken = await runAuth(
    tokenAuth,
    mockReq({ headers: { 'x-parry-admin-token': 'wrong-token' } })
  );
  assert(
    'Token auth returns 403 when token is wrong',
    wrongToken.res._status === 403 && wrongToken.res._body.error.code === 'ADMIN_FORBIDDEN'
  );

  const validToken = await runAuth(
    tokenAuth,
    mockReq({ headers: { 'x-parry-admin-token': 'secret-token' } })
  );
  assert(
    'Token auth allows correct token and attaches req.parryAdmin',
    validToken.nextCalled &&
      validToken.req.parryAdmin.authenticated === true &&
      validToken.req.parryAdmin.strategy === 'token' &&
      validToken.req.parryAdmin.subject === 'local-token'
  );

  assert(
    'Token auth does not return expected token',
    !JSON.stringify(wrongToken.res._body).includes('secret-token')
  );

  console.log('\n── Admin Auth — IP Allowlist ───────────────────────────────');

  const exactIp = createAdminAuthMiddleware({
    mode: 'ip-allowlist',
    allowedIps: ['127.0.0.1'],
  });
  assert('IP allowlist permits exact IP', (await runAuth(exactIp)).nextCalled);

  const deniedIp = await runAuth(
    exactIp,
    mockReq({ ip: '203.0.113.10', socket: { remoteAddress: '203.0.113.10' } })
  );
  assert('IP allowlist denies unlisted IP with 403', deniedIp.res._status === 403);

  const cidrIp = createAdminAuthMiddleware({
    mode: 'ip-allowlist',
    allowedIps: ['10.0.0.0/8'],
  });
  assert(
    'IP allowlist permits IPv4 CIDR',
    (await runAuth(cidrIp, mockReq({ socket: { remoteAddress: '10.20.30.40' } }))).nextCalled
  );

  const ipv6Ip = createAdminAuthMiddleware({
    mode: 'ip-allowlist',
    allowedIps: ['::1'],
  });
  assert(
    'IP allowlist permits IPv6 localhost',
    (await runAuth(ipv6Ip, mockReq({ socket: { remoteAddress: '::1' } }))).nextCalled
  );

  const mappedIp = createAdminAuthMiddleware({
    mode: 'ip-allowlist',
    allowedIps: ['127.0.0.1'],
  });
  assert(
    'IP allowlist normalizes IPv4-mapped IPv6',
    (await runAuth(mappedIp, mockReq({ socket: { remoteAddress: '::ffff:127.0.0.1' } }))).nextCalled
  );

  const spoofedIp = await runAuth(
    createAdminAuthMiddleware({
      mode: 'ip-allowlist',
      allowedIps: ['198.51.100.10'],
    }),
    mockReq({
      socket: { remoteAddress: '10.0.0.5' },
      headers: { 'x-forwarded-for': '198.51.100.10' },
    })
  );
  assert('IP allowlist ignores x-forwarded-for by default', spoofedIp.res._status === 403);

  const trustedForwardedIp = await runAuth(
    createAdminAuthMiddleware({
      mode: 'ip-allowlist',
      allowedIps: ['198.51.100.10'],
      trustProxyHeaders: true,
      trustedProxies: ['10.0.0.0/8'],
    }),
    mockReq({
      socket: { remoteAddress: '10.0.0.5' },
      headers: { 'x-forwarded-for': '198.51.100.10, 10.0.0.5' },
    })
  );
  assert('IP allowlist uses x-forwarded-for only from trusted proxy', trustedForwardedIp.nextCalled);

  console.log('\n── Admin Auth — Trusted Proxy ──────────────────────────────');

  const trustedProxy = createAdminAuthMiddleware({
    mode: 'trusted-proxy',
    trustedProxies: ['10.0.0.0/8'],
    requiredHeaders: { 'x-parry-admin-authenticated': 'true' },
    userHeader: 'x-parry-admin-user',
    emailHeader: 'x-parry-admin-email',
    rolesHeader: 'x-parry-admin-roles',
  });

  const untrustedProxy = await runAuth(
    trustedProxy,
    mockReq({
      socket: { remoteAddress: '203.0.113.10' },
      headers: { 'x-parry-admin-authenticated': 'true' },
    })
  );
  assert('Trusted proxy rejects untrusted direct peer', untrustedProxy.res._status === 403);

  const missingTrustedHeader = await runAuth(
    trustedProxy,
    mockReq({ socket: { remoteAddress: '10.0.0.5' } })
  );
  assert('Trusted proxy returns 401 when required header is absent', missingTrustedHeader.res._status === 401);

  const validTrustedProxy = await runAuth(
    trustedProxy,
    mockReq({
      socket: { remoteAddress: '10.0.0.5' },
      headers: {
        'x-forwarded-for': '198.51.100.25',
        'x-parry-admin-authenticated': 'true',
        'x-parry-admin-user': 'admin-user',
        'x-parry-admin-email': 'admin@example.com',
        'x-parry-admin-roles': 'security,ops',
      },
    })
  );
  assert(
    'Trusted proxy accepts required header from trusted proxy',
    validTrustedProxy.nextCalled &&
      validTrustedProxy.req.parryAdmin.strategy === 'trusted-proxy' &&
      validTrustedProxy.req.parryAdmin.subject === 'proxy:admin-user' &&
      validTrustedProxy.req.parryAdmin.email === 'admin@example.com' &&
      validTrustedProxy.req.parryAdmin.roles.length === 2
  );

  const secretProxy = createAdminAuthMiddleware({
    mode: 'trusted-proxy',
    trustedProxies: ['127.0.0.1'],
    requiredHeaders: { 'x-parry-admin-authenticated': 'true' },
    proxySharedSecretHeader: 'x-parry-proxy-secret',
    proxySharedSecret: 'shared-secret',
  });
  const wrongSecret = await runAuth(
    secretProxy,
    mockReq({
      headers: {
        'x-parry-admin-authenticated': 'true',
        'x-parry-proxy-secret': 'wrong-secret',
      },
    })
  );
  assert('Trusted proxy rejects wrong shared secret', wrongSecret.res._status === 403);
  assert('Shared secret is not returned in response', !JSON.stringify(wrongSecret.res._body).includes('shared-secret'));

  const correctSecret = await runAuth(
    secretProxy,
    mockReq({
      headers: {
        'x-parry-admin-authenticated': 'true',
        'x-parry-proxy-secret': 'shared-secret',
      },
    })
  );
  assert('Trusted proxy accepts correct shared secret', correctSecret.nextCalled);

  const spoofedAdminHeader = await runAuth(
    secretProxy,
    mockReq({
      socket: { remoteAddress: '203.0.113.99' },
      headers: {
        'x-parry-admin-authenticated': 'true',
        'x-parry-proxy-secret': 'shared-secret',
      },
    })
  );
  assert('Trusted proxy ignores administrative headers from public clients', spoofedAdminHeader.res._status === 403);

  console.log('\n── Admin Auth — Combined and None ──────────────────────────');

  const allowAny = await runAuth(
    createAdminAuthMiddleware({
      mode: 'combined',
      allowAny: [
        { mode: 'token', token: 'secret-token' },
        { mode: 'ip-allowlist', allowedIps: ['127.0.0.1'] },
      ],
    })
  );
  assert('Combined allowAny permits one valid strategy', allowAny.nextCalled);

  const requireAllFail = await runAuth(
    createAdminAuthMiddleware({
      mode: 'combined',
      requireAll: [
        { mode: 'token', token: 'secret-token' },
        { mode: 'ip-allowlist', allowedIps: ['127.0.0.1'] },
      ],
    })
  );
  assert('Combined requireAll requires all strategies', requireAllFail.res._status === 401);

  const requireAllPass = await runAuth(
    createAdminAuthMiddleware({
      mode: 'combined',
      requireAll: [
        { mode: 'token', token: 'secret-token' },
        { mode: 'ip-allowlist', allowedIps: ['127.0.0.1'] },
      ],
    }),
    mockReq({ headers: { 'x-parry-admin-token': 'secret-token' } })
  );
  assert('Combined requireAll allows when all strategies pass', requireAllPass.nextCalled);

  assert(
    'Combined rejects allowAny and requireAll together',
    throws(() =>
      createAdminAuthMiddleware({
        mode: 'combined',
        allowAny: [{ mode: 'ip-allowlist', allowedIps: ['127.0.0.1'] }],
        requireAll: [{ mode: 'token', token: 'secret-token' }],
      })
    )
  );

  assert(
    'Combined rejects nested combined strategy',
    throws(() =>
      createAdminAuthMiddleware({
        mode: 'combined',
        allowAny: [{ mode: 'combined', allowAny: [{ mode: 'token', token: 'secret-token' }] }],
      })
    )
  );

  const previousNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  assert(
    'None mode is blocked in production without explicit override',
    throws(() => createAdminAuthMiddleware({ mode: 'none' }))
  );
  process.env.NODE_ENV = previousNodeEnv;

  console.log('\n── Admin Auth — Legacy Compatibility ───────────────────────');
  const legacyAuth = await runAuth(requireAdminAuth({ auth: () => true }));
  assert('Legacy auth callback still allows requests', legacyAuth.nextCalled);

  return { passed, failed };
}

function throws(fn) {
  try {
    fn();
    return false;
  } catch (_error) {
    return true;
  }
}

module.exports = runAll().then(() => ({ passed, failed }));
