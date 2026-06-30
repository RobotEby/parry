'use strict';

const http = require('http');
const { createDemoApp } = require('../../docker/demo-api/app');

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

async function runAll() {
  console.log('\n── Demo API ────────────────────────────────────────────────');

  const { app } = createDemoApp({
    env: {
      PARRY_ADMIN_TOKEN: 'change-me',
      PARRY_RATE_LIMIT_ENABLED: 'false',
      PARRY_LOG_THREATS: 'false',
      DEMO_USER_EMAIL: 'demo@example.com',
      DEMO_USER_PASSWORD: 'password123',
    },
  });
  const server = await listen(app);

  try {
    const health = await request(server, 'GET', '/health');
    assert('Demo API health returns ok', health.status === 200 && health.body.ok === true);

    const echo = await request(server, 'POST', '/echo', { message: 'hello' });
    assert('Demo API /echo returns allowed body', echo.status === 200 && echo.body.received.message === 'hello');

    const blockedEcho = await request(server, 'POST', '/echo', { username: "' OR '1'='1" });
    assert('Demo API /echo is protected by Parry', blockedEcho.status === 400);

    const deniedAdmin = await request(server, 'GET', '/_parry/health');
    assert('Demo Admin API requires token', deniedAdmin.status === 401);

    const allowedAdmin = await request(server, 'GET', '/_parry/health', null, {
      'x-parry-admin-token': 'change-me',
    });
    assert('Demo Admin API accepts configured token', allowedAdmin.status === 200 && allowedAdmin.body.ok);
  } finally {
    await close(server);
  }

  const { app: defaultTokenApp } = createDemoApp({
    env: {
      PARRY_RATE_LIMIT_ENABLED: 'false',
      PARRY_LOG_THREATS: 'false',
    },
  });
  const defaultTokenServer = await listen(defaultTokenApp);
  try {
    const defaultTokenAdmin = await request(defaultTokenServer, 'GET', '/_parry/health', null, {
      'x-parry-admin-token': 'change-me',
    });
    assert('Demo Admin API defaults to change-me token locally', defaultTokenAdmin.status === 200);
  } finally {
    await close(defaultTokenServer);
  }

  const { app: allowlistApp } = createDemoApp({
    env: {
      PARRY_ADMIN_AUTH_MODE: 'ip-allowlist',
      PARRY_ADMIN_ALLOWED_IPS: '127.0.0.1',
      PARRY_RATE_LIMIT_ENABLED: 'false',
      PARRY_LOG_THREATS: 'false',
    },
  });
  const allowlistServer = await listen(allowlistApp);
  try {
    const allowlistAdmin = await request(allowlistServer, 'GET', '/_parry/health');
    assert('Demo Admin API supports ip-allowlist mode', allowlistAdmin.status === 200);
  } finally {
    await close(allowlistServer);
  }

  const { app: trustedProxyApp } = createDemoApp({
    env: {
      PARRY_ADMIN_AUTH_MODE: 'trusted-proxy',
      PARRY_ADMIN_TRUSTED_PROXIES: '127.0.0.1',
      PARRY_ADMIN_REQUIRED_HEADER: 'x-parry-admin-authenticated:true',
      PARRY_RATE_LIMIT_ENABLED: 'false',
      PARRY_LOG_THREATS: 'false',
    },
  });
  const trustedProxyServer = await listen(trustedProxyApp);
  try {
    const missingProxyHeader = await request(trustedProxyServer, 'GET', '/_parry/health');
    assert('Demo trusted-proxy mode requires configured header', missingProxyHeader.status === 401);

    const trustedProxyAdmin = await request(trustedProxyServer, 'GET', '/_parry/health', null, {
      'x-parry-admin-authenticated': 'true',
    });
    assert('Demo Admin API supports trusted-proxy mode', trustedProxyAdmin.status === 200);
  } finally {
    await close(trustedProxyServer);
  }

  return { passed, failed };
}

function listen(app) {
  return new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function request(server, method, path, body, headers = {}) {
  const address = server.address();
  const payload = body == null ? null : JSON.stringify(body);

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: address.port,
        method,
        path,
        headers: {
          Accept: 'application/json',
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
          ...headers,
        },
      },
      (res) => {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          raw += chunk;
        });
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            body: raw ? JSON.parse(raw) : null,
          });
        });
      }
    );

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

module.exports = runAll().then(() => ({ passed, failed }));
