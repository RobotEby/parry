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
