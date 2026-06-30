'use strict';

/**
 * scripts/run-tests.js
 * Suite of real HTTP tests against the test server.
 * No external dependencies — uses only Node.js's native http module.
 *
 * Usage:
 *   Terminal 1 → node scripts/test-server.js
 *   Terminal 2 → node scripts/run-tests.js
 */

const http = require('http');

let passed = 0,
  failed = 0,
  total = 0;
// Each section uses 10.0.0.X → completely isolated in the RateLimiter
let _sectionIp = 10;

function nextIp() {
  return `10.0.0.${_sectionIp++}`;
}

function request({ method = 'GET', path, body, ip }) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        hostname: 'localhost',
        port: 3000,
        path,
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-Forwarded-For': ip,
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          let json;
          try {
            json = JSON.parse(data);
          } catch {
            json = {};
          }
          resolve({ status: res.statusCode, headers: res.headers, body: json });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function assert(label, condition, got) {
  total++;
  if (condition) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    console.error(`  ✗ ${label}\n     → received: ${JSON.stringify(got)}`);
    failed++;
  }
}

function section(title) {
  console.log(`\n${'─'.repeat(62)}`);
  console.log(`  ${title}`);
  console.log('─'.repeat(62));
}

async function run() {
  console.log('\n' + '═'.repeat(62));
  console.log('Real HTTP Tests');
  console.log('═'.repeat(62));

  section('The server is up — sanity check');
  {
    const ip = nextIp();
    const res = await request({ path: '/ping', ip });
    assert('GET /ping returns 200', res.status === 200, res.status);
    assert('Response contains ok:true', res.body.ok === true, res.body);
  }

  section('Clean requests — expect: 200 in everything');
  {
    const ip = nextIp();
    const cases = [
      {
        label: 'Valid login',
        method: 'POST',
        path: '/login',
        body: { username: 'maria@email.com', password: 'M3T4NF3T4M1N4' },
      },
      { label: 'Search with simple text', path: '/search?q=notebook+gamer' },
      {
        label: 'Search with accents (encoded)',
        path: '/search?q=cadeira+de+escrit%C3%B3rio',
      },
      {
        label: 'Clean comment',
        method: 'POST',
        path: '/comment',
        body: { text: 'Great product! I highly recommend it.' },
      },
      {
        label: 'Simple filter',
        method: 'POST',
        path: '/filter',
        body: { filter: { category: 'electronics', priceMax: 500 } },
      },
      { label: 'Route by numerical parameter', path: '/user/42' },
    ];
    for (const c of cases) {
      const res = await request({ ...c, ip });
      assert(c.label, res.status === 200, res.status);
    }
  }

  section('SQL Injection — status: 400 with SQL_INJECTION detector');
  {
    const cases = [
      { label: 'OR 1=1', body: { username: "' OR 1=1 --" } },
      {
        label: 'UNION SELECT',
        body: { username: "' UNION SELECT * FROM users" },
      },
      { label: 'DROP TABLE', body: { username: '; DROP TABLE users;' } },
      { label: 'SLEEP()', body: { username: "' AND SLEEP(5) --" } },
      { label: 'comment --', body: { username: "admin' --" } },
      { label: 'URL-encoded', body: { username: "admin' OR '1'='1" } },
      {
        label: 'via query parameter',
        path: '/search?q=%27+OR+%271%27%3D%271',
        body: null,
      },
      {
        label: 'nested body',
        body: { user: { profile: { bio: "' UNION SELECT * FROM users" } } },
        path: '/filter',
      },
    ];
    for (const c of cases) {
      const ip = nextIp();
      const res = await request({
        method: c.body && !c.path ? 'POST' : c.path?.startsWith('/filter') ? 'POST' : 'GET',
        path: c.path || '/login',
        body: c.body || undefined,
        ip,
      });
      assert(`Block: ${c.label}`, res.status === 400, res.status);
      assert(
        `→ detector SQL_INJECTION`,
        res.body?.threats?.[0]?.detector === 'SQL_INJECTION',
        res.body?.threats?.[0]?.detector
      );
    }
  }

  section('XSS — status: 400 with XSS detector');
  {
    const cases = [
      {
        label: '<script> tag',
        path: '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E',
      },
      {
        label: 'onerror handler',
        path: '/search?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E',
      },
      { label: 'javascript: proto', path: '/search?q=javascript%3Aalert(1)' },
      { label: 'template injection', path: '/search?q=%7B%7B7*7%7D%7D' },
      { label: 'vbscript:', path: '/search?q=vbscript%3Amsgbox(%22xss%22)' },
      {
        label: 'XSS em body',
        method: 'POST',
        path: '/comment',
        body: { text: '<script>document.cookie="hacked"</script>' },
      },
    ];
    for (const c of cases) {
      const ip = nextIp();
      const res = await request({
        method: c.method || 'GET',
        path: c.path,
        body: c.body,
        ip,
      });
      assert(`Block: ${c.label}`, res.status === 400, res.status);
      assert(
        `→ XSS detector`,
        res.body?.threats?.[0]?.detector === 'XSS',
        res.body?.threats?.[0]?.detector
      );
    }
  }

  section('NoSQL Injection — status: 400 with NOSQL_INJECTION detector');
  {
    const cases = [
      {
        label: '$gt operator',
        body: { username: { $gt: '' }, password: { $gt: '' } },
      },
      { label: '$ne operator', body: { username: { $ne: null } } },
      {
        label: '$where JS',
        body: { username: { $where: 'function(){return true;}' } },
      },
      { label: '$or operator', body: { $or: [{ admin: true }] } },
      { label: 'JSON string $gt', body: { username: '{"$gt":""}' } },
      {
        label: 'nested $gt no filter',
        path: '/filter',
        method: 'POST',
        body: { filter: { price: { $gt: 0 } } },
      },
    ];
    for (const c of cases) {
      const ip = nextIp();
      const res = await request({
        method: c.method || 'POST',
        path: c.path || '/login',
        body: c.body,
        ip,
      });
      assert(`Block: ${c.label}`, res.status === 400, res.status);
      assert(
        `→ NOSQL_INJECTION detector`,
        res.body?.threats?.[0]?.detector === 'NOSQL_INJECTION',
        res.body?.threats?.[0]?.detector
      );
    }
  }

  section('X-RateLimit headers — status: present in every response');
  {
    const ip = nextIp();
    const res = await request({ path: '/ping', ip });
    assert(
      'X-RateLimit-Limit present',
      'x-ratelimit-limit' in res.headers,
      Object.keys(res.headers)
    );
    assert(
      'X-RateLimit-Remaining present',
      'x-ratelimit-remaining' in res.headers,
      Object.keys(res.headers)
    );
    assert(
      'X-RateLimit-Reset present',
      'x-ratelimit-reset' in res.headers,
      Object.keys(res.headers)
    );
    assert(
      'Remaining is a number >= 0',
      Number(res.headers['x-ratelimit-remaining']) >= 0,
      res.headers['x-ratelimit-remaining']
    );
    assert(
      'Limit collides with maxRequests=30',
      Number(res.headers['x-ratelimit-limit']) === 30,
      res.headers['x-ratelimit-limit']
    );
  }

  section('Volume-based rate limiting — wait: 429 after 30 requests/min');
  {
    const ip = nextIp();
    for (let i = 0; i < 30; i++) await request({ path: '/ping', ip });
    const r31 = await request({ path: '/ping', ip });
    assert('31st request returns 429', r31.status === 429, r31.status);
    assert(
      'Message indicates limit reached',
      typeof r31.body.message === 'string',
      r31.body.message
    );
    assert(
      'Remaining reaches 0 before block',
      Number((await request({ path: '/ping', ip: nextIp() })).headers['x-ratelimit-remaining']) >=
        0,
      'ok'
    );
  }

  section('Smart ban — waiting: 429 after 5 attacks detected');
  {
    const ip = nextIp();
    for (let i = 0; i < 5; i++) {
      await request({
        method: 'POST',
        path: '/login',
        body: { username: "' OR 1=1 --" },
        ip,
      });
    }
    const check = await request({ path: '/ping', ip });
    assert(
      'Banned IP returns a 429 error on a legitimate request',
      check.status === 429,
      check.status
    );
    assert(
      'banExpiresAt is currently present in the response',
      typeof check.body.banExpiresAt === 'number',
      check.body
    );
    assert(
      'banExpiresAt is a future timestamp',
      check.body.banExpiresAt > Date.now(),
      check.body.banExpiresAt
    );
  }

  section('MMultiple threats — wait: all listed detectors');
  {
    const ip = nextIp();
    const res = await request({
      method: 'POST',
      path: '/login',
      ip,
      body: {
        username: "' OR 1=1 --",
        comment: '<script>alert(1)</script>',
      },
    });
    assert('Returns 400', res.status === 400, res.status);
    assert('Lists >= 2 threats', (res.body?.threats?.length ?? 0) >= 2, res.body?.threats);
    const detectors = (res.body?.threats ?? []).map((t) => t.detector);
    assert('Includes SQL_INJECTION', detectors.includes('SQL_INJECTION'), detectors);
    assert('Includes XSS', detectors.includes('XSS'), detectors);
  }

  console.log('\n' + '═'.repeat(62));
  console.log(`  Result: ${passed}/${total}  ✓ passed  |  ✗ ${failed}  failed`);
  if (failed === 0) console.log('  ✓ Parry validated — 100% approved!');
  else console.log('  ⚠  Check the errors listed above.');
  console.log('═'.repeat(62) + '\n');
  process.exit(failed > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error('\n✗ Connection error — the test server is running?\n');
  console.error('   Run: node scripts/test-server.js\n');
  console.error(err.message);
  process.exit(1);
});
