'use strict';

const { analyzeRequest } = require('../../src/core/engine');

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
  console.log('\n── Core Engine ─────────────────────────────────────────────');

  const clean = await analyzeRequest(
    {
      ip: '127.0.0.1',
      timestamp: '2026-01-01T00:00:00.000Z',
      method: 'POST',
      url: '/test',
      targets: [{ label: 'body.username', value: 'alice', stringValue: 'alice' }],
    },
    {
      config: { sql: true, xss: true, nosql: true, rateLimit: false },
      rateLimiter: null,
    }
  );

  assert('Allows clean request data', clean.allowed && !clean.blocked);
  assert('Clean decision has no event', clean.event === null);

  const blocked = await analyzeRequest(
    {
      ip: '127.0.0.1',
      timestamp: '2026-01-01T00:00:00.000Z',
      method: 'POST',
      url: '/test',
      targets: [{ label: 'body.username', value: "' OR 1=1 --", stringValue: "' OR 1=1 --" }],
    },
    {
      config: { sql: true, xss: false, nosql: false, rateLimit: false },
      rateLimiter: null,
    }
  );

  assert('Blocks SQL injection request data', blocked.blocked && !blocked.allowed);
  assert(
    'Blocked decision exposes reason and status',
    blocked.reason === 'THREAT' && blocked.statusCode === 400
  );
  assert(
    'Blocked decision exposes detector and severity',
    blocked.detector === 'SQL_INJECTION' && blocked.severity === 'high'
  );
  assert(
    'Blocked decision keeps compatible event shape',
    blocked.event?.type === 'THREAT' && blocked.event.threats?.[0]?.field === 'body.username'
  );

  return { passed, failed };
}

module.exports = runAll();
