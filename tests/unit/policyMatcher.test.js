'use strict';

const { matchesPolicy } = require('../../src/policies');

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

console.log('\n── Policy Matcher ─────────────────────────────────────────');

assert(
  'Matches exact path',
  matchesPolicy({ match: { path: '/login' } }, { method: 'GET', path: '/login' })
);
assert(
  'Matches wildcard path',
  matchesPolicy({ match: { path: '/auth/*' } }, { method: 'GET', path: '/auth/login' })
);
assert(
  'Matches array of paths',
  matchesPolicy({ match: { path: ['/login', '/signin'] } }, { method: 'GET', path: '/signin' })
);
assert(
  'Matches exact method',
  matchesPolicy({ match: { method: 'POST' } }, { method: 'POST', path: '/login' })
);
assert(
  'Matches array of methods',
  matchesPolicy({ match: { method: ['POST', 'PUT'] } }, { method: 'PUT', path: '/login' })
);
assert(
  'Matches RegExp path',
  matchesPolicy({ match: { path: /^\/api\/v1\/auth\// } }, { method: 'POST', path: '/api/v1/auth/login' })
);
assert(
  'Does not match when method differs',
  !matchesPolicy({ match: { method: 'POST', path: '/login' } }, { method: 'GET', path: '/login' })
);
assert(
  'Does not match when path differs',
  !matchesPolicy({ match: { method: 'POST', path: '/login' } }, { method: 'POST', path: '/profile' })
);

module.exports = { passed, failed };
