'use strict';

const { test } = require('node:test');
const nodeAssert = require('node:assert/strict');
const { buildKey } = require('../../src/brute-force');

function assert(description, condition) {
  nodeAssert.ok(condition, description);
}

function runAll() {
  console.log('\n── BruteForce Key Builder ─────────────────────────────────');

  const requestData = {
    ip: '127.0.0.1',
    method: 'POST',
    path: '/login',
    headers: { 'user-agent': 'Mozilla Test' },
    body: {
      email: '  USER@Example.COM ',
      username: '  Alice ',
      password: 'secret',
    },
    query: { email: 'QUERY@Example.COM' },
    params: { id: '42' },
  };

  assert(
    'Builds ip key',
    buildKey('auth-login', 'ip', requestData, 'bf')?.key === 'bf:auth-login:ip:127.0.0.1'
  );
  assert(
    'Normalizes body.email',
    buildKey('auth-login', 'body.email', requestData, 'bf')?.key ===
      'bf:auth-login:body.email:user@example.com'
  );
  assert(
    'Normalizes body.username',
    buildKey('auth-login', 'body.username', requestData, 'bf')?.key ===
      'bf:auth-login:body.username:alice'
  );
  assert(
    'Builds composed ip+body.email key',
    buildKey('auth-login', 'ip+body.email', requestData, 'bf')?.key ===
      'bf:auth-login:ip+body.email:127.0.0.1:user@example.com'
  );
  assert(
    'Ignores empty values',
    buildKey('auth-login', 'body.email', { ...requestData, body: { email: '   ' } }, 'bf') === null
  );
  assert(
    'Does not use password key',
    buildKey('auth-login', 'body.password', requestData, 'bf') === null
  );
  assert(
    'Builds custom function key',
    buildKey('auth-login', () => ({ type: 'tenant', value: 'acme' }), requestData, 'bf')?.key ===
      'bf:auth-login:tenant:acme'
  );
}

test('Brute-force key builder', runAll);
