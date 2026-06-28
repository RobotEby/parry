'use strict';

const { EventEmitter } = require('events');
const { MemoryStore } = require('../../src/stores');
const { normalizePolicy } = require('../../src/policies');
const {
  attachParryRequestApi,
  checkBruteForceBlock,
  createBruteForceContext,
  observeAuthenticationResult,
} = require('../../src/brute-force');

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

function basePolicy(overrides = {}) {
  return normalizePolicy({
    name: 'auth-login',
    match: { method: 'POST', path: '/login' },
    bruteForce: {
      enabled: true,
      maxAttempts: 2,
      windowMs: 60_000,
      blockDurationMs: 60_000,
      keys: ['ip', 'body.email', 'ip+body.email'],
      resetOnSuccess: true,
      ...overrides,
    },
  });
}

function requestData(overrides = {}) {
  return {
    ip: '127.0.0.1',
    method: 'POST',
    path: '/login',
    headers: { 'user-agent': 'Unit Test', 'x-request-id': 'req-1' },
    body: { email: 'USER@example.COM' },
    query: {},
    params: {},
    ...overrides,
  };
}

function mockReq(existingParry) {
  return existingParry ? { parry: existingParry } : {};
}

function mockRes(statusCode = 200) {
  const emitter = new EventEmitter();
  return {
    statusCode,
    on: emitter.on.bind(emitter),
    emit: emitter.emit.bind(emitter),
  };
}

function context({ policy = basePolicy(), store = new MemoryStore(), statusCode = 200, config = {}, events = [], req } = {}) {
  const logger = {
    log(entry) {
      events.push(entry);
    },
    logStoreError(error, entry) {
      events.push({ ...entry, error: error.message });
    },
    logHookError(error, entry) {
      events.push({ type: 'HOOK_ERROR', entry, error: error.message });
    },
  };
  const res = mockRes(statusCode);
  return createBruteForceContext({
    policy,
    requestData: requestData(),
    req: req || mockReq(),
    res,
    store,
    config: { storeFailureMode: 'fail-open', ...config },
    logger,
  });
}

function sleep() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function finish(ctx, statusCode) {
  ctx.res.statusCode = statusCode;
  ctx.res.emit('finish');
  await sleep();
}

async function runAll() {
  console.log('\n── BruteForceGuard ────────────────────────────────────────');

  const initial = context();
  attachParryRequestApi(initial.req, initial);
  assert('Allows initial attempt', (await checkBruteForceBlock(initial)).allowed);

  const store = new MemoryStore();
  const failedAttempt = context({ store });
  attachParryRequestApi(failedAttempt.req, failedAttempt);
  observeAuthenticationResult(failedAttempt);
  await finish(failedAttempt, 401);
  assert(
    'Registers failure by status 401',
    store.getCounter('bf:auth-login:ip:127.0.0.1').count === 1
  );

  const secondFailure = context({ store });
  attachParryRequestApi(secondFailure.req, secondFailure);
  observeAuthenticationResult(secondFailure);
  await finish(secondFailure, 401);
  const blocked = context({ store });
  attachParryRequestApi(blocked.req, blocked);
  assert('Blocks after maxAttempts', (await checkBruteForceBlock(blocked)).blocked);

  const resetStore = new MemoryStore();
  const resetFailure = context({ store: resetStore });
  attachParryRequestApi(resetFailure.req, resetFailure);
  observeAuthenticationResult(resetFailure);
  await finish(resetFailure, 401);
  const resetSuccess = context({ store: resetStore });
  attachParryRequestApi(resetSuccess.req, resetSuccess);
  observeAuthenticationResult(resetSuccess);
  await finish(resetSuccess, 200);
  assert('Resets on success when resetOnSuccess true', resetStore.getCounter('bf:auth-login:ip:127.0.0.1').count === 0);

  const noResetStore = new MemoryStore();
  const noResetPolicy = basePolicy({ resetOnSuccess: false });
  const noResetFailure = context({ store: noResetStore, policy: noResetPolicy });
  attachParryRequestApi(noResetFailure.req, noResetFailure);
  observeAuthenticationResult(noResetFailure);
  await finish(noResetFailure, 401);
  const noResetSuccess = context({ store: noResetStore, policy: noResetPolicy });
  attachParryRequestApi(noResetSuccess.req, noResetSuccess);
  observeAuthenticationResult(noResetSuccess);
  await finish(noResetSuccess, 200);
  assert(
    'Does not reset on success when resetOnSuccess false',
    noResetStore.getCounter('bf:auth-login:ip:127.0.0.1').count === 1
  );

  const manualFailureStore = new MemoryStore();
  const manualFailure = context({ store: manualFailureStore });
  attachParryRequestApi(manualFailure.req, manualFailure);
  observeAuthenticationResult(manualFailure);
  manualFailure.req.parry.recordAuthFailure('invalid_credentials');
  await finish(manualFailure, 200);
  assert(
    'Manual recordAuthFailure counts failure even with status 200',
    manualFailureStore.getCounter('bf:auth-login:ip:127.0.0.1').count === 1
  );

  const manualSuccessStore = new MemoryStore();
  const manualBefore = context({ store: manualSuccessStore });
  attachParryRequestApi(manualBefore.req, manualBefore);
  observeAuthenticationResult(manualBefore);
  await finish(manualBefore, 401);
  const manualSuccess = context({ store: manualSuccessStore });
  attachParryRequestApi(manualSuccess.req, manualSuccess);
  observeAuthenticationResult(manualSuccess);
  manualSuccess.req.parry.recordAuthSuccess();
  await finish(manualSuccess, 401);
  assert(
    'Manual recordAuthSuccess resets counter',
    manualSuccessStore.getCounter('bf:auth-login:ip:127.0.0.1').count === 0
  );

  const noDoubleStore = new MemoryStore();
  const noDouble = context({ store: noDoubleStore });
  attachParryRequestApi(noDouble.req, noDouble);
  observeAuthenticationResult(noDouble);
  noDouble.req.parry.recordAuthFailure('manual');
  await finish(noDouble, 401);
  assert('Does not double count manual failure plus status failure', noDoubleStore.getCounter('bf:auth-login:ip:127.0.0.1').count === 1);

  const events = [];
  const eventCtx = context({
    store: new MemoryStore(),
    events,
    config: {
      storeFailureMode: 'fail-open',
      onThreat(entry) {
        events.push({ type: 'ON_THREAT', originalType: entry.type });
      },
    },
  });
  attachParryRequestApi(eventCtx.req, eventCtx);
  observeAuthenticationResult(eventCtx);
  await finish(eventCtx, 401);
  assert(
    'Generates brute force event and onThreat callback',
    events.some((entry) => entry.type === 'BRUTE_FORCE_ATTEMPT') &&
      events.some((entry) => entry.type === 'ON_THREAT' && entry.originalType === 'BRUTE_FORCE_ATTEMPT')
  );

  const asyncStore = createAsyncStore(new MemoryStore());
  const asyncCtx = context({ store: asyncStore });
  attachParryRequestApi(asyncCtx.req, asyncCtx);
  assert('Works with async store fake', (await checkBruteForceBlock(asyncCtx)).allowed);

  const failingStore = {
    async isBlocked() {
      throw new Error('store down');
    },
  };
  const failOpen = context({ store: failingStore, config: { storeFailureMode: 'fail-open' } });
  attachParryRequestApi(failOpen.req, failOpen);
  assert('Store failure fail-open allows request', (await checkBruteForceBlock(failOpen)).allowed);

  const failClosed = context({ store: failingStore, config: { storeFailureMode: 'fail-closed' } });
  attachParryRequestApi(failClosed.req, failClosed);
  const failClosedResult = await checkBruteForceBlock(failClosed);
  assert('Store failure fail-closed blocks request', failClosedResult.blocked && failClosedResult.statusCode === 503);

  const existingReq = mockReq({ traceId: 'abc' });
  const existing = context({ req: existingReq });
  attachParryRequestApi(existing.req, existing);
  assert('Preserves existing req.parry fields', existing.req.parry.traceId === 'abc');

  return { passed, failed };
}

function createAsyncStore(store) {
  return {
    async isBlocked(key) {
      return store.isBlocked(key);
    },
    async incrementCounter(key, ttlMs, metadata) {
      return store.incrementCounter(key, ttlMs, metadata);
    },
    async resetCounter(key) {
      return store.resetCounter(key);
    },
    async blockKey(key, ttlMs, metadata) {
      return store.blockKey(key, ttlMs, metadata);
    },
  };
}

module.exports = runAll();
