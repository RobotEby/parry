'use strict';

const { EventEmitter } = require('events');

function clone(value) {
  if (value == null || typeof value !== 'object') return value;
  return JSON.parse(JSON.stringify(value));
}

function materializePayload(fixture) {
  if (fixture.category !== 'request-shape') return clone(fixture.payload);

  const descriptor = fixture.payload || {};
  switch (descriptor.kind) {
    case 'deep-object':
      return buildDeepObject(descriptor.depth);
    case 'deep-array':
      return buildDeepArray(descriptor.depth);
    case 'wide-object':
      return buildWideObject(descriptor.keys);
    case 'nested-wide-object':
      return buildNestedWideObject(descriptor.parents, descriptor.keysPerParent);
    case 'large-array':
      return Array.from({ length: descriptor.length }, (_, index) => index);
    case 'nested-large-array':
      return { items: Array.from({ length: descriptor.length }, (_, index) => index) };
    case 'long-string':
      return 'x'.repeat(descriptor.length);
    case 'nested-long-string':
      return { profile: { bio: 'x'.repeat(descriptor.length) } };
    case 'mixed-depth':
      return buildMixedDepth(descriptor.depth);
    case 'object-with-large-array':
      return { items: Array.from({ length: descriptor.length }, (_, index) => index) };
    case 'array-with-long-string':
      return ['x'.repeat(descriptor.length)];
    default:
      throw new Error(`Unknown request-shape fixture kind: ${descriptor.kind}`);
  }
}

function buildDeepObject(depth) {
  let root = {};
  let cursor = root;
  for (let i = 0; i < depth; i++) {
    cursor.child = {};
    cursor = cursor.child;
  }
  return root;
}

function buildDeepArray(depth) {
  let value = 'leaf';
  for (let i = 0; i < depth; i++) value = [value];
  return value;
}

function buildMixedDepth(depth) {
  let value = { leaf: true };
  for (let i = 0; i < depth; i++) value = { items: [value] };
  return value;
}

function buildWideObject(keys) {
  const value = {};
  for (let i = 0; i < keys; i++) value[`key_${i}`] = i;
  return value;
}

function buildNestedWideObject(parents, keysPerParent) {
  const value = {};
  for (let parent = 0; parent < parents; parent++) {
    value[`parent_${parent}`] = {};
    for (let key = 0; key < keysPerParent; key++) {
      value[`parent_${parent}`][`key_${key}`] = key;
    }
  }
  return value;
}

function mockReq(overrides = {}) {
  return {
    method: 'POST',
    url: '/payload-regression',
    originalUrl: '/payload-regression',
    ip: '127.0.0.1',
    headers: {},
    query: {},
    body: {},
    params: {},
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

function runMiddleware(middleware, req, routeHandler) {
  return new Promise((resolve, reject) => {
    const res = mockRes();
    let called = false;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      resolve({ req, res, next: called });
    };

    const maybePromise = middleware(req, res, async (error) => {
      if (error) return reject(error);
      called = true;
      try {
        if (routeHandler) {
          await routeHandler(req, res);
          res.emit('finish');
          await new Promise((done) => setTimeout(done, 0));
        }
        finish();
      } catch (routeError) {
        reject(routeError);
      }
    });

    Promise.resolve(maybePromise)
      .then(() => {
        if (!called) finish();
      })
      .catch(reject);
  });
}

function requestFromFixture(fixture, options = {}) {
  const value = materializePayload(fixture);
  const req = mockReq({
    ip: options.ip || '203.0.113.50',
    headers: {
      authorization: 'Bearer should-not-leak',
      cookie: 'sid=should-not-leak',
      'user-agent': 'PayloadRegression',
      ...(options.headers || {}),
    },
    body: { password: 'should-not-leak', token: 'should-not-leak' },
  });

  if (fixture.category === 'hpp') {
    req.query = value;
    return req;
  }

  assignTarget(req, fixture.target, value);
  return req;
}

function assignTarget(req, target, value) {
  if (target === 'body') {
    req.body = value;
    return;
  }
  if (target === 'query') {
    req.query = value;
    return;
  }
  if (target === 'params') {
    req.params = value;
    return;
  }
  if (target.startsWith('header.')) {
    req.headers[target.slice('header.'.length).toLowerCase()] = value;
    return;
  }

  const [surface, ...path] = target.split('.');
  if (!['body', 'query', 'params'].includes(surface)) return;
  if (!req[surface] || typeof req[surface] !== 'object') req[surface] = {};

  let cursor = req[surface];
  for (let i = 0; i < path.length - 1; i++) {
    if (!cursor[path[i]] || typeof cursor[path[i]] !== 'object') cursor[path[i]] = {};
    cursor = cursor[path[i]];
  }
  cursor[path[path.length - 1]] = value;
}

module.exports = {
  assignTarget,
  materializePayload,
  mockReq,
  mockRes,
  requestFromFixture,
  runMiddleware,
};
