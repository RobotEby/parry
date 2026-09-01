'use strict';

const ipaddr = require('ipaddr.js');
const { NOSQL_DANGEROUS_OPERATORS, NOSQL_SUSPICIOUS_OPERATORS } = require('../constants/patterns');

const HEADER_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const NOSQL_PATH_PATTERN = /^(?:body|query|params)(?:\.|\[|$)/;

function assertObject(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
}

function assertPositive(value, name, { integer = false, allowZero = false } = {}) {
  if (value === undefined) return;
  if (
    typeof value !== 'number' ||
    !Number.isFinite(value) ||
    (integer && !Number.isInteger(value)) ||
    (allowZero ? value < 0 : value <= 0)
  ) {
    throw new TypeError(
      `${name} must be a ${allowZero ? 'non-negative' : 'positive'}${integer ? ' integer' : ' number'}`
    );
  }
}

function validateIpOrCidr(value, name) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(`${name} must be a non-empty IP address or CIDR`);
  }

  try {
    if (value.includes('/')) ipaddr.parseCIDR(value);
    else ipaddr.parse(value);
  } catch {
    throw new TypeError(`${name} contains an invalid IP address or CIDR: ${value}`);
  }
}

function validateTrustedProxies(value, name = 'trustedProxies') {
  if (value === undefined) return;
  if (!Array.isArray(value)) throw new TypeError(`${name} must be an array`);
  value.forEach((entry, index) => validateIpOrCidr(entry, `${name}[${index}]`));
}

function normalizeHeadersConfig(value) {
  const defaultHeaders = ['user-agent', 'referer', 'x-forwarded-for', 'cookie'];
  if (value === undefined) return { scan: defaultHeaders };
  assertObject(value, 'headers');
  const scan = value.scan === undefined ? defaultHeaders : value.scan;
  if (!Array.isArray(scan)) throw new TypeError('headers.scan must be an array');

  const normalized = [];
  const seen = new Set();
  for (const header of scan) {
    validateHeaderName(header, 'headers.scan');
    const name = header.toLowerCase();
    if (!seen.has(name)) {
      seen.add(name);
      normalized.push(name);
    }
  }
  return { scan: normalized };
}

function validateHeaderName(value, name = 'header') {
  if (typeof value !== 'string' || !HEADER_NAME_PATTERN.test(value)) {
    throw new TypeError(`${name} contains an invalid header name: ${String(value)}`);
  }
}

function normalizeNoSQLConfig(value) {
  if (value === undefined) return { enabled: true, allowedOperators: {} };
  if (typeof value === 'boolean') return { enabled: value, allowedOperators: {} };
  assertObject(value, 'nosql');

  if (value.enabled !== undefined && typeof value.enabled !== 'boolean') {
    throw new TypeError('nosql.enabled must be a boolean');
  }
  const allowedOperators = value.allowedOperators || {};
  assertObject(allowedOperators, 'nosql.allowedOperators');

  const normalized = Object.create(null);
  for (const [path, operators] of Object.entries(allowedOperators)) {
    if (!NOSQL_PATH_PATTERN.test(path)) {
      throw new TypeError(`nosql.allowedOperators contains an invalid exact path: ${path}`);
    }
    if (!Array.isArray(operators)) {
      throw new TypeError(`nosql.allowedOperators.${path} must be an array`);
    }

    normalized[path] = [];
    const seen = new Set();
    for (const operator of operators) {
      if (typeof operator !== 'string' || !operator.startsWith('$')) {
        throw new TypeError(`nosql.allowedOperators.${path} contains an invalid operator`);
      }
      if (NOSQL_DANGEROUS_OPERATORS.has(operator)) {
        throw new TypeError(`NoSQL operator ${operator} can never be allowlisted`);
      }
      if (!NOSQL_SUSPICIOUS_OPERATORS.has(operator)) {
        throw new TypeError(`Only suspicious NoSQL operators may be allowlisted: ${operator}`);
      }
      if (!seen.has(operator)) {
        seen.add(operator);
        normalized[path].push(operator);
      }
    }
  }

  return {
    enabled: value.enabled !== false,
    allowedOperators: normalized,
  };
}

function validateRateConfig(rate, name) {
  if (rate === undefined) return;
  assertObject(rate, name);
  assertPositive(rate.maxRequests, `${name}.maxRequests`, { integer: true });
  assertPositive(rate.windowMs, `${name}.windowMs`, { integer: true });
}

function validateMatch(match, name) {
  assertObject(match, name);
  if (match.method === undefined && match.path === undefined) {
    throw new TypeError(`${name} must define method or path`);
  }
  const validateList = (value, field, validateEntry) => {
    const values = Array.isArray(value) ? value : [value];
    if (values.length === 0 || values.some((entry) => !validateEntry(entry))) {
      throw new TypeError(`${name}.${field} is invalid`);
    }
  };
  if (match.method !== undefined) {
    validateList(
      match.method,
      'method',
      (entry) => typeof entry === 'string' && entry.trim() !== ''
    );
  }
  if (match.path !== undefined) {
    validateList(
      match.path,
      'path',
      (entry) => entry instanceof RegExp || (typeof entry === 'string' && entry.trim() !== '')
    );
  }
}

function validateParryOptions(options) {
  if (options === undefined) return;
  assertObject(options, 'options');

  assertPositive(options.maxRequests, 'maxRequests', { integer: true });
  assertPositive(options.windowMs, 'windowMs', { integer: true });
  assertPositive(options.banDurationMs, 'banDurationMs', { integer: true });
  assertPositive(options.suspiciousThreshold, 'suspiciousThreshold', { integer: true });
  assertPositive(options.maxObjectDepth, 'maxObjectDepth', { integer: true, allowZero: true });
  if (options.rateLimit && typeof options.rateLimit === 'object') {
    assertPositive(options.rateLimit.max, 'rateLimit.max', { integer: true });
    assertPositive(options.rateLimit.maxRequests, 'rateLimit.maxRequests', { integer: true });
    assertPositive(options.rateLimit.windowMs, 'rateLimit.windowMs', { integer: true });
  }

  if (options.requestShape !== undefined) {
    assertObject(options.requestShape, 'requestShape');
    assertPositive(options.requestShape.maxDepth, 'requestShape.maxDepth', {
      integer: true,
      allowZero: true,
    });
    assertPositive(options.requestShape.maxKeys, 'requestShape.maxKeys', { integer: true });
    assertPositive(options.requestShape.maxArrayLength, 'requestShape.maxArrayLength', {
      integer: true,
    });
    assertPositive(options.requestShape.maxStringLength, 'requestShape.maxStringLength', {
      integer: true,
    });
  }

  if (options.events !== undefined) {
    assertObject(options.events, 'events');
    assertPositive(options.events.maxEvents, 'events.maxEvents', { integer: true });
  }

  if (options.requestId !== undefined) {
    assertObject(options.requestId, 'requestId');
    if (options.requestId.header !== undefined) {
      validateHeaderName(options.requestId.header, 'requestId.header');
    }
    if (
      options.requestId.responseHeader !== undefined &&
      options.requestId.responseHeader !== false
    ) {
      validateHeaderName(options.requestId.responseHeader, 'requestId.responseHeader');
    }
  }

  if (options.admin !== undefined) {
    assertObject(options.admin, 'admin');
    if (options.admin.path !== undefined && !String(options.admin.path).startsWith('/')) {
      throw new TypeError('admin.path must start with /');
    }
  }

  if (options.bruteForce !== undefined) {
    assertObject(options.bruteForce, 'bruteForce');
  }

  if (options.policies !== undefined) {
    if (!Array.isArray(options.policies)) throw new TypeError('policies must be an array');
    options.policies.forEach((policy, index) => {
      assertObject(policy, `policies[${index}]`);
      if (typeof policy.name !== 'string' || policy.name.trim() === '') {
        throw new TypeError(`policies[${index}].name must be a non-empty string`);
      }
      validateMatch(policy.match, `policies[${index}].match`);
      validateRateConfig(policy.rateLimit, `policies[${index}].rateLimit`);
      if (policy.rateLimit) {
        assertPositive(policy.rateLimit.max, `policies[${index}].rateLimit.max`, {
          integer: true,
        });
      }
      if (policy.bruteForce) {
        assertObject(policy.bruteForce, `policies[${index}].bruteForce`);
        assertPositive(policy.bruteForce.maxAttempts, `policies[${index}].bruteForce.maxAttempts`, {
          integer: true,
        });
        assertPositive(policy.bruteForce.windowMs, `policies[${index}].bruteForce.windowMs`, {
          integer: true,
        });
        assertPositive(
          policy.bruteForce.blockDurationMs,
          `policies[${index}].bruteForce.blockDurationMs`,
          { integer: true }
        );
      }
    });
  }

  validateTrustedProxies(options.trustedProxies);
  normalizeHeadersConfig(options.headers);
  normalizeNoSQLConfig(options.nosql);
}

module.exports = {
  normalizeHeadersConfig,
  normalizeNoSQLConfig,
  validateHeaderName,
  validateIpOrCidr,
  validateParryOptions,
  validateTrustedProxies,
};
