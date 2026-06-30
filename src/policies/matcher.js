'use strict';

function matchesPolicy(policy, requestData) {
  if (!policy || !policy.match) return false;

  return (
    matchesMethod(policy.match.method, requestData.method) &&
    matchesPath(policy.match.path, requestData.path || requestData.url || '/')
  );
}

function findMatchingPolicy(policies, requestData) {
  return (policies || []).find((policy) => matchesPolicy(policy, requestData)) || null;
}

function matchesMethod(expected, method) {
  if (!expected) return true;

  const actual = String(method || '').toUpperCase();
  const methods = Array.isArray(expected) ? expected : [expected];
  return methods.some((item) => String(item || '').toUpperCase() === actual);
}

function matchesPath(expected, path) {
  if (!expected) return true;

  const actual = stripQuery(path || '/');
  const paths = Array.isArray(expected) ? expected : [expected];

  return paths.some((item) => {
    if (item instanceof RegExp) return item.test(actual);

    const pattern = String(item || '');
    if (pattern.endsWith('*')) {
      return actual.startsWith(pattern.slice(0, -1));
    }

    return actual === pattern;
  });
}

function stripQuery(value) {
  const path = String(value || '/');
  const index = path.indexOf('?');
  return index === -1 ? path : path.slice(0, index);
}

module.exports = { findMatchingPolicy, matchesPolicy, matchesMethod, matchesPath, stripQuery };
