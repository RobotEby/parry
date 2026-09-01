'use strict';

const HPP_DUPLICATE_QUERY = { id: ['1', '2'] };
const HPP_ALLOWED_QUERY = { tags: ['node', 'security'] };

const PROTOTYPE_POLLUTION_BODY = JSON.parse('{"profile":{"__proto__":{"polluted":true}}}');
const PROTOTYPE_POLLUTION_QUERY = { options: { constructor: { prototype: { admin: true } } } };

const PATH_TRAVERSAL_VALUES = [
  '../etc/passwd',
  '..\\windows\\win.ini',
  '%2e%2e%2fetc/passwd',
  '%252e%252e%252fetc/passwd',
];
const PATH_TRAVERSAL_CLEAN_VALUES = ['release-notes..draft', 'folder/name.txt', 'user.profile'];

const SHAPE_LIMITS = {
  maxDepth: 2,
  maxKeys: 5,
  maxArrayLength: 3,
  maxStringLength: 12,
};

module.exports = {
  HPP_DUPLICATE_QUERY,
  HPP_ALLOWED_QUERY,
  PROTOTYPE_POLLUTION_BODY,
  PROTOTYPE_POLLUTION_QUERY,
  PATH_TRAVERSAL_VALUES,
  PATH_TRAVERSAL_CLEAN_VALUES,
  SHAPE_LIMITS,
};
