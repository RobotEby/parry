'use strict';

const { SENSITIVE_HEADERS } = require('../../constants/patterns');
const { flattenObject } = require('../utils/flatten');
const { normalizeTarget } = require('../utils/normalize');

function collectRequestTargets(req, maxDepth) {
  const targets = [];
  const headers = req.headers || {};

  const add = (label, value) => {
    if (value != null) targets.push(normalizeTarget({ label, value }));
  };

  if (req.query && typeof req.query === 'object') {
    for (const [key, value] of Object.entries(req.query)) add(`query.${key}`, value);
  }

  if (req.params && typeof req.params === 'object') {
    for (const [key, value] of Object.entries(req.params)) add(`params.${key}`, value);
  }

  if (req.body && typeof req.body === 'object') {
    add('body', req.body);
    for (const target of flattenObject(req.body, 'body', maxDepth)) add(target.label, target.value);
  }

  for (const header of SENSITIVE_HEADERS) {
    if (headers[header]) add(`header.${header}`, headers[header]);
  }

  return targets;
}

module.exports = { collectRequestTargets };
