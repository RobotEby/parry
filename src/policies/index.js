'use strict';

const { findMatchingPolicy, matchesPolicy, matchesMethod, matchesPath } = require('./matcher');
const { buildPolicies, normalizePolicy } = require('./normalize-policy');
const { getPresetPolicies } = require('./presets');

module.exports = {
  findMatchingPolicy,
  matchesPolicy,
  matchesMethod,
  matchesPath,
  buildPolicies,
  normalizePolicy,
  getPresetPolicies,
};
