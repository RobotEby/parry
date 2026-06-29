'use strict';

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..', '..');
const FIXTURE_DIR = path.join(ROOT_DIR, 'tests', 'fixtures', 'payloads');

const VALID_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const VALID_MODES = new Set(['off', 'recommended', 'strict', 'monitor']);
const OPTIONAL_DETECTORS = new Set(['command-injection', 'ssrf']);
const IMPLEMENTED_DETECTORS = new Set([
  'sql',
  'xss',
  'nosql',
  'hpp',
  'prototype-pollution',
  'path-traversal',
  'request-shape',
  'brute-force',
]);

const DETECTOR_TO_INTERNAL = {
  sql: 'SQL_INJECTION',
  xss: 'XSS',
  nosql: 'NOSQL_INJECTION',
  hpp: 'HTTP_PARAMETER_POLLUTION',
  'prototype-pollution': 'PROTOTYPE_POLLUTION',
  'path-traversal': 'PATH_TRAVERSAL',
  'request-shape': 'REQUEST_SHAPE',
  'brute-force': 'BRUTE_FORCE',
};

function fixturePath(fileName) {
  return path.join(FIXTURE_DIR, fileName);
}

function listFixtureFiles() {
  if (!fs.existsSync(FIXTURE_DIR)) return [];
  return fs
    .readdirSync(FIXTURE_DIR)
    .filter((fileName) => fileName.endsWith('.json'))
    .sort();
}

function loadFixtureFile(fileName) {
  const fullPath = fixturePath(fileName);
  const raw = fs.readFileSync(fullPath, 'utf8');
  return JSON.parse(raw);
}

function loadFixtures() {
  const byCategory = {};
  const all = [];

  for (const fileName of listFixtureFiles()) {
    const category = path.basename(fileName, '.json');
    const fixtures = loadFixtureFile(fileName);
    byCategory[category] = fixtures;
    for (const fixture of fixtures) {
      all.push({ ...fixture, __fileName: fileName });
    }
  }

  return { all, byCategory };
}

function validateFixtures() {
  const errors = [];
  const seenIds = new Map();
  const counts = {};

  for (const fileName of listFixtureFiles()) {
    const category = path.basename(fileName, '.json');
    let fixtures;

    try {
      fixtures = loadFixtureFile(fileName);
    } catch (error) {
      errors.push(`${fileName}: invalid JSON (${error.message})`);
      continue;
    }

    if (!Array.isArray(fixtures)) {
      errors.push(`${fileName}: root value must be an array`);
      continue;
    }

    counts[category] = fixtures.length;
    fixtures.forEach((fixture, index) => {
      const label = fixture && fixture.id ? `${fileName}:${fixture.id}` : `${fileName}#${index}`;
      validateFixture({ fixture, label, category, errors });

      if (fixture && fixture.id) {
        if (seenIds.has(fixture.id)) {
          errors.push(`${label}: duplicate id also found in ${seenIds.get(fixture.id)}`);
        } else {
          seenIds.set(fixture.id, label);
        }
      }
    });
  }

  return {
    ok: errors.length === 0,
    errors,
    counts,
    total: Object.values(counts).reduce((sum, value) => sum + value, 0),
  };
}

function validateFixture({ fixture, label, category, errors }) {
  if (!fixture || typeof fixture !== 'object' || Array.isArray(fixture)) {
    errors.push(`${label}: fixture must be an object`);
    return;
  }

  for (const field of ['id', 'category', 'name', 'payload', 'target', 'expected', 'source']) {
    if (!(field in fixture)) errors.push(`${label}: missing required field "${field}"`);
  }

  if (fixture.category !== category) {
    errors.push(`${label}: category "${fixture.category}" does not match file category "${category}"`);
  }

  if (!fixture.expected || typeof fixture.expected !== 'object' || Array.isArray(fixture.expected)) {
    errors.push(`${label}: expected must be an object`);
  } else {
    if (typeof fixture.expected.blocked !== 'boolean') {
      errors.push(`${label}: expected.blocked must be boolean`);
    }
    if (fixture.expected.blocked === true && !fixture.expected.detector) {
      errors.push(`${label}: expected.detector is required when expected.blocked is true`);
    }
    if (!VALID_SEVERITIES.has(fixture.expected.severity)) {
      errors.push(`${label}: expected.severity must be one of ${[...VALID_SEVERITIES].join(', ')}`);
    }
    if (fixture.expected.mode && !VALID_MODES.has(fixture.expected.mode)) {
      errors.push(`${label}: expected.mode must be one of ${[...VALID_MODES].join(', ')}`);
    }
  }

  if (!fixture.source || typeof fixture.source !== 'object' || Array.isArray(fixture.source)) {
    errors.push(`${label}: source must be an object`);
  } else {
    if (!fixture.source.name) errors.push(`${label}: source.name is required`);
    if (!fixture.source.category) errors.push(`${label}: source.category is required`);
  }
}

function getExpectedCounts() {
  return {
    sql: 28,
    xss: 28,
    nosql: 20,
    hpp: 12,
    'prototype-pollution': 12,
    'path-traversal': 20,
    'command-injection': 12,
    ssrf: 12,
    'request-shape': 12,
    'brute-force': 10,
    benign: 45,
  };
}

module.exports = {
  ROOT_DIR,
  FIXTURE_DIR,
  OPTIONAL_DETECTORS,
  IMPLEMENTED_DETECTORS,
  DETECTOR_TO_INTERNAL,
  fixturePath,
  listFixtureFiles,
  loadFixtureFile,
  loadFixtures,
  validateFixtures,
  getExpectedCounts,
};
