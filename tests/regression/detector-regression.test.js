'use strict';

const { test } = require('node:test');
const nodeAssert = require('node:assert/strict');
const { DEFAULTS } = require('../../config/defaults');
const {
  HPPDetector,
  NoSQLDetector,
  PathTraversalDetector,
  PrototypePollutionDetector,
  RequestShapeGuard,
  SQLInjectionDetector,
  XSSDetector,
} = require('../../src/detectors');
const { loadFixtures } = require('../../scripts/payloads/fixture-utils');
const { assignTarget, materializePayload, mockReq } = require('./fixture-helpers');

function assert(description, condition) {
  nodeAssert.ok(condition, description);
}

function runAll() {
  console.log('\n── Detector Payload Regression ─────────────────────────────');

  const { byCategory } = loadFixtures();

  for (const fixture of byCategory.sql) {
    assert(`SQL blocks ${fixture.id}`, SQLInjectionDetector.scan(String(fixture.payload)) !== null);
  }

  for (const fixture of byCategory.xss) {
    assert(`XSS blocks ${fixture.id}`, XSSDetector.scan(String(fixture.payload)) !== null);
  }

  for (const fixture of byCategory.nosql) {
    assert(`NoSQL blocks ${fixture.id}`, NoSQLDetector.scan(materializePayload(fixture)) !== null);
  }

  for (const fixture of byCategory.hpp) {
    assert(`HPP blocks ${fixture.id}`, HPPDetector.scan(materializePayload(fixture), {}) !== null);
  }

  for (const fixture of byCategory['prototype-pollution']) {
    assert(
      `Prototype Pollution blocks ${fixture.id}`,
      PrototypePollutionDetector.scan(buildSurfaces(fixture)) !== null
    );
  }

  for (const fixture of byCategory['path-traversal']) {
    assert(
      `Path Traversal blocks ${fixture.id}`,
      PathTraversalDetector.scan([
        { label: fixture.target, value: materializePayload(fixture) },
      ]) !== null
    );
  }

  for (const fixture of byCategory['request-shape']) {
    assert(
      `Request Shape blocks ${fixture.id}`,
      RequestShapeGuard.scan(buildSurfaces(fixture), DEFAULTS.requestShape) !== null
    );
  }

  for (const fixture of byCategory.benign) {
    assert(
      `Benign fixture ${fixture.id} is not blocked by direct detectors`,
      allowsBenignFixture(fixture)
    );
  }
}

function buildSurfaces(fixture) {
  const req = mockReq();
  assignTarget(req, fixture.target, materializePayload(fixture));
  return {
    query: req.query || {},
    params: req.params || {},
    body: req.body,
  };
}

function allowsBenignFixture(fixture) {
  const value = materializePayload(fixture);
  const stringValue = typeof value === 'string' ? value : JSON.stringify(value);

  if (SQLInjectionDetector.scan(stringValue) !== null) return false;
  if (XSSDetector.scan(stringValue) !== null) return false;
  if (fixture.tags?.includes('nosql-allowlist')) {
    if (
      NoSQLDetector.scan(value, {
        rootPath: fixture.target,
        allowedOperators: { [fixture.target]: ['$gt'] },
      }) !== null
    ) {
      return false;
    }
  } else {
    if (NoSQLDetector.scan(value) !== null) return false;
    if (NoSQLDetector.scan(stringValue) !== null) return false;
  }
  if (PrototypePollutionDetector.scan(buildSurfaces(fixture)) !== null) return false;
  if (PathTraversalDetector.scan([{ label: fixture.target, value }]) !== null) return false;

  const req = mockReq();
  assignTarget(req, fixture.target, value);
  if (
    HPPDetector.scan(req.query, { allowDuplicateParamsFor: ['tags', 'filters', 'sort'] }) !== null
  )
    return false;

  return true;
}

test('Detector payload regression', runAll);
