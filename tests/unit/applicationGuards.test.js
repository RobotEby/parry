'use strict';

const {
  HPPDetector,
  PrototypePollutionDetector,
  PathTraversalDetector,
  RequestShapeGuard,
} = require('../../src/detectors');
const {
  HPP_DUPLICATE_QUERY,
  HPP_ALLOWED_QUERY,
  PROTOTYPE_POLLUTION_BODY,
  PROTOTYPE_POLLUTION_QUERY,
  PATH_TRAVERSAL_VALUES,
  PATH_TRAVERSAL_CLEAN_VALUES,
  SHAPE_LIMITS,
} = require('../fixtures/application-layer');

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

console.log('\n── Application-Layer Guards ───────────────────────────────');

const hppHit = HPPDetector.scan(HPP_DUPLICATE_QUERY, { allowDuplicateParamsFor: [] });
assert('HPP detects duplicated query params', hppHit?.detector === 'HTTP_PARAMETER_POLLUTION');
assert(
  'HPP allows configured duplicate params',
  HPPDetector.scan(HPP_ALLOWED_QUERY, { allowDuplicateParamsFor: ['tags'] }) === null
);
assert('HPP allows single query values', HPPDetector.scan({ id: '1' }) === null);

const protoBodyHit = PrototypePollutionDetector.scan({ body: PROTOTYPE_POLLUTION_BODY });
assert('Prototype Pollution detects __proto__ key', protoBodyHit?.detector === 'PROTOTYPE_POLLUTION');
const protoQueryHit = PrototypePollutionDetector.scan({ query: PROTOTYPE_POLLUTION_QUERY });
assert('Prototype Pollution detects constructor/prototype keys', protoQueryHit?.detector === 'PROTOTYPE_POLLUTION');
const circular = {};
circular.self = circular;
assert('Prototype Pollution handles circular objects', PrototypePollutionDetector.scan({ body: circular }) === null);

PATH_TRAVERSAL_VALUES.forEach((value, index) => {
  const hit = PathTraversalDetector.scan([{ label: `query.file${index}`, value }]);
  assert(`Path Traversal detects payload #${index + 1}`, hit?.detector === 'PATH_TRAVERSAL');
});
PATH_TRAVERSAL_CLEAN_VALUES.forEach((value, index) => {
  const hit = PathTraversalDetector.scan([{ label: `query.clean${index}`, value }]);
  assert(`Path Traversal allows clean value #${index + 1}`, hit === null);
});

assert(
  'Request Shape detects excessive depth',
  RequestShapeGuard.scan({ body: { a: { b: { c: { d: 'x' } } } } }, SHAPE_LIMITS)?.pattern ===
    'maxDepth'
);
assert(
  'Request Shape detects excessive keys',
  RequestShapeGuard.scan({ body: { a: 1, b: 2, c: 3, d: 4, e: 5, f: 6 } }, SHAPE_LIMITS)?.pattern === 'maxKeys'
);
assert(
  'Request Shape detects excessive array length',
  RequestShapeGuard.scan({ body: { ids: [1, 2, 3, 4] } }, SHAPE_LIMITS)?.pattern === 'maxArrayLength'
);
assert(
  'Request Shape detects excessive string length',
  RequestShapeGuard.scan({ body: { text: 'x'.repeat(13) } }, SHAPE_LIMITS)?.pattern === 'maxStringLength'
);
const circularShape = { name: 'safe' };
circularShape.self = circularShape;
assert('Request Shape handles circular objects', RequestShapeGuard.scan({ body: circularShape }, SHAPE_LIMITS) === null);
assert('Request Shape allows normal data', RequestShapeGuard.scan({ body: { tags: ['a', 'b'], name: 'safe' } }, SHAPE_LIMITS) === null);

module.exports = { passed, failed };
