'use strict';

const { SQLInjectionDetector } = require('./sql');
const { XSSDetector } = require('./xss');
const { NoSQLDetector } = require('./nosql');
const { HPPDetector } = require('./hpp');
const { PrototypePollutionDetector } = require('./prototype-pollution');
const { PathTraversalDetector } = require('./path-traversal');
const { RequestShapeGuard } = require('./request-shape');

module.exports = {
  SQLInjectionDetector,
  XSSDetector,
  NoSQLDetector,
  HPPDetector,
  PrototypePollutionDetector,
  PathTraversalDetector,
  RequestShapeGuard,
};
