'use strict';

const { Parry_DDoS } = require('./middleware');
const { RateLimiter, ThreatLogger } = require('./core');
const {
  SQLInjectionDetector,
  XSSDetector,
  NoSQLDetector,
  HPPDetector,
  PrototypePollutionDetector,
  PathTraversalDetector,
  RequestShapeGuard,
} = require('./detectors');

module.exports = {
  Parry_DDoS,
  RateLimiter,
  ThreatLogger,
  SQLInjectionDetector,
  XSSDetector,
  NoSQLDetector,
  HPPDetector,
  PrototypePollutionDetector,
  PathTraversalDetector,
  RequestShapeGuard,
};
