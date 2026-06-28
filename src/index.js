'use strict';

const { Parry_DDoS } = require('./middleware');
const { RateLimiter, ThreatLogger } = require('./core');
const { MemoryStore, RedisStore } = require('./stores');
const Policies = require('./policies');
const BruteForce = require('./brute-force');
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
  MemoryStore,
  RedisStore,
  Policies,
  BruteForce,
  SQLInjectionDetector,
  XSSDetector,
  NoSQLDetector,
  HPPDetector,
  PrototypePollutionDetector,
  PathTraversalDetector,
  RequestShapeGuard,
};
