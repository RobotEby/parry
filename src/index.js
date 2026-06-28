'use strict';

const { Parry_DDoS, createParry } = require('./middleware');
const { RateLimiter, ThreatLogger } = require('./core');
const { MemoryStore, RedisStore } = require('./stores');
const { EventBus, MemoryEventStore } = require('./events');
const { Metrics } = require('./observability');
const { createParryAdminRouter } = require('./admin');
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
  createParry,
  createParryAdminRouter,
  RateLimiter,
  ThreatLogger,
  MemoryStore,
  RedisStore,
  EventBus,
  MemoryEventStore,
  Metrics,
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
