import {
  BruteForce,
  EventBus,
  MemoryEventStore,
  MemoryStore,
  Metrics,
  NoSQLDetector,
  Parry_DDoS,
  Parry_DDoSOptions,
  ParryOptions,
  Policies,
  RateLimiter,
  RedisStore,
  SQLInjectionDetector,
  ThreatLogger,
  XSSDetector,
  createParry,
  createParryAdminRouter,
} from '@roboteby/parry';
import { requireAdminAuth } from '@roboteby/parry/admin';
import { buildBruteForceKeys } from '@roboteby/parry/brute-force';
import { RateLimiter as CoreRateLimiter } from '@roboteby/parry/core';
import { HPPDetector } from '@roboteby/parry/detectors';
import { createThreatEvent } from '@roboteby/parry/events';
import { createSnapshot } from '@roboteby/parry/observability';
import { matchesPath } from '@roboteby/parry/policies';
import { MemoryStore as SubpathMemoryStore } from '@roboteby/parry/stores';

const options: ParryOptions = {
  rateLimit: false,
  headers: { scan: ['user-agent'] },
  nosql: { allowedOperators: { 'body.filters.price': ['$gt'] } },
};
const legacyOptions: Parry_DDoSOptions = options;
const instance = createParry(options);

void legacyOptions;
void instance;
void createParryAdminRouter;
void Parry_DDoS;
void MemoryStore;
void RedisStore;
void RateLimiter;
void CoreRateLimiter;
void ThreatLogger;
void EventBus;
void MemoryEventStore;
void Metrics;
void SQLInjectionDetector;
void XSSDetector;
void NoSQLDetector;
void HPPDetector;
void Policies;
void BruteForce;
void SubpathMemoryStore;
void requireAdminAuth;
void buildBruteForceKeys;
void createThreatEvent;
void createSnapshot;
void matchesPath;
