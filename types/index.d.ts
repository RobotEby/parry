import { Request, Response, RequestHandler, Router } from 'express';

export interface Parry_DDoSOptions {
  /** Enables SQL injection detection. Default: true */
  sql?: boolean;
  /** Enables XSS detection. Default: true */
  xss?: boolean;
  /** Enables NoSQL injection detection. Default: true */
  nosql?: boolean;
  /** HTTP Parameter Pollution protection. Default: disabled */
  hpp?: {
    enabled?: boolean;
    allowDuplicateParamsFor?: string[];
  };
  /** Prototype Pollution key protection. Default: enabled */
  prototypePollution?: {
    enabled?: boolean;
  };
  /** Path Traversal protection for request values. Default: enabled */
  pathTraversal?: {
    enabled?: boolean;
  };
  /** Request shape limits. Default: enabled with conservative limits */
  requestShape?: {
    enabled?: boolean;
    maxDepth?: number;
    maxKeys?: number;
    maxArrayLength?: number;
    maxStringLength?: number;
  };
  /** Enables rate limiting by IP. Default: true */
  rateLimit?:
    | boolean
    | {
        enabled?: boolean;
        max?: number;
        maxRequests?: number;
        windowMs?: number;
        headers?: boolean;
      };
  /** Maximum number of requests per time window per IP. Default: 100 */
  maxRequests?: number;
  /** Duration of the rate limiting window in ms. Default: 60000 */
  windowMs?: number;
  /** Shared rate limit store. Defaults to MemoryStore. */
  store?: RateLimitStore;
  /** Store error behavior. Default: fail-open */
  storeFailureMode?: 'fail-open' | 'fail-closed';
  /** Optional route-based policies. */
  policies?: PolicyConfig[];
  /** Optional policy preset. Default: off */
  preset?: 'off' | 'recommended' | 'strict';
  /** Global brute force switch. Default: disabled */
  bruteForce?: false | { enabled?: boolean };
  /** Recent event buffer configuration. Default: { maxEvents: 500 } */
  events?: {
    maxEvents?: number;
  };
  /** Admin API metadata. The router is never mounted automatically. */
  admin?: {
    enabled?: boolean;
    allowMutations?: boolean;
  };
  /** Request id configuration. Default: enabled with x-request-id input and no response header. */
  requestId?: {
    enabled?: boolean;
    header?: string;
    responseHeader?: false | string;
  };
  /** Emits extra internal observability events where supported. Default: false */
  debug?: boolean;
  /** Suspicious attempts before temporary ban. Default: 5 */
  suspiciousThreshold?: number;
  /** Duration of the ban in ms. Default: 300000 (5 min) */
  banDurationMs?: number;
  /** Displays colored threat logs in the console. Default: true */
  logThreats?: boolean;
  /** Callback triggered for each detected threat */
  onThreat?: (entry: ThreatEvent, req: Request, res: Response) => void;
  /** Callback triggered for every emitted Parry event */
  onEvent?: (event: ThreatEvent) => void;
  /** Callback triggered when a configured store throws */
  onStoreError?: (error: Error, event: ThreatEvent) => void;
}

export type ThreatSeverity = 'none' | 'low' | 'medium' | 'high' | 'critical';
export type ThreatAction = 'allowed' | 'blocked' | 'observed' | 'reset' | 'error' | 'created';

export type DetectorType =
  | 'SQL_INJECTION'
  | 'XSS'
  | 'NOSQL_INJECTION'
  | 'HTTP_PARAMETER_POLLUTION'
  | 'PROTOTYPE_POLLUTION'
  | 'PATH_TRAVERSAL'
  | 'REQUEST_SHAPE'
  | 'BRUTE_FORCE'
  | 'ROUTE_RATE_LIMIT';

export interface ThreatMatch {
  detector: DetectorType;
  field: string;
  pattern: string;
  reason?: string;
  severity?: ThreatSeverity;
}

export type LogEntryType =
  | 'THREAT'
  | 'BAN'
  | 'RATE_LIMIT'
  | 'STORE_FAILURE'
  | 'BRUTE_FORCE_ATTEMPT'
  | 'BRUTE_FORCE_BLOCK'
  | 'BRUTE_FORCE_RESET'
  | 'ROUTE_RATE_LIMIT_EXCEEDED';

export type ThreatEventType =
  | 'SQL_INJECTION_BLOCKED'
  | 'XSS_BLOCKED'
  | 'NOSQL_INJECTION_BLOCKED'
  | 'HPP_BLOCKED'
  | 'PROTOTYPE_POLLUTION_BLOCKED'
  | 'PATH_TRAVERSAL_BLOCKED'
  | 'REQUEST_SHAPE_BLOCKED'
  | 'RATE_LIMIT_EXCEEDED'
  | 'ROUTE_RATE_LIMIT_EXCEEDED'
  | 'TEMPORARY_BAN_CREATED'
  | 'TEMPORARY_BAN_HIT'
  | 'BRUTE_FORCE_ATTEMPT'
  | 'BRUTE_FORCE_BLOCKED'
  | 'BRUTE_FORCE_RESET'
  | 'STORE_ERROR'
  | 'HOOK_ERROR'
  | 'SECURITY_EVENT';

export interface ThreatLogEntry {
  id?: string;
  type: LogEntryType | ThreatEventType | string;
  ip: string;
  timestamp: string;
  method?: string;
  url?: string;
  path?: string;
  detector?: DetectorType;
  detectorSlug?: string;
  severity?: ThreatSeverity;
  action?: ThreatAction;
  statusCode?: number;
  target?: string;
  reason?: string;
  module?: string;
  policyName?: string;
  keyTypes?: string[];
  requestId?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
  threats?: ThreatMatch[];
}

export interface ThreatEvent extends ThreatLogEntry {
  id: string;
  timestamp: string;
  severity: ThreatSeverity;
  action: ThreatAction;
  metadata: Record<string, unknown>;
}

export interface PolicyConfig {
  name: string;
  match: {
    method?: string | string[];
    path?: string | string[] | RegExp;
  };
  inheritGlobalRateLimit?: boolean;
  rateLimit?: {
    enabled?: boolean;
    max?: number;
    maxRequests?: number;
    windowMs?: number;
    key?: 'ip' | 'ip+path' | ((requestData: unknown) => string | { type?: string; value: string } | null);
  };
  bruteForce?: {
    enabled?: boolean;
    maxAttempts?: number;
    windowMs?: number;
    blockDurationMs?: number;
    keys?: Array<string | ((requestData: unknown) => string | { type?: string; value: string } | null)>;
    failureStatusCodes?: number[];
    successStatusCodes?: number[];
    blockedStatusCode?: number;
    resetOnSuccess?: boolean;
  };
}

export interface ParryRequestContext {
  requestId?: string;
  recordAuthFailure(reason?: string): void;
  recordAuthSuccess(): void;
  [key: string]: unknown;
}

export interface EventPage {
  data: ThreatEvent[];
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
}

export interface EventFilters {
  limit?: number | string;
  offset?: number | string;
  type?: string;
  severity?: ThreatSeverity | string;
  action?: ThreatAction | string;
  detector?: string;
  ip?: string;
  path?: string;
  policyName?: string;
}

export interface MetricsSnapshot {
  startedAt: string;
  uptimeMs: number;
  totalRequests: number;
  allowedRequests: number;
  blockedRequests: number;
  rateLimitedRequests: number;
  bruteForceBlocks: number;
  activeBans: number;
  eventsByType: Record<string, number>;
  eventsBySeverity: Record<string, number>;
  eventsByDetector: Record<string, number>;
  eventsByAction: Record<string, number>;
}

export interface AdminRouterOptions {
  requireAuth?: boolean;
  auth?: (req: Request) => boolean | Promise<boolean>;
}

export interface ParryInstance {
  middleware(): RequestHandler;
  eventBus: EventBus;
  metrics: Metrics;
  eventStore: MemoryEventStore;
  store: RateLimitStore;
  policies: PolicyConfig[];
  getContext(): unknown;
}

export interface RateLimitResult {
  limited: boolean;
  banned: boolean;
  remaining: number;
  resetAt: number;
  banExpiresAt: number | null;
}

export interface StoreCounterResult {
  key: string;
  count: number;
  resetAt: number | null;
  ttlMs: number;
}

export interface StoreBanResult {
  key: string;
  banned: boolean;
  banExpiresAt: number | null;
  metadata?: unknown;
}

export interface RateLimitStore {
  incrementRateLimit(key: string, windowMs: number): StoreCounterResult | Promise<StoreCounterResult>;
  getRateLimit(key: string): StoreCounterResult | Promise<StoreCounterResult>;
  resetRateLimit(key: string): unknown;
  ban(key: string, ttlMs: number, metadata?: unknown): StoreBanResult | Promise<StoreBanResult>;
  isBanned(key: string): StoreBanResult | Promise<StoreBanResult>;
  unban(key: string): unknown;
  recordSuspicious(
    key: string,
    ttlMs: number,
    metadata?: unknown
  ): StoreCounterResult | Promise<StoreCounterResult>;
  incrementCounter(key: string, ttlMs: number, metadata?: unknown): StoreCounterResult | Promise<StoreCounterResult>;
  getCounter(key: string): StoreCounterResult | Promise<StoreCounterResult>;
  resetCounter(key: string): unknown;
  blockKey(key: string, ttlMs: number, metadata?: unknown): StoreBlockResult | Promise<StoreBlockResult>;
  isBlocked(key: string): StoreBlockResult | Promise<StoreBlockResult>;
  unblockKey(key: string): unknown;
  close?(): unknown;
}

export interface StoreBlockResult {
  key: string;
  blocked: boolean;
  blockExpiresAt: number | null;
  metadata?: unknown;
}

export interface IPSnapshot {
  ip: string;
  requests: number;
  suspicious: number;
  banned: boolean;
  banExpiresAt: number | null;
}

export interface BanSnapshot {
  key: string;
  banExpiresAt: number;
  metadata?: unknown;
}

export declare class RateLimiter {
  constructor(
    config: Pick<
      Parry_DDoSOptions,
      'rateLimit' | 'maxRequests' | 'windowMs' | 'suspiciousThreshold' | 'banDurationMs' | 'store'
    >,
    store?: RateLimitStore
  );
  check(ip: string): Promise<RateLimitResult>;
  recordSuspicious(ip: string): Promise<unknown>;
  unban(ip: string): Promise<unknown>;
  snapshot(): Promise<IPSnapshot[]>;
  destroy(): unknown;
}

export declare class MemoryStore implements RateLimitStore {
  constructor();
  incrementRateLimit(key: string, windowMs: number): StoreCounterResult;
  getRateLimit(key: string): StoreCounterResult;
  resetRateLimit(key: string): boolean;
  ban(key: string, ttlMs: number, metadata?: unknown): StoreBanResult;
  isBanned(key: string): StoreBanResult;
  unban(key: string): boolean;
  recordSuspicious(key: string, ttlMs: number, metadata?: unknown): StoreCounterResult;
  incrementCounter(key: string, ttlMs: number, metadata?: unknown): StoreCounterResult;
  getCounter(key: string): StoreCounterResult;
  resetCounter(key: string): boolean;
  blockKey(key: string, ttlMs: number, metadata?: unknown): StoreBlockResult;
  isBlocked(key: string): StoreBlockResult;
  unblockKey(key: string): boolean;
  cleanup(now?: number): void;
  snapshot(windowMs: number): IPSnapshot[];
  listBans(): BanSnapshot[];
  clear(): void;
  close(): void;
}

export declare class RedisStore implements RateLimitStore {
  constructor(options: { client: unknown; prefix?: string; closeClient?: boolean });
  incrementRateLimit(key: string, windowMs: number): Promise<StoreCounterResult>;
  getRateLimit(key: string): Promise<StoreCounterResult>;
  resetRateLimit(key: string): Promise<unknown>;
  ban(key: string, ttlMs: number, metadata?: unknown): Promise<StoreBanResult>;
  isBanned(key: string): Promise<StoreBanResult>;
  unban(key: string): Promise<unknown>;
  recordSuspicious(key: string, ttlMs: number, metadata?: unknown): Promise<StoreCounterResult>;
  incrementCounter(key: string, ttlMs: number, metadata?: unknown): Promise<StoreCounterResult>;
  getCounter(key: string): Promise<StoreCounterResult>;
  resetCounter(key: string): Promise<unknown>;
  blockKey(key: string, ttlMs: number, metadata?: unknown): Promise<StoreBlockResult>;
  isBlocked(key: string): Promise<StoreBlockResult>;
  unblockKey(key: string): Promise<unknown>;
  close(): Promise<unknown>;
}

export declare const SQLInjectionDetector: {
  scan(value: string): string | null;
};
export declare const XSSDetector: { scan(value: string): string | null };
export declare const NoSQLDetector: { scan(value: unknown): string | null };
export declare const HPPDetector: {
  scan(
    query: unknown,
    options?: { allowDuplicateParamsFor?: string[] }
  ): ThreatMatch | null;
};
export declare const PrototypePollutionDetector: {
  scan(surfaces: unknown): ThreatMatch | null;
};
export declare const PathTraversalDetector: {
  scan(targets: Array<{ label: string; value: unknown }>): ThreatMatch | null;
};
export declare const RequestShapeGuard: {
  scan(
    surfaces: unknown,
    options: {
      maxDepth: number;
      maxKeys: number;
      maxArrayLength: number;
      maxStringLength: number;
    }
  ): ThreatMatch | null;
};

export declare class MemoryEventStore {
  constructor(options?: { maxEvents?: number });
  add(event: ThreatEvent): ThreatEvent;
  getRecentEvents(options?: EventFilters): EventPage;
  getById(id: string): ThreatEvent | null;
  clear(): void;
}

export declare class EventBus {
  constructor(options?: { eventStore?: MemoryEventStore; maxEvents?: number });
  emitThreat(event: Partial<ThreatEvent> | ThreatLogEntry, context?: { req?: Request; res?: Response }): ThreatEvent;
  onThreat(listener: (event: ThreatEvent, req?: Request, res?: Response) => void): () => void;
  getRecentEvents(options?: EventFilters): EventPage;
  getEventById(id: string): ThreatEvent | null;
}

export declare class Metrics {
  constructor();
  increment(name: string, value?: number): void;
  recordRequest(action: 'started' | 'allowed' | 'blocked'): void;
  recordEvent(event: ThreatEvent): void;
  snapshot(extra?: { activeBans?: number }): MetricsSnapshot;
}

export declare function Parry_DDoS(options?: Parry_DDoSOptions): RequestHandler;
export declare function createParry(options?: Parry_DDoSOptions): ParryInstance;
export declare function createParryAdminRouter(
  parry: ParryInstance | RequestHandler,
  options?: AdminRouterOptions
): Router;

declare module 'express-serve-static-core' {
  interface Request {
    parry?: ParryRequestContext;
  }
}
