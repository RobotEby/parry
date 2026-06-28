import { Request, Response, NextFunction, RequestHandler } from 'express';

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
  /** Suspicious attempts before temporary ban. Default: 5 */
  suspiciousThreshold?: number;
  /** Duration of the ban in ms. Default: 300000 (5 min) */
  banDurationMs?: number;
  /** Displays colored threat logs in the console. Default: true */
  logThreats?: boolean;
  /** Callback triggered for each detected threat */
  onThreat?: (entry: ThreatLogEntry, req: Request, res: Response) => void;
}

export type DetectorType =
  | 'SQL_INJECTION'
  | 'XSS'
  | 'NOSQL_INJECTION'
  | 'HTTP_PARAMETER_POLLUTION'
  | 'PROTOTYPE_POLLUTION'
  | 'PATH_TRAVERSAL'
  | 'REQUEST_SHAPE';

export interface ThreatMatch {
  detector: DetectorType;
  field: string;
  pattern: string;
  reason?: string;
  severity?: 'none' | 'low' | 'medium' | 'high';
}

export type LogEntryType = 'THREAT' | 'BAN' | 'RATE_LIMIT' | 'STORE_FAILURE';

export interface ThreatLogEntry {
  type: LogEntryType;
  ip: string;
  timestamp: string;
  method?: string;
  url?: string;
  detector?: DetectorType;
  severity?: 'none' | 'low' | 'medium' | 'high';
  target?: string;
  reason?: string;
  threats?: ThreatMatch[];
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
  close?(): unknown;
}

export interface IPSnapshot {
  ip: string;
  requests: number;
  suspicious: number;
  banned: boolean;
  banExpiresAt: number | null;
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
  cleanup(now?: number): void;
  snapshot(windowMs: number): IPSnapshot[];
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

export declare function Parry_DDoS(options?: Parry_DDoSOptions): RequestHandler;
