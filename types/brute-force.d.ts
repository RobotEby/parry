import { PolicyConfig, ThreatEvent } from './index';

export interface BuiltKey {
  type: string;
  value: string;
  key: string;
}

export declare function createBruteForceContext(
  context: Record<string, unknown>
): Record<string, unknown>;
export declare function attachParryRequestApi(req: object, context: Record<string, unknown>): void;
export declare function checkBruteForceBlock(
  context: Record<string, unknown>
): Promise<Record<string, unknown>>;
export declare function observeAuthenticationResult(context: Record<string, unknown>): void;
export declare function finalizeAuthenticationResult(
  context: Record<string, unknown>
): Promise<unknown>;
export declare function createBruteForceEvent(context: Record<string, unknown>): ThreatEvent;
export declare function buildBruteForceKeys(
  policy: PolicyConfig,
  requestData: Record<string, unknown>
): BuiltKey[];
export declare function buildRouteRateLimitKey(
  policy: PolicyConfig,
  requestData: Record<string, unknown>
): BuiltKey | null;
export declare function buildKey(
  policyName: string,
  spec: string | ((requestData: Record<string, unknown>) => unknown),
  requestData: Record<string, unknown>,
  namespace: string
): BuiltKey | null;
export declare function resolveValue(
  path: string,
  requestData: Record<string, unknown>
): string | null;
export declare function createBlockedResponse(blocked: Record<string, unknown>): {
  statusCode: number;
  headers: { 'Retry-After': number };
  body: { error: string; code: string; retryAfter: number };
};
export declare function retryAfterSeconds(blocked: Record<string, unknown>): number;
