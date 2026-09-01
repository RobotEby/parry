import { ParryOptions, PolicyConfig } from './index';

export declare function findMatchingPolicy(
  policies: PolicyConfig[],
  requestData: { method?: string; path?: string; url?: string }
): PolicyConfig | null;
export declare function matchesPolicy(
  policy: PolicyConfig,
  requestData: { method?: string; path?: string; url?: string }
): boolean;
export declare function matchesMethod(
  expected: string | string[] | undefined,
  method?: string
): boolean;
export declare function matchesPath(
  expected: string | string[] | RegExp | undefined,
  path?: string
): boolean;
export declare function buildPolicies(options?: ParryOptions): PolicyConfig[];
export declare function normalizePolicy(policy: PolicyConfig, options?: ParryOptions): PolicyConfig;
export declare function getPresetPolicies(name?: 'off' | 'recommended' | 'strict'): PolicyConfig[];
