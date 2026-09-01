export {
  createParryAdminRouter,
  AdminRouterOptions,
  AdminAuthMode,
  AdminAuthConfig,
  AdminAuthStrategyConfig,
  AdminCombinedAuthConfig,
  ParryAdminContext,
} from './index';
import { Request, RequestHandler } from 'express';
import { AdminAuthConfig, ParryAdminContext } from './index';

export declare function resolveParryContext(parry: unknown): Record<string, unknown> | null;
export declare function createAdminAuthMiddleware(
  config: AdminAuthConfig,
  context?: Record<string, unknown>
): RequestHandler;
export declare function authenticateAdminRequest(
  req: Request,
  config: AdminAuthConfig,
  context?: Record<string, unknown>
): Promise<{ ok: boolean; statusCode?: number; admin?: ParryAdminContext }>;
export declare function requireAdminAuth(
  options?: Record<string, unknown>,
  context?: Record<string, unknown> | null
): RequestHandler;
