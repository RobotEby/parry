export { Metrics, MetricsSnapshot, EventPage, PolicyConfig } from './index';
import { EventPage, MetricsSnapshot, PolicyConfig } from './index';

export declare function createSnapshot(context: Record<string, unknown>): {
  metrics: MetricsSnapshot;
  policies: PolicyConfig[];
  store: string;
  events: EventPage;
};
export declare function describeStore(store: unknown): string;
export declare function sanitizePolicies(policies: PolicyConfig[]): PolicyConfig[];
export declare function countActiveBans(store: unknown): number;
