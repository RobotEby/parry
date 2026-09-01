export { EventBus, MemoryEventStore } from './index';
export { ThreatEvent, ThreatLogEntry, EventFilters, EventPage } from './index';
import { ThreatEvent, ThreatLogEntry } from './index';

export declare function createThreatEvent(
  input?: Partial<ThreatEvent> | ThreatLogEntry
): ThreatEvent;
export declare function createStoreErrorEvent(
  error: unknown,
  context?: Record<string, unknown>
): ThreatEvent;
export declare function createHookErrorEvent(
  error: unknown,
  event?: Partial<ThreatEvent>
): ThreatEvent;
export declare function sanitizeEvent<T>(event: T): T;
