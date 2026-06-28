'use strict';

class MemoryEventStore {
  constructor(options = {}) {
    this.maxEvents = options.maxEvents || 500;
    this.events = [];
  }

  add(event) {
    this.events.unshift(event);
    if (this.events.length > this.maxEvents) {
      this.events.length = this.maxEvents;
    }
    return event;
  }

  getRecentEvents(options = {}) {
    const limit = clampNumber(options.limit, 50, 1, this.maxEvents);
    const offset = clampNumber(options.offset, 0, 0, this.maxEvents);
    const filtered = this.events.filter((event) => matchesFilters(event, options));

    return {
      data: filtered.slice(offset, offset + limit),
      pagination: {
        limit,
        offset,
        total: filtered.length,
      },
    };
  }

  getById(id) {
    return this.events.find((event) => event.id === id) || null;
  }

  clear() {
    this.events = [];
  }
}

function matchesFilters(event, filters) {
  for (const key of ['type', 'severity', 'action', 'detector', 'ip', 'path', 'policyName']) {
    if (filters[key] && event[key] !== filters[key]) return false;
  }
  return true;
}

function clampNumber(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
}

module.exports = { MemoryEventStore };
