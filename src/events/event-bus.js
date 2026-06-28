'use strict';

const { createThreatEvent, createHookErrorEvent } = require('./threat-event');
const { MemoryEventStore } = require('./memory-event-store');

class EventBus {
  constructor(options = {}) {
    this.eventStore = options.eventStore || new MemoryEventStore(options);
    this.listeners = [];
  }

  emitThreat(event, context = {}) {
    const normalized = createThreatEvent(event);
    this._record(normalized);
    this._notify(normalized, context);
    return normalized;
  }

  onThreat(listener) {
    if (typeof listener !== 'function') return () => {};
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((item) => item !== listener);
    };
  }

  getRecentEvents(options) {
    return this.eventStore.getRecentEvents(options);
  }

  getEventById(id) {
    return this.eventStore.getById(id);
  }

  _record(event) {
    this.eventStore.add(event);
  }

  _notify(event, context) {
    for (const listener of this.listeners) {
      try {
        listener(event, context.req, context.res);
      } catch (error) {
        const hookError = createHookErrorEvent(error, event);
        this._record(hookError);
      }
    }
  }
}

module.exports = { EventBus };
