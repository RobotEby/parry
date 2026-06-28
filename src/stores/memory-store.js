'use strict';

class MemoryStore {
  constructor() {
    this.records = new Map();
  }

  has(key) {
    return this.records.has(key);
  }

  get(key) {
    return this.records.get(key);
  }

  set(key, value) {
    this.records.set(key, value);
  }

  delete(key) {
    return this.records.delete(key);
  }

  entries() {
    return this.records.entries();
  }

  clear() {
    this.records.clear();
  }

  getOrCreate(key, createValue) {
    if (!this.records.has(key)) this.records.set(key, createValue());
    return this.records.get(key);
  }
}

module.exports = { MemoryStore };
