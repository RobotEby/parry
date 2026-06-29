'use strict';

const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

const TYPE_COLOR = {
  THREAT: COLORS.red,
  BAN: COLORS.red,
  RATE_LIMIT: COLORS.yellow,
  STORE_FAILURE: COLORS.yellow,
  BRUTE_FORCE_ATTEMPT: COLORS.yellow,
  BRUTE_FORCE_BLOCK: COLORS.red,
  BRUTE_FORCE_RESET: COLORS.cyan,
  ROUTE_RATE_LIMIT_EXCEEDED: COLORS.yellow,
};

class ThreatLogger {
  /** @param {boolean} enabled */
  constructor(enabled = true) {
    this.enabled = enabled;
  }

  /** @param {import('../../types/index').ThreatLogEntry} entry */
  log(entry) {
    if (!this.enabled) return;

    const color = TYPE_COLOR[entry.type] || COLORS.cyan;
    const prefix = `${color}[Parry][${entry.type}]${COLORS.reset}`;
    const meta = `${COLORS.gray}${entry.timestamp} — IP: ${entry.ip}${COLORS.reset}`;

    if (entry.type === 'THREAT') {
      console.warn(
          `${prefix} ${meta}\n` +
          `  ${COLORS.cyan}${entry.method} ${entry.url}${COLORS.reset}\n` +
          entry.threats.map((t) => `  ⚠  ${t.detector} in the field "${t.field}"`).join('\n')
      );
    } else if (entry.type === 'BAN') {
      console.warn(`${prefix} ${meta} — ${entry.reason}`);
    } else {
      console.warn(`${prefix} ${meta}`);
    }
  }

  logHookError(error, entry) {
    if (!this.enabled) return;

    const timestamp = entry?.timestamp || new Date().toISOString();
    const ip = entry?.ip || 'unknown';
    const message = error && error.message ? error.message : String(error);
    const prefix = `${COLORS.yellow}[Parry][HOOK_ERROR]${COLORS.reset}`;
    const meta = `${COLORS.gray}${timestamp} — IP: ${ip}${COLORS.reset}`;

    console.warn(`${prefix} ${meta} — onThreat callback failed: ${message}`);
  }

  logStoreError(error, entry) {
    if (!this.enabled) return;

    const timestamp = entry?.timestamp || new Date().toISOString();
    const ip = entry?.ip || 'unknown';
    const mode = entry?.mode || 'fail-open';
    const message = error && error.message ? error.message : String(error);
    const prefix = `${COLORS.yellow}[Parry][STORE_FAILURE]${COLORS.reset}`;
    const meta = `${COLORS.gray}${timestamp} — IP: ${ip}${COLORS.reset}`;

    console.warn(`${prefix} ${meta} — ${mode}: ${message}`);
  }
}

module.exports = { ThreatLogger };
