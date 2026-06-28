'use strict';

const { sanitizeEvent, sanitizeUserAgent } = require('./sanitize-event');

let eventSequence = 0;

const LEGACY_TYPE_MAP = {
  BAN: 'TEMPORARY_BAN_HIT',
  RATE_LIMIT: 'RATE_LIMIT_EXCEEDED',
  STORE_FAILURE: 'STORE_ERROR',
  THREAT: null,
  BRUTE_FORCE_BLOCK: 'BRUTE_FORCE_BLOCKED',
};

const DETECTOR_TYPE_MAP = {
  SQL_INJECTION: 'SQL_INJECTION_BLOCKED',
  XSS: 'XSS_BLOCKED',
  NOSQL_INJECTION: 'NOSQL_INJECTION_BLOCKED',
  HTTP_PARAMETER_POLLUTION: 'HPP_BLOCKED',
  PROTOTYPE_POLLUTION: 'PROTOTYPE_POLLUTION_BLOCKED',
  PATH_TRAVERSAL: 'PATH_TRAVERSAL_BLOCKED',
  REQUEST_SHAPE: 'REQUEST_SHAPE_BLOCKED',
};

const DETECTOR_NAME_MAP = {
  SQL_INJECTION: 'sql',
  XSS: 'xss',
  NOSQL_INJECTION: 'nosql',
  HTTP_PARAMETER_POLLUTION: 'hpp',
  PROTOTYPE_POLLUTION: 'prototype-pollution',
  PATH_TRAVERSAL: 'path-traversal',
  REQUEST_SHAPE: 'request-shape',
  BRUTE_FORCE: 'brute-force',
  ROUTE_RATE_LIMIT: 'route-rate-limit',
};

function createThreatEvent(input = {}) {
  const source = sanitizeEvent(input);
  const firstThreat = Array.isArray(source.threats) ? source.threats[0] : null;
  const sourceDetector = source.detector || firstThreat?.detector;
  const type = normalizeType(source.type, sourceDetector);
  const event = {
    ...source,
    id: source.id || createEventId(),
    type,
    module: source.module || moduleForType(type),
    detector: sourceDetector || source.detector,
    detectorSlug: normalizeDetector(sourceDetector),
    severity: source.severity || firstThreat?.severity || severityForType(type),
    action: source.action || actionForType(type),
    reason: source.reason || firstThreat?.reason || reasonForType(type),
    ip: source.ip,
    method: source.method,
    path: source.path || normalizePath(source.url),
    statusCode: source.statusCode,
    policyName: source.policyName,
    keyTypes: source.keyTypes,
    requestId: source.requestId,
    userAgent: sanitizeUserAgent(source.userAgent),
    timestamp: source.timestamp || new Date().toISOString(),
    metadata: sanitizeEvent(source.metadata || {}),
  };

  if (source.url && !event.url) event.url = source.url;
  if (source.threats) event.threats = source.threats;
  return sanitizeEvent(event);
}

function createStoreErrorEvent(error, context = {}) {
  return createThreatEvent({
    type: 'STORE_ERROR',
    module: context.module || 'store',
    severity: 'medium',
    action: 'error',
    reason: error && error.message ? error.message : String(error),
    ...context,
  });
}

function createHookErrorEvent(error, event = {}) {
  return createThreatEvent({
    type: 'HOOK_ERROR',
    module: 'hook',
    severity: 'low',
    action: 'error',
    reason: error && error.message ? error.message : String(error),
    ip: event.ip,
    method: event.method,
    path: event.path,
    requestId: event.requestId,
    metadata: { sourceEventId: event.id, sourceType: event.type },
  });
}

function createEventId() {
  eventSequence += 1;
  return `evt_${Date.now().toString(36)}_${eventSequence.toString(36)}`;
}

function normalizeType(type, detector) {
  if (LEGACY_TYPE_MAP[type]) return LEGACY_TYPE_MAP[type];
  if (type === 'THREAT' && detector) return DETECTOR_TYPE_MAP[detector] || 'THREAT_BLOCKED';
  if (DETECTOR_TYPE_MAP[detector] && (!type || type === detector)) return DETECTOR_TYPE_MAP[detector];
  return type || 'SECURITY_EVENT';
}

function normalizeDetector(detector) {
  return DETECTOR_NAME_MAP[detector] || detector || undefined;
}

function moduleForType(type) {
  if (type.startsWith('BRUTE_FORCE')) return 'brute-force';
  if (type === 'ROUTE_RATE_LIMIT_EXCEEDED') return 'route-policy';
  if (type === 'RATE_LIMIT_EXCEEDED' || type.startsWith('TEMPORARY_BAN')) return 'rate-limit';
  if (type === 'STORE_ERROR') return 'store';
  if (type === 'HOOK_ERROR') return 'hook';
  return 'detector';
}

function severityForType(type) {
  if (type.includes('SQL') || type.includes('NOSQL') || type.includes('BRUTE_FORCE_BLOCK')) return 'high';
  if (type.includes('BLOCKED') || type.includes('RATE_LIMIT') || type.includes('STORE')) return 'medium';
  if (type.includes('RESET')) return 'low';
  return 'medium';
}

function actionForType(type) {
  if (type.includes('BLOCKED') || type.includes('EXCEEDED') || type.includes('BAN_HIT')) return 'blocked';
  if (type.includes('ATTEMPT')) return 'observed';
  if (type.includes('RESET')) return 'reset';
  if (type.includes('ERROR')) return 'error';
  if (type.includes('CREATED')) return 'created';
  return 'observed';
}

function reasonForType(type) {
  return type.toLowerCase().replace(/_/g, ' ');
}

function normalizePath(url) {
  if (!url) return undefined;
  const value = String(url);
  const index = value.indexOf('?');
  return index === -1 ? value : value.slice(0, index);
}

module.exports = {
  createThreatEvent,
  createStoreErrorEvent,
  createHookErrorEvent,
  createEventId,
  normalizeType,
};
