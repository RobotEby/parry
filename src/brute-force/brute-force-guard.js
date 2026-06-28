'use strict';

const { buildBruteForceKeys } = require('./key-builder');
const { createAllowedResult, createBlockedResult } = require('./result');

function createBruteForceContext({ policy, requestData, req, res, store, config, logger, eventBus }) {
  const enabled = Boolean(policy?.bruteForce?.enabled);
  const keys = enabled ? buildBruteForceKeys(policy, requestData) : [];
  const state = {
    manualAction: null,
    manualReason: null,
    processed: false,
  };

  return { policy, requestData, req, res, store, config, logger, eventBus, enabled, keys, state };
}

function attachParryRequestApi(req, context) {
  const existing = req.parry && typeof req.parry === 'object' ? req.parry : {};
  req.parry = {
    ...existing,
    recordAuthFailure(reason) {
      context.state.manualAction = 'failure';
      context.state.manualReason = reason || 'manual_failure';
    },
    recordAuthSuccess() {
      context.state.manualAction = 'success';
      context.state.manualReason = 'manual_success';
    },
  };
}

async function checkBruteForceBlock(context) {
  if (!context.enabled || context.keys.length === 0) return createAllowedResult();

  try {
    for (const key of context.keys) {
      const blocked = await context.store.isBlocked(key.key);
      if (blocked.blocked) {
        const event = createBruteForceEvent(context, 'BRUTE_FORCE_BLOCK', {
          reason: 'Authentication attempts temporarily blocked',
          severity: 'high',
          keyTypes: context.keys.map((item) => item.type),
        });
        emitEvent(context, event);

        return createBlockedResult({
          statusCode: context.policy.bruteForce.blockedStatusCode,
          blockExpiresAt: blocked.blockExpiresAt,
          retryAfterMs: Math.max(0, blocked.blockExpiresAt - Date.now()),
          event,
        });
      }
    }
  } catch (error) {
    return handleStoreFailure(context, error);
  }

  return createAllowedResult();
}

function observeAuthenticationResult(context) {
  if (!context.enabled || context.keys.length === 0 || !context.res || typeof context.res.on !== 'function') {
    return;
  }

  context.res.on('finish', () => {
    finalizeAuthenticationResult(context).catch((error) => {
      const event = createStoreFailureEvent(context, error);
      if (context.logger && typeof context.logger.logStoreError === 'function') {
        context.logger.logStoreError(error, event);
      }
    });
  });
}

async function finalizeAuthenticationResult(context) {
  if (context.state.processed) return;
  context.state.processed = true;

  const action = resolveAction(context);
  if (action === 'failure') {
    await recordFailure(context, context.state.manualReason || 'status_failure');
  } else if (action === 'success' && context.policy.bruteForce.resetOnSuccess) {
    await resetCounters(context);
  }
}

function resolveAction(context) {
  if (context.state.manualAction) return context.state.manualAction;

  const status = getResponseStatus(context.res);
  if (context.policy.bruteForce.failureStatusCodes.includes(status)) return 'failure';
  if (context.policy.bruteForce.successStatusCodes.includes(status)) return 'success';
  return null;
}

async function recordFailure(context, reason) {
  const attempts = [];
  for (const key of context.keys) {
    const attempt = await context.store.incrementCounter(key.key, context.policy.bruteForce.windowMs, {
      policyName: context.policy.name,
      keyType: key.type,
      reason,
    });
    attempts.push({ key, attempt });
  }

  emitEvent(
    context,
    createBruteForceEvent(context, 'BRUTE_FORCE_ATTEMPT', {
      reason,
      severity: 'medium',
      keyTypes: context.keys.map((item) => item.type),
    })
  );

  const shouldBlock = attempts.some(({ attempt }) => attempt.count >= context.policy.bruteForce.maxAttempts);
  if (!shouldBlock) return;

  for (const key of context.keys) {
    await context.store.blockKey(key.key, context.policy.bruteForce.blockDurationMs, {
      policyName: context.policy.name,
      keyType: key.type,
      reason: 'max_attempts_exceeded',
    });
  }

  emitEvent(
    context,
    createBruteForceEvent(context, 'BRUTE_FORCE_BLOCK', {
      reason: 'max_attempts_exceeded',
      severity: 'high',
      keyTypes: context.keys.map((item) => item.type),
    })
  );
}

async function resetCounters(context) {
  for (const key of context.keys) {
    await context.store.resetCounter(key.key);
  }

  emitEvent(
    context,
    createBruteForceEvent(context, 'BRUTE_FORCE_RESET', {
      reason: context.state.manualReason || 'auth_success',
      severity: 'low',
      keyTypes: context.keys.map((item) => item.type),
    })
  );
}

function handleStoreFailure(context, error) {
  const mode = context.config.storeFailureMode === 'fail-closed' ? 'fail-closed' : 'fail-open';
  const event = createStoreFailureEvent(context, error, mode);
  if (context.logger && typeof context.logger.logStoreError === 'function') {
    context.logger.logStoreError(error, event);
  }

  if (mode === 'fail-open') return createAllowedResult();

  return createBlockedResult({
    statusCode: 503,
    storeFailure: true,
    event,
  });
}

function createBruteForceEvent(context, type, details = {}) {
  return {
    type,
    module: 'brute-force',
    detector: 'BRUTE_FORCE',
    policyName: context.policy.name,
    ip: context.requestData.ip,
    method: context.requestData.method,
    path: context.requestData.path,
    keyTypes: details.keyTypes || [],
    severity: details.severity || 'medium',
    reason: details.reason,
    timestamp: new Date().toISOString(),
    requestId: context.requestData.requestId || getHeader(context.requestData.headers, 'x-request-id'),
    userAgent: context.requestData.userAgent || getHeader(context.requestData.headers, 'user-agent'),
  };
}

function createStoreFailureEvent(context, error, mode) {
  return {
    type: 'STORE_FAILURE',
    module: 'brute-force',
    policyName: context.policy?.name,
    ip: context.requestData.ip,
    method: context.requestData.method,
    path: context.requestData.path,
    timestamp: new Date().toISOString(),
    reason: error && error.message ? error.message : String(error),
    mode: mode || context.config.storeFailureMode || 'fail-open',
    requestId: context.requestData.requestId || getHeader(context.requestData.headers, 'x-request-id'),
    userAgent: context.requestData.userAgent || getHeader(context.requestData.headers, 'user-agent'),
  };
}

function emitEvent(context, event) {
  if (context.eventBus && typeof context.eventBus.emitThreat === 'function') {
    context.eventBus.emitThreat(event, { req: context.req, res: context.res });
    return;
  }

  if (context.logger && typeof context.logger.log === 'function') context.logger.log(event);

  if (context.config.onThreat) {
    try {
      context.config.onThreat(event, context.req, context.res);
    } catch (error) {
      if (context.logger && typeof context.logger.logHookError === 'function') {
        context.logger.logHookError(error, event);
      }
    }
  }
}

function getResponseStatus(res) {
  return Number(res.statusCode || res._status || 200);
}

function getHeader(headers, name) {
  if (!headers) return undefined;
  const lower = name.toLowerCase();
  return headers[lower] || headers[name] || headers[Object.keys(headers).find((key) => key.toLowerCase() === lower)];
}

module.exports = {
  createBruteForceContext,
  attachParryRequestApi,
  checkBruteForceBlock,
  observeAuthenticationResult,
  finalizeAuthenticationResult,
  createBruteForceEvent,
};
