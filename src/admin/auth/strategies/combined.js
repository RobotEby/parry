'use strict';

const { success } = require('../utils/result');

async function authenticateCombined(req, config, context) {
  const allowAny = Array.isArray(config.allowAny) ? config.allowAny : null;
  const requireAll = Array.isArray(config.requireAll) ? config.requireAll : null;

  if (allowAny) return authenticateAny(req, allowAny, context);
  return authenticateAll(req, requireAll || [], context);
}

async function authenticateAny(req, strategies, context) {
  let sawForbidden = false;
  const { authenticateAdminRequest } = require('../admin-auth');

  for (const strategyConfig of strategies) {
    const result = await authenticateAdminRequest(req, strategyConfig, context);
    if (result.ok) {
      return success(req, 'combined', {
        ...result.admin,
        strategy: 'combined',
        subject: result.admin.subject,
      });
    }
    if (result.statusCode === 403) sawForbidden = true;
  }

  return sawForbidden ? { ok: false, statusCode: 403 } : { ok: false, statusCode: 401 };
}

async function authenticateAll(req, strategies, context) {
  const { authenticateAdminRequest } = require('../admin-auth');
  let lastAdmin = null;

  for (const strategyConfig of strategies) {
    const result = await authenticateAdminRequest(req, strategyConfig, context);
    if (!result.ok) return result;
    lastAdmin = result.admin;
  }

  return success(req, 'combined', {
    ...lastAdmin,
    strategy: 'combined',
    subject: lastAdmin?.subject || 'combined',
    roles: lastAdmin?.roles || [],
  });
}

module.exports = { authenticateCombined };
