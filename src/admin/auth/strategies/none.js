'use strict';

const { getClientIp } = require('../../../express/ip-resolver');
const { success } = require('../utils/result');

let warned = false;

function authenticateNone(req, config) {
  if (!warned) {
    warned = true;
    console.warn(
      '[parry] Admin API auth mode "none" is insecure and intended only for local development.'
    );
  }

  const ip = getClientIp(req, config);
  return success(req, 'none', { subject: 'insecure-none', ip }, config);
}

module.exports = { authenticateNone };
