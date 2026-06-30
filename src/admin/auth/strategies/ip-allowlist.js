'use strict';

const { getClientIp, isIpAllowed } = require('../../../express/ip-resolver');
const { success, forbidden } = require('../utils/result');

function authenticateIpAllowlist(req, config) {
  const ip = getClientIp(req, config);
  if (!isIpAllowed(ip, config.allowedIps)) return forbidden();

  return success(req, 'ip-allowlist', { subject: `ip:${ip}`, ip }, config);
}

module.exports = { authenticateIpAllowlist };
