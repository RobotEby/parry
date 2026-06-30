'use strict';

const { getClientIp } = require('../../../express/ip-resolver');
const { readHeader } = require('../utils/header-utils');
const { safeCompare } = require('../utils/constant-time');
const { success, unauthorized, forbidden } = require('../utils/result');

function authenticateToken(req, config) {
  const headerName = config.header || 'x-parry-admin-token';
  const supplied = readHeader(req, headerName);
  if (!supplied) return unauthorized();
  if (!safeCompare(String(config.token), String(supplied))) return forbidden();

  return success(
    req,
    'token',
    {
      subject: 'local-token',
      ip: getClientIp(req, config),
    },
    config
  );
}

module.exports = { authenticateToken };
