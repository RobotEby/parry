'use strict';

const THREAT_SEVERITY = {
  SQL_INJECTION: 'high',
  XSS: 'high',
  NOSQL_INJECTION: 'high',
  HTTP_PARAMETER_POLLUTION: 'medium',
  PROTOTYPE_POLLUTION: 'high',
  PATH_TRAVERSAL: 'high',
  REQUEST_SHAPE: 'medium',
};

function severityForThreats(threats) {
  if (!threats || threats.length === 0) return 'none';
  return THREAT_SEVERITY[threats[0].detector] || 'medium';
}

module.exports = { severityForThreats };
