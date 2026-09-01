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
  const rank = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return threats.reduce((highest, threat) => {
    const severity = threat.severity || THREAT_SEVERITY[threat.detector] || 'medium';
    return rank[severity] > rank[highest] ? severity : highest;
  }, 'none');
}

module.exports = { severityForThreats };
