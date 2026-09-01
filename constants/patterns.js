'use strict';

const SQL_PATTERNS = [
  /\b(union)\b.{0,30}\b(select)\b/i,
  /\b(or|and)\b\s+[\w'"]{1,20}\s*=\s*[\w'"]{1,20}/i,
  /(['"`]\s*(--|#|\/\*)|(--|#|\/\*)\s*$)/,
  /;\s*(drop|alter|truncate|delete|insert|update|create|exec|execute)\b/i,
  /\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i,
  /\b(select|insert|update|delete|drop|alter)\b.{0,80}\b(from|into|table|where)\b/i,
  /'?\s*\bor\b\s+'?1'?\s*=\s*'?1/i,
  /'?\s*\band\b\s+'?1'?\s*=\s*'?1/i,
  /information_schema|sys\.tables|sysobjects|pg_catalog/i,
  /\bchar\s*\(\s*\d+/i,
  /0x[0-9a-f]{2,}/i,
  /\b(load_file|into\s+outfile|into\s+dumpfile)\b/i,
  /\b(exec\s*\(|xp_cmdshell|sp_executesql)\b/i,
];

const XSS_PATTERNS = [
  /<\s*script\b[^>]{0,500}>/i,
  /\bon\w+\s*=\s*["']?[^"'>]*/i,
  /javascript\s*:/i,
  /vbscript\s*:/i,
  /data\s*:\s*[^,]*script/i,
  /<\s*(img|iframe|object|embed|svg|video|audio|source|track|input)\b[^>]*\s(src|data|href)\s*=\s*["']?\s*javascript/i,
  /<\s*svg\b[^>]*>[\s\S]*?(script|onload|onerror)/i,
  /expression\s*\(/i,
  /url\s*\(\s*["']?\s*javascript/i,
  /\{\{[^{}]{0,200}(?:constructor(?:\.constructor)?|alert\s*\(|document\.|window\.)[^{}]{0,200}\}\}/i,
  /\$\{[^{}]{0,200}(?:constructor(?:\.constructor)?|alert\s*\(|document\.|window\.)[^{}]{0,200}\}/i,
  /<\s*(base|link|meta|style)\b[^>]*(http-equiv|href|content)\s*=\s*["']?[^"'>]*script/i,
  /\0|%00/,
  /autofocus.{0,30}onfocus/i,
];

const NOSQL_DANGEROUS_OPERATORS = new Set(['$where', '$expr', '$function', '$accumulator']);

const NOSQL_SUSPICIOUS_OPERATORS = new Set([
  '$gt',
  '$gte',
  '$lt',
  '$lte',
  '$ne',
  '$in',
  '$nin',
  '$or',
  '$and',
  '$not',
  '$nor',
  '$exists',
  '$type',
  '$regex',
  '$options',
  '$elemMatch',
  '$size',
  '$slice',
  '$meta',
]);

const NOSQL_STRING_PATTERNS = [
  /"\$\w+"?\s*:/,
  /\$where\s*[:=]\s*["'`]?(function|this\.|sleep|db\.)/i,
  /\b(mapReduce|runCommand|eval)\s*\(/i,
  /db\.(getCollection|find|update|insert|remove|drop)\s*\(/i,
];

const SENSITIVE_HEADERS = ['user-agent', 'referer', 'x-forwarded-for', 'cookie'];

module.exports = {
  SQL_PATTERNS,
  XSS_PATTERNS,
  NOSQL_DANGEROUS_OPERATORS,
  NOSQL_SUSPICIOUS_OPERATORS,
  NOSQL_STRING_PATTERNS,
  SENSITIVE_HEADERS,
};
