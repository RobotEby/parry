'use strict';

const fs = require('fs');
const path = require('path');
const {
  IMPLEMENTED_DETECTORS,
  OPTIONAL_DETECTORS,
  ROOT_DIR,
  getExpectedCounts,
  loadFixtures,
  validateFixtures,
} = require('./fixture-utils');

const REPORT_PATH = path.join(ROOT_DIR, 'docs', 'payload-regression-report.md');

function generateReport() {
  const validation = validateFixtures();
  if (!validation.ok) {
    throw new Error(`Cannot generate report with invalid fixtures:\n${validation.errors.join('\n')}`);
  }

  const { all, byCategory } = loadFixtures();
  const expectedCounts = getExpectedCounts();
  const categories = Object.keys(expectedCounts);
  const malicious = all.filter((fixture) => fixture.category !== 'benign');
  const blocked = all.filter((fixture) => fixture.expected.blocked);
  const benign = byCategory.benign || [];
  const monitorOnly = all.filter((fixture) => fixture.monitorOnly || fixture.expected.mode === 'monitor');
  const strictOnly = all.filter((fixture) => fixture.strictOnly || fixture.expected.mode === 'strict');
  const absentDetectors = [...OPTIONAL_DETECTORS].filter(
    (detector) => (byCategory[detector] || []).length > 0 && !IMPLEMENTED_DETECTORS.has(detector)
  );

  const lines = [
    '# Payload Regression Coverage Report',
    '',
    `Generated at: ${new Date().toISOString()}`,
    '',
    'This report summarizes curated defensive regression fixtures. Payloads are not executed, are not sent to external hosts, and are not imported by runtime middleware code.',
    '',
    '## Totals',
    '',
    `- Total fixtures: ${all.length}`,
    `- Malicious or abuse scenario fixtures: ${malicious.length}`,
    `- Expected blocking fixtures: ${blocked.length}`,
    `- Benign false-positive controls: ${benign.length}`,
    `- monitorOnly fixtures: ${monitorOnly.length}`,
    `- strictOnly fixtures: ${strictOnly.length}`,
    '',
    '## Fixtures by Category',
    '',
    '| Category | Fixtures | Expected blocked | monitorOnly | strictOnly |',
    '| --- | ---: | ---: | ---: | ---: |',
  ];

  for (const category of categories) {
    const fixtures = byCategory[category] || [];
    lines.push(
      `| ${category} | ${fixtures.length} | ${fixtures.filter((fixture) => fixture.expected.blocked).length} | ${fixtures.filter((fixture) => fixture.monitorOnly || fixture.expected.mode === 'monitor').length} | ${fixtures.filter((fixture) => fixture.strictOnly || fixture.expected.mode === 'strict').length} |`
    );
  }

  lines.push(
    '',
    '## Detector Coverage',
    '',
    `- Implemented detector categories: ${[...IMPLEMENTED_DETECTORS].sort().join(', ')}`,
    `- Optional categories without detectors in this version: ${absentDetectors.length ? absentDetectors.sort().join(', ') : 'none'}`,
    '',
    '## Defensive Use Notice',
    '',
    'These fixtures are small, local, curated regression examples inspired by known web security payload categories. PayloadsAllTheThings is used only as read-only reference when available locally. Do not execute these payloads against third-party systems, do not use them as a scanner, and do not treat this suite as proof of complete protection.',
    ''
  );

  fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  fs.writeFileSync(REPORT_PATH, `${lines.join('\n')}\n`);
  return { reportPath: REPORT_PATH, total: all.length };
}

function main() {
  try {
    const result = generateReport();
    console.log(`Payload regression report generated: ${path.relative(ROOT_DIR, result.reportPath)} (${result.total} fixtures).`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { generateReport };
