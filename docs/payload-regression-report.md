# Payload Regression Coverage Report

Generated at: 2026-08-31T18:13:22.865Z

This report summarizes curated defensive regression fixtures. Payloads are not executed, are not sent to external hosts, and are not imported by runtime middleware code.

## Totals

- Total fixtures: 217
- Malicious or abuse scenario fixtures: 142
- Expected blocking fixtures: 138
- Benign false-positive controls: 75
- monitorOnly fixtures: 0
- strictOnly fixtures: 0

## Fixtures by Category

| Category            | Fixtures | Expected blocked | monitorOnly | strictOnly |
| ------------------- | -------: | ---------------: | ----------: | ---------: |
| sql                 |       28 |               28 |           0 |          0 |
| xss                 |       28 |               28 |           0 |          0 |
| nosql               |       20 |               20 |           0 |          0 |
| hpp                 |       12 |               12 |           0 |          0 |
| prototype-pollution |       12 |               12 |           0 |          0 |
| path-traversal      |       20 |               20 |           0 |          0 |
| request-shape       |       12 |               12 |           0 |          0 |
| brute-force         |       10 |                6 |           0 |          0 |
| benign              |       75 |                0 |           0 |          0 |

## Detector Coverage

- Implemented detector categories: brute-force, hpp, nosql, path-traversal, prototype-pollution, request-shape, sql, xss
- Fixtures cover only detectors implemented by this version.

## Defensive Use Notice

These fixtures are small, local, curated regression examples inspired by known web security payload categories. PayloadsAllTheThings is used only as read-only reference when available locally. Do not execute these payloads against third-party systems, do not use them as a scanner, and do not treat this suite as proof of complete protection.
