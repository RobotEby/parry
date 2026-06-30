# Payload Regression Coverage Report

Generated at: 2026-06-29T00:33:27.967Z

This report summarizes curated defensive regression fixtures. Payloads are not executed, are not sent to external hosts, and are not imported by runtime middleware code.

## Totals

- Total fixtures: 211
- Malicious or abuse scenario fixtures: 166
- Expected blocking fixtures: 138
- Benign false-positive controls: 45
- monitorOnly fixtures: 24
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
| command-injection   |       12 |                0 |          12 |          0 |
| ssrf                |       12 |                0 |          12 |          0 |
| request-shape       |       12 |               12 |           0 |          0 |
| brute-force         |       10 |                6 |           0 |          0 |
| benign              |       45 |                0 |           0 |          0 |

## Detector Coverage

- Implemented detector categories: brute-force, hpp, nosql, path-traversal, prototype-pollution, request-shape, sql, xss
- Optional categories without detectors in this version: command-injection, ssrf

## Defensive Use Notice

These fixtures are small, local, curated regression examples inspired by known web security payload categories. PayloadsAllTheThings is used only as read-only reference when available locally. Do not execute these payloads against third-party systems, do not use them as a scanner, and do not treat this suite as proof of complete protection.
