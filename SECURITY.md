# Security Policy

## Supported versions

Security fixes are targeted at the current stable 1.x release. At present that
is `1.1.1`. The `1.1.0-rc.1` release candidate and older versions are not
separate supported branches.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private
vulnerability reporting if the repository has it enabled. If that option is not
visible, email `ubuntu.onion@hotmail.com` with the subject `Parry security report`.

Include the affected version, impact, minimal reproduction, relevant
configuration, and any suggested mitigation. Do not include real credentials,
personal data, or traffic from systems you do not own or have permission to test.

You should receive an acknowledgement within seven days. Timelines for triage,
fixes, and disclosure depend on severity and reproducibility. Please allow a
reasonable remediation window before public disclosure.

## Scope notes

Reports about detector bypasses or false negatives should explain the downstream
security impact. Parry's SQLi and XSS checks are documented heuristics and do not
replace parameterized queries or output encoding. False positives that do not
expose confidential data can use the dedicated public issue form.
