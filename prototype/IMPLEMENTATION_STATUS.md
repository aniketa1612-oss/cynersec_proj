# Implementation Status

## Implemented

- Authorization gate for all inputs.
- Normalized JSON, Nuclei JSONL, OWASP ZAP JSON, and Nmap XML import.
- Deterministic values with strict 0–10 validation; no random generation.
- External `scoring_config.json`; weights, thresholds, mappings, defaults, and recommendations are not embedded in Python.
- Explainable scoring, priority labels, console output, HTML report, and optional JSON results.
- Evidence source and observation timestamp when supplied by the scanner.
- Safe next-step recommendations requiring analyst verification.

## Not implemented

- Direct scanner execution, exploitation, payloads, credential attacks, or system modification.
- A trained ML model; the present AI component is an explainable rules-based baseline.
- Online CVE/CVSS/KEV enrichment.
- Web dashboard/API, accounts, database, job queue, audit log, or RBAC.
- Automatic asset criticality/exposure discovery or feedback-based learning.

## Review statement

“The prototype completes evidence ingestion, validation, explainable prioritization, and reporting. It accepts real scanner exports but deliberately does not initiate scans or attacks. The next phase is an authenticated web interface, controlled orchestration for authorized lab targets, CVE/KEV enrichment, and evaluation of a trained ranking model.”
