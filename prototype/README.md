# AI-Based Adaptive Penetration Testing Assistant

This prototype imports real evidence exported by security tools and applies a deterministic, explainable priority formula. It generates no random vulnerability values and does not launch scans or exploits.

The Python file contains no fixed findings and no embedded scoring policy. Findings come from the input export, while weights, thresholds, mappings, import defaults, and recommendations come from `scoring_config.json`.

## Review demo

```powershell
uv run --offline python adaptive_pentest_assistant.py sample_findings.json --report outcome_report.html --output-json ranked_findings.json
```

Open `outcome_report.html`. The included JSON is reproducible demonstration evidence, not a live scan.

## Import an authorized scanner export

```powershell
uv run --offline python adaptive_pentest_assistant.py nuclei-results.jsonl --format nuclei --authorized
uv run --offline python adaptive_pentest_assistant.py zap-report.json --format zap --authorized
uv run --offline python adaptive_pentest_assistant.py nmap-results.xml --format nmap --authorized
```

Nuclei CVSS is read from `classification.cvss-score`; if absent, scanner severity is mapped to a documented representative score. ZAP risk labels are similarly mapped because its JSON normally lacks CVSS. Nmap reports services, not vulnerabilities, so these start at CVSS 0 pending analyst correlation. All fallbacks are deterministic.

`asset_value` and `internet_exposed` are business context and cannot be truthfully inferred from scanner output. Imports use neutral defaults (`5` and `false`) until analyst enrichment.

To change the policy, edit `scoring_config.json` or supply another file with `--config company_policy.json`. The program does not silently invent missing fields in normalized JSON: `cvss`, `asset_value`, and `confidence` are required.

Score: `0.55 × CVSS + 0.20 × asset value + 0.10 × confidence + 1.0 known exploit + 0.8 internet exposed`, capped at 10.

Scanner imports require `--authorized`; normalized JSON requires `authorized_assessment: true`. See `IMPLEMENTATION_STATUS.md`.
