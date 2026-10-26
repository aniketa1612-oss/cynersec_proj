from __future__ import annotations

from app.scanners import NormalizedFinding


def parse_trivy_report(report: dict) -> list[NormalizedFinding]:
    """Normalize Trivy vulnerability JSON without executing or exploiting anything."""
    findings: list[NormalizedFinding] = []
    for result in report.get("Results", []):
        target = str(result.get("Target", "software artifact"))
        for item in result.get("Vulnerabilities") or []:
            severity = str(item.get("Severity", "UNKNOWN")).lower()
            cvss_sources = item.get("CVSS") or {}
            scores = [float(x.get("V3Score", 0) or x.get("V2Score", 0) or 0) for x in cvss_sources.values()]
            findings.append(NormalizedFinding(
                host=target, port=0, protocol="local", service="software-supply-chain",
                product=str(item.get("PkgName", "unknown-package")),
                version=str(item.get("InstalledVersion", "unknown")),
                cve_id=item.get("VulnerabilityID"),
                title=str(item.get("Title") or item.get("VulnerabilityID") or "Dependency vulnerability"),
                description=str(item.get("Description") or "Trivy dependency finding"),
                severity=severity if severity in {"low","medium","high","critical"} else "low",
                cvss=max(scores, default=0.0), cwe_id=None,
                evidence=f"Package {item.get('PkgName','unknown')} {item.get('InstalledVersion','unknown')}; fixed version {item.get('FixedVersion') or 'not published'}",
                source="Trivy", reference=str(item.get("PrimaryURL") or ""),
            ))
    return findings
