from app.trivy import parse_trivy_report


def test_trivy_report_normalization():
    report = {"Results":[{"Target":"demo-image","Vulnerabilities":[{
        "VulnerabilityID":"CVE-2025-0001","PkgName":"demo-lib","InstalledVersion":"1.0",
        "FixedVersion":"1.1","Severity":"HIGH","Title":"Demo dependency issue",
        "Description":"Synthetic fixture","PrimaryURL":"https://example.test/CVE-2025-0001",
        "CVSS":{"nvd":{"V3Score":8.1}}
    }]}]}
    finding = parse_trivy_report(report)[0]
    assert finding.source == "Trivy"
    assert finding.cve_id == "CVE-2025-0001"
    assert finding.cvss == 8.1
    assert finding.service == "software-supply-chain"
