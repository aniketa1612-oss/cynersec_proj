import pytest
from app.scanners import ScannerError, _find_executable, enforce_network_policy, parse_nmap_xml, parse_nuclei_record, parse_zap_alert

def test_nmap_xml_normalization():
    xml = """<?xml version="1.0"?><nmaprun><host><address addr="192.168.56.10"/>
    <hostnames><hostname name="lab.local"/></hostnames><ports><port protocol="tcp" portid="443">
    <state state="open"/><service name="https" product="nginx" version="1.24"/></port></ports></host></nmaprun>"""
    rows = parse_nmap_xml(xml)
    assert rows == [{"ip":"192.168.56.10","hostname":"lab.local","port":443,"protocol":"tcp",
                     "service":"https","version":"nginx 1.24","os":"Unknown"}]

def test_nuclei_json_normalization():
    finding = parse_nuclei_record({"template-id":"cve-test","matched-at":"https://lab.local/a",
      "info":{"name":"Test finding","severity":"high","description":"description",
      "classification":{"cve-id":["CVE-2025-0001"],"cwe-id":["CWE-79"],"cvss-score":8.1},
      "reference":["https://example.test/reference"]}})
    assert finding.source == "nuclei"
    assert finding.cve_id == "CVE-2025-0001"
    assert finding.cvss == 8.1

def test_zap_alert_normalization():
    finding = parse_zap_alert({"url":"https://lab.local/login","risk":"Medium","alert":"Missing header",
                               "cweid":"693","evidence":"header absent"})
    assert finding.source == "zap"
    assert finding.port == 443
    assert finding.cwe_id == "CWE-693"

def test_public_target_blocked_by_default(monkeypatch):
    monkeypatch.setenv("ALLOW_PUBLIC_TARGETS", "false")
    with pytest.raises(ScannerError):
        enforce_network_policy("8.8.8.8")
    enforce_network_policy("192.168.56.10")

def test_windows_scanner_fallbacks_are_installed():
    assert _find_executable("nmap")
    assert _find_executable("nuclei")
