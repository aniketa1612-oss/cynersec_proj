"""Controlled scanner adapters for explicitly authorized assessment targets."""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx


class ScannerError(RuntimeError):
    """A scanner failed safely without exposing implementation internals."""


@dataclass
class NormalizedFinding:
    source: str
    host: str
    port: int
    protocol: str
    service: str
    product: str
    version: str
    title: str
    description: str
    cve_id: str | None
    cwe_id: str | None
    severity: str
    cvss: float
    evidence: str
    reference: str


def canonical_target(host: str, target_type: str) -> str:
    """Return a shell-safe host/URL after rejecting option and credential injection."""
    value = host.strip()
    if not value or value.startswith("-") or any(c in value for c in "\r\n\0"):
        raise ScannerError("Invalid target value")
    if target_type == "URL":
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ScannerError("URL must be HTTP(S) and must not contain credentials")
        return value
    if "://" in value or "/" in value and target_type != "NETWORK":
        raise ScannerError("Target type does not match host value")
    return value


def target_host(value: str) -> str:
    parsed = urlparse(value)
    return parsed.hostname or value.split("/")[0]


def enforce_network_policy(value: str) -> None:
    """Block public IP literals by default; public domains require an explicit opt-in."""
    hostname = target_host(value)
    allow_public = os.getenv("ALLOW_PUBLIC_TARGETS", "false").lower() == "true"
    try:
        network = ipaddress.ip_network(hostname, strict=False)
    except ValueError:
        if not allow_public and hostname not in {"localhost"} and not hostname.endswith((".local", ".test")):
            raise ScannerError("Public/domain targets are disabled; use an isolated lab or set ALLOW_PUBLIC_TARGETS=true")
        return
    if not allow_public and not (network.is_private or network.is_loopback or network.is_link_local):
        raise ScannerError("Public IP targets are disabled by policy")


def _find_executable(name: str) -> str | None:
    """Resolve scanners even when an open Windows IDE has a stale PATH."""
    resolved = shutil.which(name)
    if resolved:
        return resolved
    if os.name != "nt":
        return None
    candidates = {
        "nmap": [
            Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Nmap/nmap.exe",
            Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Nmap/nmap.exe",
        ],
        "nuclei": [Path.home() / "Tools/nuclei/nuclei.exe", Path.home() / "go/bin/nuclei.exe"],
    }
    return next((str(path) for path in candidates.get(name, []) if path.is_file()), None)


def scanner_status() -> dict[str, bool]:
    return {
        "nmap": bool(_find_executable("nmap")),
        "nuclei": bool(_find_executable("nuclei")),
        "zap": _zap_available(),
    }


def _zap_available() -> bool:
    try:
        response = httpx.get(
            os.getenv("ZAP_URL", "http://127.0.0.1:8080").rstrip("/") + "/JSON/core/view/version/",
            params={"apikey": os.getenv("ZAP_API_KEY", "")}, timeout=2,
        )
        return response.is_success
    except httpx.HTTPError:
        return False


def run_nmap(host: str, target_type: str, timeout: int = 180) -> list[dict]:
    target = canonical_target(host, target_type)
    enforce_network_policy(target)
    executable = _find_executable("nmap")
    if not executable:
        raise ScannerError("Nmap is not installed or not on PATH")
    # Fixed allowlist only: service/version discovery and XML to stdout.
    command = [executable, "-sV", "--version-light", "-T3", "-oX", "-", target_host(target)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ScannerError("Nmap scan timed out") from exc
    if result.returncode:
        raise ScannerError(f"Nmap failed with exit code {result.returncode}")
    return parse_nmap_xml(result.stdout)


def parse_nmap_xml(xml_text: str) -> list[dict]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScannerError("Nmap returned malformed XML") from exc
    assets = []
    for node in root.findall("host"):
        address = node.find("address")
        ip = address.get("addr", "") if address is not None else ""
        hostname_node = node.find("./hostnames/hostname")
        hostname = hostname_node.get("name", "") if hostname_node is not None else ""
        os_node = node.find("./os/osmatch")
        os_name = os_node.get("name", "Unknown") if os_node is not None else "Unknown"
        for port in node.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            extra = service.get("extrainfo", "") if service is not None else ""
            assets.append({
                "ip": ip, "hostname": hostname, "port": int(port.get("portid", "0")),
                "protocol": port.get("protocol", "tcp"),
                "service": service.get("name", "unknown") if service is not None else "unknown",
                "version": " ".join(x for x in (product, version, extra) if x).strip() or "Unknown",
                "os": os_name,
            })
    return assets


def run_nuclei(host: str, target_type: str, timeout: int = 300) -> list[NormalizedFinding]:
    target = canonical_target(host, target_type)
    enforce_network_policy(target)
    executable = _find_executable("nuclei")
    if not executable:
        raise ScannerError("Nuclei is not installed or not on PATH")
    # Users cannot choose templates. Only the predefined non-destructive categories run.
    command = [
        executable, "-u", target, "-jsonl", "-silent", "-no-interactsh",
        "-disable-update-check", "-tags", os.getenv("NUCLEI_TAGS", "misconfig,exposure"),
        "-severity", "low,medium,high,critical", "-timeout", os.getenv("NUCLEI_REQUEST_TIMEOUT", "5"),
        "-retries", os.getenv("NUCLEI_RETRIES", "1"),
        "-rate-limit", os.getenv("NUCLEI_RATE_LIMIT", "20"),
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ScannerError("Nuclei scan timed out") from exc
    if result.returncode not in {0, 1}:
        raise ScannerError(f"Nuclei failed with exit code {result.returncode}")
    findings = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            findings.append(parse_nuclei_record(json.loads(line)))
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    return findings


def parse_nuclei_record(item: dict) -> NormalizedFinding:
    info = item.get("info") or {}
    classification = info.get("classification") or {}
    classification = classification if isinstance(classification, dict) else {}
    cves = classification.get("cve-id") or classification.get("cve_id") or []
    cwes = classification.get("cwe-id") or classification.get("cwe_id") or []
    if isinstance(cves, str): cves = [cves]
    if isinstance(cwes, str): cwes = [cwes]
    parsed = urlparse(item.get("matched-at") or item.get("host") or "")
    refs = info.get("reference") or []
    if isinstance(refs, str): refs = [refs]
    return NormalizedFinding(
        source="nuclei", host=parsed.hostname or item.get("host", ""),
        port=parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else 0),
        protocol="tcp", service=parsed.scheme or "unknown", product="", version="",
        title=info.get("name") or item.get("template-id") or "Nuclei finding",
        description=info.get("description") or "No scanner description provided.",
        cve_id=cves[0] if cves else None, cwe_id=cwes[0] if cwes else None,
        severity=str(info.get("severity") or "info").lower(),
        cvss=float(classification.get("cvss-score") or classification.get("cvss_score") or 0),
        evidence=f"Template {item.get('template-id','unknown')} matched at {item.get('matched-at',item.get('host','unknown'))}",
        reference=str(refs[0]) if refs else "",
    )


def run_zap_passive(url: str, target_type: str, timeout: int = 300) -> list[NormalizedFinding]:
    target = canonical_target(url, target_type)
    enforce_network_policy(target)
    if target_type != "URL":
        raise ScannerError("ZAP web scan requires a URL target")
    base = os.getenv("ZAP_URL", "http://127.0.0.1:8080").rstrip("/")
    key = os.getenv("ZAP_API_KEY", "")
    client = httpx.Client(timeout=15)
    try:
        response = client.get(base + "/JSON/spider/action/scan/", params={
            "apikey": key, "url": target, "recurse": "true", "subtreeOnly": "true",
            "maxChildren": os.getenv("ZAP_MAX_CHILDREN", "50"),
        })
        response.raise_for_status()
        scan_id = response.json().get("scan")
        if scan_id is None:
            raise ScannerError("ZAP did not return a spider scan ID")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = client.get(base + "/JSON/spider/view/status/", params={"apikey": key, "scanId": scan_id}).json()
            if int(status.get("status", 0)) >= 100:
                break
            time.sleep(1)
        else:
            client.get(base + "/JSON/spider/action/stop/", params={"apikey": key, "scanId": scan_id})
            raise ScannerError("ZAP spider timed out")
        while time.monotonic() < deadline:
            queued = client.get(base + "/JSON/pscan/view/recordsToScan/", params={"apikey": key}).json()
            if int(queued.get("recordsToScan", 0)) == 0:
                break
            time.sleep(1)
        alerts = client.get(base + "/JSON/core/view/alerts/", params={
            "apikey": key, "baseurl": target, "start": 0, "count": 500,
        })
        alerts.raise_for_status()
        return [parse_zap_alert(x) for x in alerts.json().get("alerts", [])]
    except httpx.HTTPError as exc:
        raise ScannerError("ZAP API is unavailable or returned an error") from exc
    finally:
        client.close()


def parse_zap_alert(item: dict) -> NormalizedFinding:
    parsed = urlparse(item.get("url", ""))
    risk = str(item.get("risk", "Informational")).lower()
    severity = {"informational": "info"}.get(risk, risk)
    cwe = str(item.get("cweid", "0"))
    return NormalizedFinding(
        source="zap", host=parsed.hostname or "", port=parsed.port or (443 if parsed.scheme == "https" else 80),
        protocol="tcp", service=parsed.scheme or "http", product="", version="",
        title=item.get("alert") or "ZAP finding", description=item.get("description") or "",
        cve_id=None, cwe_id=f"CWE-{cwe}" if cwe not in {"", "0"} else None,
        severity=severity, cvss=0, evidence=(item.get("evidence") or item.get("param") or "")[:2000],
        reference=item.get("reference") or item.get("solution") or "",
    )
