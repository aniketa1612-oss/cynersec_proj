"""Authoritative NVD and CISA KEV lookups with bounded local caching."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx

CACHE_DIR = Path("data/cache")
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _fresh(path: Path, max_age: int = 86400) -> bool:
    return path.exists() and time.time() - path.stat().st_mtime < max_age


def nvd_lookup(cve_id: str) -> dict:
    path = CACHE_DIR / f"{cve_id}.json"
    if _fresh(path):
        return json.loads(path.read_text(encoding="utf-8"))
    headers = {}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    response = httpx.get(
        os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        params={"cveId": cve_id}, headers=headers, timeout=20,
    )
    response.raise_for_status()
    payload = response.json()
    records = payload.get("vulnerabilities", [])
    result = records[0].get("cve", {}) if records else {}
    path.write_text(json.dumps(result), encoding="utf-8")
    return result


def kev_catalog() -> dict[str, dict]:
    path = CACHE_DIR / "cisa-kev.json"
    if not _fresh(path):
        response = httpx.get(os.getenv(
            "KEV_URL",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ), timeout=30)
        response.raise_for_status()
        path.write_text(response.text, encoding="utf-8")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {row["cveID"]: row for row in payload.get("vulnerabilities", [])}


def enrich_cve(cve_id: str | None) -> dict:
    if not cve_id:
        return {"nvd": {}, "kev": None}
    nvd, kev = {}, None
    try:
        nvd = nvd_lookup(cve_id)
    except (httpx.HTTPError, OSError, ValueError, json.JSONDecodeError):
        pass
    try:
        kev = kev_catalog().get(cve_id)
    except (httpx.HTTPError, OSError, ValueError, json.JSONDecodeError):
        pass
    return {"nvd": nvd, "kev": kev}


def nvd_fields(cve: dict) -> dict:
    metrics = cve.get("metrics", {})
    metric = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
    data = metric.get("cvssData", {})
    descriptions = cve.get("descriptions") or []
    description = next((x.get("value", "") for x in descriptions if x.get("lang") == "en"), "")
    weaknesses = cve.get("weaknesses") or []
    cwe = None
    if weaknesses:
        choices = weaknesses[0].get("description") or []
        cwe = next((x.get("value") for x in choices if x.get("lang") == "en"), None)
    return {
        "description": description,
        "cvss": float(data.get("baseScore", 0) or 0),
        "attack_vector": data.get("attackVector", "UNKNOWN"),
        "attack_complexity": data.get("attackComplexity", "UNKNOWN"),
        "privileges_required": data.get("privilegesRequired", "UNKNOWN"),
        "user_interaction": data.get("userInteraction", "UNKNOWN"),
        "confidentiality_impact": data.get("confidentialityImpact", "UNKNOWN"),
        "integrity_impact": data.get("integrityImpact", "UNKNOWN"),
        "availability_impact": data.get("availabilityImpact", "UNKNOWN"),
        "cwe": cwe,
        "exploitability_score": float(metric.get("exploitabilityScore", 0) or 0),
        "published": cve.get("published"),
    }
