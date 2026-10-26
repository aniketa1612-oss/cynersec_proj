import json
from pathlib import Path
import pandas as pd
rows = []
for path in Path("data/nvd").glob("*.json"):
    for item in json.loads(path.read_text(encoding="utf-8")).get("vulnerabilities", []):
        c = item["cve"]
        metrics = c.get("metrics", {})
        metric = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0].get("cvssData", {})
        desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
        weak = (c.get("weaknesses") or [{}])[0].get("description", [{}])[0].get("value", "UNKNOWN")
        rows.append({"cve_id": c["id"], "description": desc, "published": c.get("published"),
          "modified": c.get("lastModified"), "cvss_score": metric.get("baseScore", 0),
          "attack_vector": metric.get("attackVector", "UNKNOWN"), "attack_complexity": metric.get("attackComplexity", "UNKNOWN"),
          "privileges_required": metric.get("privilegesRequired", "UNKNOWN"), "user_interaction": metric.get("userInteraction", "UNKNOWN"),
          "confidentiality_impact": metric.get("confidentialityImpact", "UNKNOWN"), "integrity_impact": metric.get("integrityImpact", "UNKNOWN"),
          "availability_impact": metric.get("availabilityImpact", "UNKNOWN"), "cwe": weak})
out = Path("data/processed/nvd.csv")
out.parent.mkdir(parents=True, exist_ok=True)
pd.DataFrame(rows).to_csv(out, index=False)
print(f"Processed {len(rows)} records to {out}")

