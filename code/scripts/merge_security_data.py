import json
from pathlib import Path
import pandas as pd
nvd = pd.read_csv("data/processed/nvd.csv")
kev_path = Path("data/kev/known_exploited_vulnerabilities.json")
kev = {x["cveID"]: x for x in json.loads(kev_path.read_text()).get("vulnerabilities", [])} if kev_path.exists() else {}
nvd["known_exploited"] = nvd.cve_id.isin(kev).astype(int)
nvd["asset_exposure"] = 5
nvd["service_exposure"] = 5
nvd["port"] = 443
nvd["exploitability_score"] = nvd.cvss_score * .8
nvd["vulnerability_age"] = ((pd.Timestamp.now(tz="UTC") - pd.to_datetime(nvd.published, utc=True, errors="coerce")).dt.days.fillna(0)).clip(lower=0)
def label(r):
    score = min(100, r.cvss_score*6.5 + r.known_exploited*25 + r.asset_exposure + r.service_exposure*.5)
    return "Critical" if score >= 76 else "High" if score >= 51 else "Medium" if score >= 26 else "Low"
nvd["risk_priority"] = nvd.apply(label, axis=1)
out = "data/processed/security_dataset.csv"
nvd.to_csv(out, index=False)
print(f"Merged {len(nvd)} rows to {out}")

