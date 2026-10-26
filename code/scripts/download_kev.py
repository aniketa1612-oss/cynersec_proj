import json, os
from pathlib import Path
from urllib.request import urlopen
url = os.getenv("KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
out = Path("data/kev/known_exploited_vulnerabilities.json")
out.parent.mkdir(parents=True, exist_ok=True)
with urlopen(url, timeout=60) as r:
    data = json.load(r)
out.write_text(json.dumps(data, indent=2), encoding="utf-8")
print(f"Saved {len(data.get('vulnerabilities', []))} KEV records to {out}")

