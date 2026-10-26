import json, os, sys
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen
year = int(sys.argv[1]) if len(sys.argv) > 1 else 2025
params = urlencode({"pubStartDate": f"{year}-01-01T00:00:00.000", "pubEndDate": f"{year}-12-31T23:59:59.999", "resultsPerPage": 2000})
req = Request(os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0") + "?" + params,
              headers={"apiKey": os.getenv("NVD_API_KEY", "")})
out = Path(f"data/nvd/nvd-{year}.json")
out.parent.mkdir(parents=True, exist_ok=True)
with urlopen(req, timeout=120) as r:
    data = json.load(r)
out.write_text(json.dumps(data), encoding="utf-8")
print(f"Saved {len(data.get('vulnerabilities', []))} NVD records to {out}; paginate for a complete year.")

