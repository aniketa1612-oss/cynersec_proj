from datetime import datetime, timedelta, timezone

def test_health(client):
    assert client.get("/health").json()["status"] == "ok"

def test_auth_and_authorization_gate(client, admin):
    r = client.post("/targets", headers=admin, json={"name":"lab","host":"192.168.56.20","target_type":"IP","description":"lab"})
    assert r.status_code == 200
    tid = r.json()["id"]
    r = client.post("/scans", headers=admin, json={"target_id":tid,"scan_type":"vulnerability_scan","tool":"mock","mode":"mock"})
    assert r.status_code == 403
    now = datetime.now(timezone.utc)
    r = client.post(f"/targets/{tid}/authorize", headers=admin, json={"authorization_reference":"TEST-AUTH","authorization_start":(now-timedelta(hours=1)).isoformat(),"authorization_end":(now+timedelta(hours=1)).isoformat()})
    assert r.status_code == 200
    r = client.post("/scans", headers=admin, json={"target_id":tid,"scan_type":"vulnerability_scan","tool":"mock","mode":"mock"})
    assert r.status_code == 202
    scan_id = r.json()["id"]
    assert client.get("/assets", headers=admin).json()
    findings = client.get("/vulnerabilities", headers=admin).json()
    assert findings and all("DEMO / MOCK" in x["title"] for x in findings)
    risks = client.get("/risk-assessments", headers=admin).json()
    assert risks and all(0 <= x["final_score"] <= 100 for x in risks)
    assert client.get(f"/reports/{scan_id}?format=pdf", headers=admin).headers["content-type"] == "application/pdf"

def test_viewer_cannot_create_target(client):
    r = client.post("/auth/register", json={"username":"viewer","email":"viewer@example.test","password":"Viewer123!","role":"viewer"})
    headers = {"Authorization": "Bearer " + r.json()["access_token"]}
    assert client.post("/targets", headers=headers, json={"name":"x","host":"127.0.0.1","target_type":"IP"}).status_code == 403
