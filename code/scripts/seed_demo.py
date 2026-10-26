"""Seed clearly documented development users and an authorized lab target."""
import sys
from pathlib import Path
from datetime import datetime, timedelta
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import Audit, Base, SessionLocal, Target, User, engine, pwd

Base.metadata.create_all(engine)
s = SessionLocal()
try:
    users = []
    for username, email, password, role in [
        ("admin", "admin@example.test", "Admin123!", "admin"),
        ("analyst", "analyst@example.test", "Analyst123!", "analyst"),
    ]:
        user = s.query(User).filter_by(username=username).first()
        if not user:
            user = User(username=username, email=email, password_hash=pwd.hash(password), role=role)
            s.add(user)
            s.flush()
        users.append(user)
    if not s.query(Target).filter_by(host="192.168.56.100").first():
        now = datetime.utcnow()
        s.add(Target(name="DEMO / MOCK Lab Server", host="192.168.56.100", target_type="IP",
                     description="Isolated synthetic academic target", authorization_status="authorized",
                     authorization_reference="DEMO-AUTH-001", authorization_start=now-timedelta(days=1),
                     authorization_end=now+timedelta(days=30), created_by=users[0].id))
    s.add(Audit(user_id=users[0].id, action="demo.seed", ip_address="local", details="Development/demo records only"))
    s.commit()
    print("Seed complete. Development users: admin/Admin123! and analyst/Analyst123!")
finally:
    s.close()
