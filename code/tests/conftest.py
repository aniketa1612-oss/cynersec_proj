import os
import tempfile
os.environ["DATABASE_URL"] = "sqlite:///" + tempfile.NamedTemporaryFile(suffix=".db", delete=False).name.replace("\\", "/")
os.environ["SECRET_KEY"] = "test-secret"
from fastapi.testclient import TestClient
from app.main import app
import pytest

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def admin(client):
    r = client.post("/auth/register", json={"username":"admin_test","email":"admin_test@example.test","password":"Admin123!","role":"admin"})
    return {"Authorization": "Bearer " + r.json()["access_token"]}

