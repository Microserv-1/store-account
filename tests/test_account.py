import os
import tempfile
import time
import uuid
os.environ["JWT_SECRET"] = "test-secret-that-is-at-least-32-characters"
os.environ["INTERNAL_AUTH_KEY"] = "test-internal-key-that-is-at-least-32-characters"
_database = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_database.close()
os.environ["DATABASE_URL"] = "sqlite:///" + _database.name

import jwt
from fastapi.testclient import TestClient
from app.main import app

def test_password_storage_duplicate_and_identity():
    with TestClient(app) as client:
        email = f"{uuid.uuid4()}@example.com"
        body = {"name": "Test", "email": email, "password": "strong-test-password"}
        response = client.post("/accounts", json=body)
        assert response.status_code == 201
        account = response.json()
        assert "password" not in account
        assert client.post("/accounts", json=body).status_code == 409
        assert client.get("/accounts/me", headers={"X-Account-ID": account["id"]}).status_code == 401
        now = int(time.time())
        token = jwt.encode({"sub": account["id"], "iss": "store-auth", "aud": "store-api", "iat": now, "exp": now+60}, os.environ["JWT_SECRET"], algorithm="HS256")
        assert client.get("/accounts/me", headers={"Authorization": "Bearer "+token}).json() == account
        assert client.post("/internal/credentials/verify", json=body).status_code == 403
        headers = {"X-Internal-Auth-Key": os.environ["INTERNAL_AUTH_KEY"]}
        assert client.post("/internal/credentials/verify", json=body, headers=headers).json() == {"id": account["id"]}
        body["password"] = "incorrect-password"
        assert client.post("/internal/credentials/verify", json=body, headers=headers).status_code == 401
