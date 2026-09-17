from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)
def test_health(): assert client.get("/health").json() == {"status":"ok", "version":"0.1.0-alpha.1"}
def test_home_is_local_only():
    response = client.get("/")
    assert response.status_code == 200 and "https://" not in response.text and "Content-Security-Policy" in response.headers
