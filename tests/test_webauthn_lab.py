"""Tests for the vulnerable WebAuthn lab (Flask app)."""

import pytest
from plugins.webauthn_plugin.webauthn_lab.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_register_begin_success(client):
    """Проверяем, что эндпоинт /register/begin возвращает challenge."""
    response = client.post('/register/begin', json={"email": "test_lab@example.com"})
    assert response.status_code == 200
    data = response.get_json()
    assert "challenge" in data
    assert data["attestation"] == "direct"

def test_register_begin_no_email(client):
    """Проверяем, что без email стенд возвращает 400."""
    response = client.post('/register/begin', json={})
    assert response.status_code == 400
    assert "email required" in response.get_json()["error"]

def test_register_complete_user_not_found(client):
    """Проверяем, что нельзя завершить регистрацию для несуществующего пользователя."""
    response = client.post('/register/complete', json={"email": "unknown@example.com"})
    assert response.status_code == 404
    assert "user not found" in response.get_json()["error"]
# source .venv/bin/activate
# pytest tests/test_webauthn_lab.py -v