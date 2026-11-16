"""Tests for error handling in the WebAuthn tool."""

import json
from unittest.mock import patch, MagicMock
import pytest
import requests

from plugins.webauthn_plugin.check_webauthn_attestation import check_webauthn_attestation

@patch("requests.post")
def test_webauthn_tool_timeout(mock_post):
    """Если сервер не отвечает (Timeout), инструмент должен вернуть ОШИБКА."""
    mock_post.side_effect = requests.exceptions.Timeout()
    
    result_str = check_webauthn_attestation.invoke({"base_url": "http://fake"})
    result = json.loads(result_str)
    
    assert result["verdict"] == "ОШИБКА"
    assert result["detail"] == "Таймаут"

@patch("requests.post")
def test_webauthn_tool_begin_fails(mock_post):
    """Если сервер отвечает ошибкой на самом первом шаге (begin)."""
    mock_begin_resp = MagicMock()
    mock_begin_resp.status_code = 500
    mock_post.return_value = mock_begin_resp
    
    result_str = check_webauthn_attestation.invoke({"base_url": "http://fake"})
    result = json.loads(result_str)
    
    assert result["verdict"] == "ОШИБКА"
    assert "begin: 500" in result["detail"]
# source .venv/bin/activate
# pytest tests/test_webauthn_errors.py -v