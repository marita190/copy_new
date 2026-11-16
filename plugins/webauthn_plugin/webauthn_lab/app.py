import os
import json
import base64
from flask import Flask, request, jsonify
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
)

app = Flask(__name__)
app.secret_key = os.urandom(32)

REQUIRED_ATTESTATION = "direct"
RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = "Vulnerable WebAuthn Lab"
ORIGIN = os.getenv("ORIGIN", "http://localhost:5001")

users = {}
challenges = {}

@app.route("/register/begin", methods=["POST"])
def register_begin():
    email = request.json.get("email")
    if not email:
        return jsonify({"error": "email required"}), 400

    user = users.setdefault(email, {"id": os.urandom(16), "credentials": []})

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user["id"],
        user_name=email,
        user_display_name=email,
        attestation=AttestationConveyancePreference.DIRECT,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    challenges["reg"] = options.challenge
    return jsonify(json.loads(options_to_json(options)))

@app.route("/register/complete", methods=["POST"])
def register_complete():
    payload = request.get_json(silent=True) or {}
    email = payload.get("email")
    if not email:
        return jsonify({"error": "email required"}), 400
    user = users.get(email)
    if not user:
        return jsonify({"error": "user not found"}), 404

    try:
        verification = verify_registration_response(
            credential=request.get_data(as_text=True),
            expected_challenge=challenges["reg"],
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=False,
        )

        user["credentials"].append({
            "id": verification.credential_id,
            "public_key": verification.credential_public_key,
            "sign_count": verification.sign_count,
            "aaguid": verification.aaguid,
        })
        return jsonify({"verified": True})

    except Exception as e:
        return jsonify({"verified": False, "error": str(e)}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
