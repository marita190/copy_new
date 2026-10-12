"""A controlled remote server providing a harmless executable RFI proof."""

import os

from flask import Flask, Response, jsonify, request


app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(status="OK")


@app.get("/payload.py")
def payload():
    nonce = request.args.get("nonce", "classroom")
    # repr prevents the nonce itself from injecting Python into this fixture.
    # The final marker does not appear in the source: execution computes 42.
    source = f"CONTENT = 'RFI_EXECUTED:' + {nonce!r} + ':' + str(6 * 7)\n"
    return Response(source, mimetype="text/plain")


if __name__ == "__main__":
    app.run(host=os.getenv("LAB_HOST", "127.0.0.1"), port=5102, debug=False)
