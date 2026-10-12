"""Intentionally vulnerable Python file inclusion lab. Use only in the lab."""

import os
from pathlib import Path
import runpy

from flask import Flask, jsonify, request
import requests


PUBLIC_DIR = Path(__file__).resolve().parent / "fi_pages"
app = Flask(__name__)


@app.get("/")
def index():
    return """<!doctype html>
<html lang="en"><meta charset="utf-8"><title>LFI / RFI lab</title>
<h1>Python file inclusion lab</h1>
<p>Intentionally vulnerable classroom target. Local modules and remote
modules are executed, not just read.</p>
<h2>LFI</h2><form action="/api/lfi">
<label>Local module <input name="file" value="welcome.py"></label>
<button>Include local file</button></form>
<p>Lab payload: <code>../fi_private_page.py</code></p>
<h2>RFI</h2><form action="/api/rfi">
<label>Remote module URL <input name="url" size="70"
value="http://fi-remote:5102/payload.py?nonce=classroom"></label>
<button>Include remote file</button></form>
<p>Fixed counterparts: <code>/api/lfi-safe</code> and
<code>/api/rfi-safe</code>. See README.md for host-mode URLs.</p>
</html>"""


@app.get("/health")
def health():
    return jsonify(status="OK", lab="file-inclusion")


@app.get("/api/lfi")
def lfi():
    # VULNERABLE: joining a directory does not stop ../ or absolute paths.
    filename = request.args.get("file", "welcome.py")
    path = PUBLIC_DIR / filename
    try:
        included = runpy.run_path(str(path))
    except FileNotFoundError:
        return jsonify(error="File not found"), 404
    except (OSError, ValueError, SyntaxError):
        return jsonify(error="Cannot include file"), 400
    return jsonify(content=included.get("CONTENT", ""))


@app.get("/api/rfi")
def rfi():
    url = request.args.get("url", "")
    if not url:
        return jsonify(error="url is required"), 400
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.RequestException:
        return jsonify(error="Remote file could not be fetched"), 502

    # VULNERABLE: remote bytes become Python code, with normal builtins.
    namespace = {"__name__": "included_remote_module"}
    try:
        exec(response.text, namespace)
    except Exception:
        return jsonify(error="Remote module execution failed"), 400
    return jsonify(content=namespace.get("CONTENT", ""))


@app.get("/api/lfi-safe")
def lfi_safe():
    # The input selects a known identifier; it never becomes a file path.
    if request.args.get("file", "welcome.py") != "welcome.py":
        return jsonify(error="Unknown page"), 403
    included = runpy.run_path(str(PUBLIC_DIR / "welcome.py"))
    return jsonify(content=included["CONTENT"])


@app.get("/api/rfi-safe")
def rfi_safe():
    # Remote code inclusion is disabled; do not fetch or execute the URL.
    return jsonify(error="Remote code inclusion is disabled"), 403


if __name__ == "__main__":
    app.run(host=os.getenv("LAB_HOST", "127.0.0.1"), port=5101, debug=False)
