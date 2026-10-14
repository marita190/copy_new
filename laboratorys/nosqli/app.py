import os
import time
from flask import Flask, request, jsonify, render_template
from pymongo import MongoClient

app = Flask(__name__, template_folder="templates")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://nosqli-mongo:27017")
DB_NAME = "nosqli_lab"

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
db = client[DB_NAME]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "OK"})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    try:
        user = db.users.find_one({"username": username, "password": password})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    if user:
        return jsonify({
            "status": "OK",
            "user_id": str(user["_id"]),
            "username": user["username"],
            "role": user.get("role"),
            "secret": user.get("secret"),
        }), 200
    return jsonify({"status": "fail"}), 401


@app.route("/api/check_user", methods=["GET"])
def check_user():
    username = request.args.get("username", "")

    # Парсим ключи вида password[$regex] в {"password": {"$regex": "..."}}
    password = ""
    for key, value in request.args.items():
        if key == "password":
            password = value
        elif key.startswith("password[") and key.endswith("]"):
            op = key[len("password["):-1]      # "$regex", "$ne", "$gt" ...
            password = {op: value}
            break

    query = {"username": username, "password": password}
    try:
        user = db.users.find_one(query)
        return jsonify({"exists": user is not None, "query": query})
    except Exception as e:
        return jsonify({"exists": False, "error": str(e), "query": query})

@app.route("/api/check_user_slow", methods=["GET"])
def check_user_slow():
    username = request.args.get("username", "")
    where_js = request.args.get("where", "")

    start = time.time()
    try:
        if where_js:
            db.users.find_one({"username": username, "$where": where_js})
        else:
            db.users.find_one({"username": username})
    except Exception:
        pass
    return jsonify({"time": time.time() - start})


@app.route("/api/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    error = None
    results = []
    try:
        cursor = db.products.find({"$where": f"this.name == '{q}'"})
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            results.append(doc)
    except Exception as e:
        error = str(e)

    return jsonify({"query": q, "error": error, "results": results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
