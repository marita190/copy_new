"""Уязвимый SQLi-стенд"""
import sqlite3
from flask import Flask, request, jsonify, g, render_template


app = Flask(__name__, template_folder="templates")
DB = "lab_database.db"

def get_db():
    """
    создает соединение, если в контейнере еще нет db 
    """
    if "db" not in g:
        g.db = sqlite3.connect(DB)
    return g.db

@app.teardown_appcontext
def close_db(exc):
    """
    закрывает базу данных в конце запроса, если была открыта
    """
    db = g.pop("db", None)
    if db: db.close()

@app.route("/")
def index():
    """
    ищет файл template/index.html в корне проекта
    рендерит его
    возвращает готовую html-строку
    """
    return render_template("index.html")

@app.route("/health")
def health():
    """
    проверка Docker
    """
    return jsonify({"status": "OK"})


# ============ ERROR-BASED SQLi ============
@app.route("/api/login", methods=["POST"])
def login():
    """
    пример SQL-инъекции в API-логине
    уязвимости:
        1) конкатенация строк в SQL - при подстановки "' OR 1=1--" в username
            СУБД вернет первую попавшуюся строку - admin
        2) утечка ошибок SQL => можно получить информацию о структуре бд
    """

    # чтение входных данных
    data_in = request.get_json() or {}
    username = data_in.get("username", "")
    password = data_in.get("password", "")

    # подключение к бд
    connection = get_db()
    cursor = connection.cursor()

    # вополнение запроса
    query = f"SELECT * FROM Users WHERE username='{username}' AND password='{password}'"
    try:
        cursor.execute(query)
        row = cursor.fetchone()
        if row:
            return jsonify({"status": "OK", "user_id": row[0], "username": row[1]}), 200
        return jsonify({"status": "fail", "query": query}), 401
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500
    
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)