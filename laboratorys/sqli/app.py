"""Уязвимый SQLi-стенд"""
import sqlite3
import time
import os
from init_db import init_db
from flask import Flask, request, jsonify, g, render_template


app = Flask(__name__, template_folder="templates")
DB = "lab_database.db"

OOB_DIR = "oob_channel"
os.makedirs(OOB_DIR, exist_ok=True)


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


# ============ IN-BAND ============
@app.route("/api/login", methods=["POST"])
def login():
    """
    пример SQL-инъекции в API-логине
    In-band SQLi: auth bypass + union + error-based
    уязвимости:
        1) конкатенация строк в SQL - при подстановки "' OR 1=1--" в username
            СУБД вернет первую попавшуюся строку - admin, a "x' UNION SELECT id, secret_usser, secret_usser FROM Secrets-- -" - его секрет
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

# ============ BLIND-BOOLEAN SQLi ============
@app.route("/api/check_user", methods=["GET"])
def check_user():
    """
    пример слепой булевой инъекции
    уязвимости:
        1) конкатенация строк
        2) разный результат в зависимости от TRUE/FALSE
        
    """

    # подключение к бд
    connection = get_db()
    cursor = connection.cursor()

    # вополнение запроса
    pid = request.args.get("id", "1")
    query = f"SELECT id FROM Users WHERE id='{pid}'"

    try:
        cursor.execute(query)
        row = cursor.fetchone()
        return jsonify({"query": query, "result": row is not None})
    except Exception:
        return jsonify({"query": query, "result": False})

# ============ BLIND-TIME SQLi ============
@app.route("/api/check_user_slow")
def check_user_slow():
    """
    пример слепой временной инъекции
    уязвимости:
        1) конкатенация строк
        2) ответ приходит с задержкой, зависящей от TRUE/FALSE
    """

    username = request.args.get("username", "")

    # подключение к бд
    connection = get_db()
    cursor = connection.cursor()

    # вополнение запроса
    query = f"SELECT COUNT(*) FROM Users WHERE username='{username}'"
    start = time.time()

    try:
        cursor.execute(query)
        cursor.fetchone()
    except Exception:
        pass
    return jsonify({"time": time.time() - start})

# ============ OUT-OF-BAND SQLi ============
def read_leaked_file(file_path):
    """
    читает по заданному пути файл, созданный через ATTACH DATABASE, как SQLite-БД
    возвращает содержимое всех таблиц
    """
    result = {}
    try:
        connection = sqlite3.connect(file_path)
        cursor = connection.cursor()

        # узнаем все таблицы
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        # читаем строки для каждой таблицы
        for table in tables:
            try:
                cursor.execute(f"SELECT * FROM {table}")
                rows = cursor.fetchall()

                # имена столбцов
                cols = [d[0] for d in cursor.description] if cursor.description else []
                result[table] = {"columns": cols, "rows": [list(r) for r in rows]}
            except Exception as e:
                result[table] = {"error": str(e)}

        connection.close()
    except Exception as e:
        result["_error"] = str(e)

    return result


@app.route("/api/oob")
def oob():
    """
    пример внеполосной инъекции (симуляция)
    -нельзя получить результат, через тот же канал, что и атаку
    уязвимости:
        1) конкатенация строк
        2) использование executescript (для множественных SQL-запросов)
        3) СУБД может создавать файлы на диске
    """

    username = request.args.get("username", "")

    # подключение к бд
    connection = get_db()
    cursor = connection.cursor()

    # вополнение запроса
    query = f"SELECT id, username FROM Users WHERE username='{username}'"
    error = None
    try:
        cursor.executescript(query)
        connection.commit()
    except Exception as e:
        error = str(e)

    # проверяем папку oob-channel на новые файлы
    time.sleep(0.1)
    leaked = []
    for file_name in os.listdir(OOB_DIR):
        file_path = os.path.join(OOB_DIR, file_name)
        if os.path.isfile(file_path):
            dumped = read_leaked_file(file_path)
            if dumped:
                leaked.append({"file": file_name, "content": dumped})

    with open("oob.log", "a") as file:
        file.write(f"{time.time()} {username} {leaked}")

    return jsonify({"query": username, "error": error, "leaked": leaked})

if __name__ == "__main__":
    if not os.path.exists(DB):
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)