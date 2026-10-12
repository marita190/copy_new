import requests
from flask import Flask, request, Response

app = Flask(__name__)

BLACKLIST = ["127.0.0.1", "localhost", "169.254.169.254"]

def is_banned(url: str) -> bool:
    return any(badpattern in url for badpattern in BLACKLIST)

PAGE = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Котики (Flask)</title></head>
<body>
  <h1>Просмотр котиков</h1>
  <form action="/fetch" method="get">
    <input type="text" name="url" placeholder="https://cataas.com/cat" size="60">
    <button type="submit">Загрузить</button>
  </form>
  <p>Или напрямую: <code>/fetch?url=...</code></p>
  {result}
</body>
</html>
"""

@app.route("/")
def home():
    return PAGE.format(result="")

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return PAGE.format(result="<p>Введите URL</p>")

    if is_banned(url):
        return PAGE.format(result="<p>Запрещенное действие</p>")

    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        content_type = r.headers.get("Content-Type", "")
        body = r.text[:5000]
        result = (
            f"<h2>Ответ от {url}</h2>"
            f"<p>HTTP {r.status_code}, Content-Type: {content_type}</p>"
            f"<pre>{body}</pre>"
        )
        return PAGE.format(result=result)

    except Exception as e:
        return PAGE.format(result=f"<p>Ошибка: {e}</p>")

@app.route("/raw")
def raw():
    url = request.args.get("url", "")
    if not url:
        return Response("no url", status=400, mimetype="text/plain")
    if is_banned(url):
        return Response("banned", status=403, mimetype="text/plain")
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        return Response(r.content, status=r.status_code,
                        content_type=r.headers.get("Content-Type", "text/plain"))
    except Exception as e:
        return Response(f"error: {e}", status=502, mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)