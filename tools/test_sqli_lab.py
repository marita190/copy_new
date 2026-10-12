#проверка SQLi на тестовом стенде
import requests
from langchain.tools import tool


@tool
def test_sqli_lab(base_url: str, endpoint: str, payload: str,
    param: str = "q", method: str = "GET"):
    """проверяет эндпоинт SQLi-стенда на инъекцию

    отправляет запрос с payload в параметре, анализирует ответ на предмет
    SQL-ошибок, утечки данных, изменения поведения

    используй для проверки SQLi на стенде:
      - /api/login (POST, params: username, password) — in-band
      - /api/check_user (GET, param: id) — blind boolean
      - /api/check_user_slow (GET, param: username) — blind time
      - /api/oob (GET, param: username) — out-of-band

    base_url - адресс ресурса
    endpoint - точка входа
    payload - SQL-payload
    param - имя параметра
    method - GET/POST
    """

    # ============== выполняет HTTP-запрос ==============
    url = f"{base_url}{endpoint}"
    try:
        if method.upper() == "POST":
            r = requests.post(url, json={param: payload}, timeout=30)
        else:
            r = requests.get(url, params={param: payload}, timeout=30)
    except Exception as e:
        return f"ошибка: {e}"

    body = (r.text or "")[:1500]

    # ============== признаки SQLi ==============
    indicators = []
    if r.status_code == 200 and '"status":"OK"' in body.replace(" ", ""):
        indicators.append("auth bypass status OK")
    if "error" in body.lower() and "sql" in body.lower():
        indicators.append("SQL-ошибка в ответе")
    if "FLAG{" in body:
        indicators.append("утечка секрета (FLAG)")
    if "secret" in body.lower():
        indicators.append("утечка secrets")

    verdict = "SQLi ПОДТВЕРЖДЁН" if indicators else "ОК"

    return (
        f"URL: {url}\n"
        f"payload: {payload}\n"
        f"status: {r.status_code}\n"
        f"вердикт: {verdict}\n"
        f"indicators: {indicators}\n"
        f"body: {body}"
    )