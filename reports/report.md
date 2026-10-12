

* **Задача:** проверить `http://ssrf-flask:8080` на SSRF с использованием `run_nuclei` и `run_semgrep`; описать находки с критичностью и рекомендациями.

* **Что сделано:**

  | # | Инструмент | Аргументы | Результат |
  |---|---|---|---|
  | 1 | `run_nuclei` | `target_url="http://ssrf-flask:8080"`, `templates=""` (шаблоны по умолчанию), `severity="critical, high, medium, low, info"` | 13 находок, все `severity: info`; шаблонов именно на SSRF среди сработавших нет |
  | 2 | `list_files` | `/app` (depth 3), `/opt`, `/srv`, `/home` | Исходники найдены в `/app/target/`, правила Semgrep — в `/app/rules/rules_semgrep.yaml`. Пути **не выдуманы**, а обнаружены |
  | 3 | `run_semgrep` | `source_path="/app/target"`, `rules_path="/app/rules/rules_semgrep.yaml"` | **0 находок** («Semgrep ничего не нашел») |
  | 4 | `read_file` | `/app/target/SSRF_app.py`, `/app/target/SSRF_service.py` | Код прочитан для ручного SAST-обхода |
  | 5 | `check_idor` / `test_sqli_*` / `run_zap_scan` | — | **Не вызывались**: не относятся к SSRF и не были запрошены |

  Замечание критика по Semgrep закрыто: запуск выполнен, путь к коду и правилам получен через `list_files`, а не назначен наугад.

---

* **Результаты:**

### Находка 1. Server-Side Request Forgery в эндпоинтах `/fetch` и `/raw`
- **Тип:** vulnerability
- **Критичность:** HIGH
- **Локация:** `http://ssrf-flask:8080/fetch`, `http://ssrf-flask:8080/raw`
- **Инструмент:** nuclei + static code review
- **Статус:** `requires_verification` (не подтверждено)

**Доказательство — часть 1 (Nuclei, сырой вывод):**
```http
GET / HTTP/1.1
Host: ssrf-flask:8080
```
```html
<form action="/fetch" method="get">
  <input type="text" name="url" placeholder="https://cataas.com/cat" size="60">
  <button type="submit">Загрузить</button>
</form>
<p>Или напрямую: <code>/fetch?url=...</code></p>
```
Сработавшие шаблоны: `tech-detect` (matcher `python`), `form-detection`.

**Доказательство — часть 2 (код `/app/target/SSRF_app.py`, строки 6–10, 33–40, 51–63):**
```python
BLACKLIST = ["127.0.0.1", "localhost", "169.254.169.254"]

def is_banned(url: str) -> bool:
    return any(badpattern in url for badpattern in BLACKLIST)
```
```python
@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    ...
    if is_banned(url):
        return PAGE.format(result="<p>Запрещенное действие</p>")
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
```
```python
@app.route("/raw")
def raw():
    url = request.args.get("url", "")
    ...
    r = requests.get(url, timeout=5, allow_redirects=True)
    return Response(r.content, status=r.status_code, ...)
```

**Интерпретация (отдельно от фактов):** параметр `url` от пользователя попадает в `requests.get()` без разбора схемы, без резолвинга DNS и без проверки итогового IP. Защита — подстрочный blacklist из трёх значений, `allow_redirects=True`. Это создаёт условия для SSRF к внутренним сервисам и метаданным облака.

**Оговорка:** payload в `/fetch` и `/raw` **не отправлялся**, ответов от этих эндпоинтов в результатах инструментов нет. Уязвимость **не подтверждена**.

---

### Находка 2. Отсутствие HTTP security headers
- **Тип:** misconfiguration
- **Критичность:** INFO
- **Локация:** `http://ssrf-flask:8080/`
- **Инструмент:** Nuclei, шаблон `http/misconfiguration/http-missing-security-headers.yaml`
- **Статус:** подтверждено

**Сырое доказательство — полный набор заголовков ответа (из `response` матча Nuclei):**
```http
HTTP/1.1 200 OK
Connection: close
Content-Length: 409
Content-Type: text/html; charset=utf-8
Date: Mon, 12 Oct 2026 16:22:29 GMT
Server: Werkzeug/3.1.9 Python/3.11.17
```
В ответе присутствуют только 6 заголовков. Ни один из перечисленных ниже security-заголовков в нём не присутствует. Каждый факт зафиксирован отдельным матчем с соответствующим `matcher-name`:

| Отсутствующий заголовок | `matcher-name` в выводе Nuclei |
|---|---|
| X-Content-Type-Options | `x-content-type-options` |
| Referrer-Policy | `referrer-policy` |
| Cross-Origin-Resource-Policy | `cross-origin-resource-policy` |
| Strict-Transport-Security | `strict-transport-security` |
| Content-Security-Policy | `content-security-policy` |
| Permissions-Policy | `permissions-policy` |
| X-Frame-Options | `x-frame-options` |
| X-Permitted-Cross-Domain-Policies | `x-permitted-cross-domain-policies` |
| Cross-Origin-Embedder-Policy | `cross-origin-embedder-policy` |
| Cross-Origin-Opener-Policy | `cross-origin-opener-policy` |

Классификация шаблона: `cwe-693`.

---

### Находка 3. Раскрытие версии сервера
- **Критичность:** INFO — **подтверждено**
- **Доказательство (сырой заголовок):** `Server: Werkzeug/3.1.9 Python/3.11.17`; matcher `python` шаблона `tech-detect`.

### Находка 4. Разрешён метод OPTIONS
- **Критичность:** INFO — **подтверждено**
- **Доказательство (сырой ответ на `OPTIONS /`):**
```http
HTTP/1.1 200 OK
Allow: HEAD, OPTIONS, GET
Content-Length: 0
```
`extracted-results: ["HEAD, OPTIONS, GET"]`. POST/PUT не разрешены — риск низкий.

---

### Находка 5. Semgrep: 0 находок при наличии уязвимого кода
- **Статус:** подтверждено (факт запуска)
- **Результат:** `run_semgrep(source_path="/app/target", rules_path="/app/rules/rules_semgrep.yaml")` → «Semgrep ничего не нашел».
- **Интерпретация:** отсутствие находок Semgrep **не означает** отсутствие уязвимости. Код в `SSRF_app.py` содержит SSRF-паттерн (проверено ручным чтением). Наиболее вероятная причина — файл правил не содержит правил под Python/`requests`. **Точная причина не установлена**: содержимое `rules_semgrep.yaml` я не читал и не проверял.

### Находка 6. Смежные чувствительные эндпоинты в коде стенда
- **Критичность:** INFO / требует проверки
- **Факт:** в `/app/target/SSRF_service.py` объявлены маршруты `/admin` и `/metadata`; в коде присутствуют захардкоженные секретные значения (токен приложения и поля, имитирующие облачные IAM-креденшелы). Значения намеренно не привожу.
- **Оговорка:** `SSRF_service.py` — **отдельное** Flask-приложение. Достижимы ли `/admin` и `/metadata` на `ssrf-flask:8080` — **не проверялось и не подтверждалось**; Nuclei их не находил. Рассматривать только как потенциальную цель при подтверждении внутренней достижимости.

---

* **Выводы:**

1. **SSRF не подтверждён.** Статус — `requires_verification`. Есть два независимых признака: входная точка `/fetch?url=` (Nuclei) и код, передающий пользовательский URL в `requests.get()` с blacklist-валидацией (ручное чтение). Но HTTP-доказательства эксплуатации отсутствуют.
2. **Уверенность в наличии уязвимой логики — высокая**, в факте эксплуатации — **нулевая**, пока не отправлен payload.
3. **Blacklist из трёх подстрок не является эффективной защитой** — это следствие из кода, а не эмпирический факт: конкретные обходы (альтернативные представления IP, внешние DNS-имена, редирект) **не проверялись**.
4. **Semgrep не закрыл SAST-часть.** Отрицательный результат инструмента при наличии уязвимого кода означает пробел в правилах, а не чистоту кода.
5. **Находки 2–4 — информационные**, к SSRF отношения не имеют, но снижают общую защищённость.

**Что нужно для подтверждения SSRF (в разрешённом изолированном стенде):**
- отправить в `/fetch?url=` безопасный внешний URL как baseline, затем внутренний адрес того же стенда;
- сравнить код статуса, размер и тело ответа, время отклика;
- отдельно проверить обход blacklist (иное IP-представление, редирект с внешнего хоста);
- проверить `/raw` — он возвращает `r.content` без экранирования, что даёт более чистый канал утечки.
Эти запросы я не выполнял: они выходят за рамки вызванных инструментов и требуют вашего явного подтверждения, что стенд изолирован.

---

* **Рекомендации:**

**По SSRF (приоритет — снять blacklist и перейти к allowlist):**
1. Строгий allowlist схем (`http`, `https`) и хостов; всё остальное — отказ по умолчанию.
2. Разобрать URL, резолвить DNS **до** запроса, проверить итоговый IP: блокировать `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `fc00::/7`, `0.0.0.0/8`. Проверять **все** адреса из DNS-ответа, не только первый.
3. Проверять IP после установки соединения (защита от DNS rebinding / TOCTOU).
4. `allow_redirects=False`; при необходимости — ручной переход с повторной валидацией каждого Location.
5. Запретить нестандартные схемы (`file://`, `gopher://`, `dict://`, `ftp://`).
6. Сетевой egress-контроль: контейнеру приложения доступен только нужный внешний хост; доступ к metadata endpoint и внутренним сервисам заблокирован на уровне сети — это страховка на случай ошибки в прикладной логике.
7. Не возвращать пользователю сырое тело ответа внутреннего ресурса (`/raw` нарушает это сейчас).
8. Таймауты и ограничение размера ответа уже есть (`timeout=5`, срез 5000 символов в `/fetch`) — сохранить; в `/raw` лимита размера нет.
9. Логировать отказы и попытки обращения к внутренним адресам.

**По security headers:** добавить через middleware или reverse proxy `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (или CSP `frame-ancestors 'none'`), `Referrer-Policy`, `Content-Security-Policy`, `Permissions-Policy`; `Strict-Transport-Security` — после перехода на HTTPS.

**По раскрытию версии:** переопределить/убрать заголовок `Server` на reverse proxy, следить за обновлениями Flask/Werkzeug/Python.

**По Semgrep:** дополнить `rules_semgrep.yaml` правилами под Python-HTTP-клиенты (`requests.get/post`, `urllib.request.urlopen`, `httpx`) с источником `request.args`/`request.json`, чтобы SSRF детектировался статически, а не только ручным разбором.

**По `SSRF_service.py`:** убрать секреты из исходного кода в переменные окружения/секреты-хранилище, закрыть `/admin` аутентификацией, `/metadata` не публиковать во внешнем контуре.