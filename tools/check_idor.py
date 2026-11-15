# проверка на IDOR
from langchain.tools import tool
import requests
import json


@tool
def check_idor(url: str, endpoint: str, id_object: str, token: str, my_id: str=""):
    """
    проверяет, может ли пользователь получить доступ к данным, 
    даже если не является их владельцом

    url - адрес ресурса
    endpoint - точка входа
    id_object - индикатор объекта
    token - токен пользователя

    отправляет get-запрос к url/endpoint/id_object c bearer token 
    возвращает JSON:
      {"url": ..., "verdict": ..., "checks": [...]}
    """
    url = f"{url}{endpoint}/{id_object}"
    headers = {"Authorization": f"Bearer {token}"}
    result = {
        "target_url": url,
        "id_object": id_object,
        "my_id": my_id or None,
        "checks": [],
        "verdict": "requires_verification",
    }

    # ============ запрос к объекту id_object ============
    try:
        res = requests.get(url, headers=headers, timeout=15)
        body = (res.text or "")
        result["checks"].append({
            "target": "id_object",
            "id": id_object,
            "status": res.status_code,
            "body_len": len(body),
            "body_preview": body[:300],
            "is_empty": len(body.strip()) == 0,
        })
    except Exception as e:
        result["error"] = f"ошибка запроса к {url}: {e}"
        return json.dumps(result, ensure_ascii=False, indent=2)

    # ============ если передан my_id — сравнить ============
    if my_id and str(my_id) != str(id_object):
        own_url = f"{url}{endpoint}/{my_id}"
        try:
            own = requests.get(own_url, headers=headers, timeout=15)
            own_body = (own.text or "")
            result["checks"].append({
                "target": "my_id",
                "id": my_id,
                "status": own.status_code,
                "body_len": len(own_body),
                "body_preview": own_body[:300],
                "is_empty": len(own_body.strip()) == 0,
            })

            foreign_ok = res.status_code == 200 and len(body.strip()) > 0
            own_ok = own.status_code == 200 and len(own_body.strip()) > 0

            if foreign_ok and own_ok and body.strip() != own_body.strip():
                result["verdict"] = (
                    "ПОДОЗРЕНИЕ НА IDOR: доступ к чужому объекту, "
                    "тело отличается от вашего"
                )
            elif foreign_ok and own_ok:
                result["verdict"] = "ОК: данные совпадают с вашим объектом"
            elif foreign_ok and not own_ok:
                result["verdict"] = (
                    "requires_verification: доступ к чужому 200, "
                    "но ваш объект недоступен"
                )
            else:
                result["verdict"] = f"ОК: статус {res.status_code}"
        except Exception as e:
            result["verdict"] = f"ошибка сравнения с my_id: {e}"
    else:
        # без my_id — только предварительная проверка
        if res.status_code == 200 and len(body.strip()) > 0:
            result["verdict"] = (
                "requires_verification: HTTP 200, но нет сравнения с "
                "вашим объектом. Передайте my_id для подтверждения."
            )
        elif res.status_code == 200:
            result["verdict"] = "ОК: HTTP 200, но тело пустое"
        elif res.status_code in (401, 403):
            result["verdict"] = "ОК: доступ запрещён (401/403)"
        else:
            result["verdict"] = f"ОК: статус {res.status_code}"

    return json.dumps(result, ensure_ascii=False, indent=2)
