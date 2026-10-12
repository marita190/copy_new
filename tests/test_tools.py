"""Behavioral tests for the tools exposed to the security agent."""

import json
import os
import subprocess
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests

from tools import (
    check_idor,
    list_files,
    read_file,
    read_file_around_line,
    run_nuclei,
    run_semgrep,
    run_zap_scan,
    test_sqli_lab as sqli_lab_tool,
    test_sqli_login as sqli_login_tool,
)

zap_module = import_module("tools.run_zap_scan")
sqli_lab_module = import_module("tools.test_sqli_lab")


def test_read_file_returns_content_and_metadata(tmp_path):
    source = tmp_path / "example.py"
    source.write_text("first line\nsecond line\n", encoding="utf-8")

    result = read_file.invoke({"path": str(source), "cnt_chars": 500})

    assert f"файл: {source}" in result
    assert "к-во строк: 2" in result
    assert "файл полностью прочитан" in result
    assert result.endswith("first line\nsecond line\n")


def test_read_file_limits_output_and_reports_truncation(tmp_path):
    source = tmp_path / "large.py"
    source.write_text("x" * 120 + "END", encoding="utf-8")

    result = read_file.invoke({"path": str(source), "cnt_chars": 1})

    assert "файл обрезан на 100 символах" in result
    assert "END" not in result


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="read_file includes the extra character used to detect truncation",
)
def test_read_file_does_not_return_more_than_the_effective_limit(tmp_path):
    source = tmp_path / "large.py"
    source.write_text("x" * 120 + "END", encoding="utf-8")

    result = read_file.invoke({"path": str(source), "cnt_chars": 1})
    content = result.split("\n", 5)[5]

    assert content == "x" * 100


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("private.pem", "чтение файла запрещено"),
        ("binary.exe", "файлы данного расширения не подходят для чтения"),
    ],
)
def test_read_file_rejects_disallowed_files(tmp_path, name, message):
    source = tmp_path / name
    source.write_text("sample", encoding="utf-8")

    result = read_file.invoke({"path": str(source), "cnt_chars": 500})

    assert message in result


@pytest.mark.parametrize("directory", [".git", ".ssh", ".aws"])
@pytest.mark.xfail(
    os.name == "nt",
    strict=True,
    raises=AssertionError,
    reason="forbidden directory checks do not recognize Windows separators",
)
def test_read_file_rejects_forbidden_directories(tmp_path, directory):
    source = tmp_path / directory / "example.py"
    source.parent.mkdir()
    source.write_text("test data", encoding="utf-8")

    result = read_file.invoke({"path": str(source), "cnt_chars": 500})

    assert "чтение файла запрещено" in result


def test_read_file_reports_missing_path(tmp_path):
    result = read_file.invoke(
        {"path": str(tmp_path / "missing.py"), "cnt_chars": 500}
    )

    assert "файл не найден" in result


def test_read_file_rejects_directory_path(tmp_path):
    result = read_file.invoke({"path": str(tmp_path), "cnt_chars": 500})

    assert "это не файл" in result


def test_read_file_around_line_returns_local_context(tmp_path):
    source = tmp_path / "example.py"
    source.write_text(
        "".join(f"line {number}\n" for number in range(1, 31)),
        encoding="utf-8",
    )

    result = read_file_around_line.invoke(
        {"path": str(source), "line": 15, "cnt_chars": 5}
    )

    assert "были прочитаны строки 10-20" in result
    assert "опорная строка: 15" in result
    assert "line 10\n" in result
    assert "line 20\n" in result
    assert "line 9\n" not in result
    assert "line 21\n" not in result


@pytest.mark.parametrize(
    ("line", "message"),
    [(0, "номер строки должен быть >= 1"), (3, "некорректный номер строки")],
)
def test_read_file_around_line_rejects_invalid_line(tmp_path, line, message):
    source = tmp_path / "example.py"
    source.write_text("one\ntwo\n", encoding="utf-8")

    result = read_file_around_line.invoke(
        {"path": str(source), "line": line, "cnt_chars": 5}
    )

    assert message in result


def test_read_file_around_line_reports_empty_file(tmp_path):
    source = tmp_path / "empty.py"
    source.write_text("", encoding="utf-8")

    result = read_file_around_line.invoke(
        {"path": str(source), "line": 1, "cnt_chars": 5}
    )

    assert result == "файл пуст"


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="cnt_chars > 500 is not capped in the current tool",
)
def test_read_file_around_line_caps_large_context(tmp_path):
    source = tmp_path / "example.py"
    source.write_text(
        "".join(f"line {number}\n" for number in range(1, 1301)),
        encoding="utf-8",
    )

    result = read_file_around_line.invoke(
        {"path": str(source), "line": 650, "cnt_chars": 800}
    )

    assert "были прочитаны строки 150-1150" in result


def test_semgrep_reports_missing_source_without_running_scan(tmp_path):
    def unexpected_run(*args, **kwargs):
        pytest.fail("Semgrep must not run when the source path is missing")

    with patch.object(subprocess, "run", side_effect=unexpected_run):
        result = run_semgrep.invoke(
            {
                "source_path": str(tmp_path / "missing"),
                "rules_path": str(tmp_path / "rules.yaml"),
            }
        )

    assert "не найден путь" in result


def test_semgrep_reports_scan_failure_for_missing_rules(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    missing_rules = tmp_path / "missing.yaml"

    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(returncode=2, stdout="")
    ) as run:
        result = run_semgrep.invoke(
            {"source_path": str(source), "rules_path": str(missing_rules)}
        )

    run.assert_called_once_with(
        ["semgrep", "scan", "--config", str(missing_rules),
         "--json", "--metrics", "off", str(source)],
        capture_output=True, text=True, timeout=600,
    )
    assert "ошибка" in result
    assert "кодом 2" in result


def test_semgrep_summarizes_findings(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    finding = {
        "check_id": "example-rule",
        "path": "source/app.py",
        "start": {"line": 7},
        "extra": {"severity": "WARNING", "message": "Review query", "lines": "query()"},
    }

    def fake_run(command, **kwargs):
        assert command == [
            "semgrep", "scan", "--config", str(rules),
            "--json", "--metrics", "off", str(source),
        ]
        assert kwargs == {"capture_output": True, "text": True, "timeout": 600}
        return SimpleNamespace(returncode=1, stdout=json.dumps({"results": [finding]}))

    with patch.object(subprocess, "run", side_effect=fake_run):
        result = json.loads(
            run_semgrep.invoke({"source_path": str(source), "rules_path": str(rules)})
        )

    assert result["total_findings"] == 1
    assert result["returned"] == 1
    assert result["findings"] == [
        {
            "check_id": "example-rule",
            "path": "source/app.py",
            "line": 7,
            "severity": "WARNING",
            "message": "Review query",
            "snippet": "query()",
        }
    ]


def test_semgrep_limits_report_to_twenty_findings(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    findings = [
        {
            "check_id": f"rule-{number}",
            "start": {"line": number},
            "extra": {"message": "m" * 105, "lines": "s" * 105},
        }
        for number in range(1, 22)
    ]
    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(
            returncode=1, stdout=json.dumps({"results": findings})
        )
    ):
        result = json.loads(
            run_semgrep.invoke({"source_path": str(source), "rules_path": str(rules)})
        )

    assert result["total_findings"] == 21
    assert result["returned"] == 20
    assert len(result["findings"]) == 20
    assert result["findings"][-1]["check_id"] == "rule-20"
    assert result["findings"][0]["message"] == "m" * 100
    assert result["findings"][0]["snippet"] == "s" * 100


def test_semgrep_reports_empty_results(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(
            returncode=0, stdout=json.dumps({"results": []})
        )
    ):
        result = run_semgrep.invoke(
            {"source_path": str(source), "rules_path": str(rules)}
        )

    assert "ничего не нашел" in result


def test_semgrep_reports_process_failure(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(returncode=2, stdout="")
    ):
        result = run_semgrep.invoke(
            {"source_path": str(source), "rules_path": str(rules)}
        )

    assert "ошибка" in result
    assert "кодом 2" in result


def test_semgrep_reports_missing_executable(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")

    def missing_executable(*args, **kwargs):
        raise FileNotFoundError("semgrep executable not found")

    with patch.object(subprocess, "run", side_effect=missing_executable):
        result = run_semgrep.invoke(
            {"source_path": str(source), "rules_path": str(rules)}
        )

    assert "ошибка" in result
    assert "semgrep executable not found" in result


@pytest.mark.parametrize(
    ("status", "verdict"),
    [(200, "найдена уязвимость IDOR"), (403, "ОК")],
)
def test_check_idor_sends_bearer_request_and_returns_verdict(status, verdict):
    def fake_get(url, **kwargs):
        assert url == "http://localhost:3000/rest/basket/1"
        assert kwargs == {
            "headers": {"Authorization": "Bearer sample-token"},
            "timeout": 5,
        }
        return SimpleNamespace(status_code=status)

    with patch.object(requests, "get", side_effect=fake_get):
        result = check_idor.invoke(
            {
                "url": "http://localhost:3000",
                "endpoint": "/rest/basket",
                "id_object": "1",
                "token": "sample-token",
            }
        )

    assert result == verdict


def test_check_idor_reports_connection_error():
    def fake_get(*args, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    with patch.object(requests, "get", side_effect=fake_get):
        result = check_idor.invoke(
            {"url": "http://localhost", "endpoint": "/item", "id_object": "1", "token": "x"}
        )

    assert "ошибка запроса" in result
    assert "connection refused" in result


def test_check_idor_reports_timeout():
    def fake_get(*args, **kwargs):
        raise requests.exceptions.Timeout("request timed out")

    with patch.object(requests, "get", side_effect=fake_get):
        result = check_idor.invoke(
            {"url": "http://localhost", "endpoint": "/item", "id_object": "1", "token": "x"}
        )

    assert "ошибка запроса" in result
    assert "request timed out" in result


def test_sqli_login_posts_payload_and_reports_neutral_response():
    def fake_post(url, **kwargs):
        assert url == "http://localhost:3000/rest/user/login"
        assert kwargs == {
            "json": {"email": "' OR 1=1--", "password": "1234567890"},
            "headers": {"Content-Type": "application/json"},
            "timeout": 10,
            "allow_redirects": False,
        }
        return SimpleNamespace(status_code=401, text="Invalid credentials")

    with patch.object(requests, "post", side_effect=fake_post):
        result = json.loads(sqli_login_tool.invoke({"base_url": "http://localhost:3000"}))

    assert result["verdict"] == "ОК"
    assert result["status"] == 401
    assert result["body"] == "invalid credentials"


def test_sqli_login_uses_custom_endpoint_and_payload():
    def fake_post(url, **kwargs):
        assert url == "http://localhost:3000/custom/login"
        assert kwargs["json"] == {"email": "custom@example.test", "password": "custom"}
        return SimpleNamespace(status_code=401, text="Invalid credentials")

    with patch.object(requests, "post", side_effect=fake_post):
        result = json.loads(
            sqli_login_tool.invoke(
                {
                    "base_url": "http://localhost:3000",
                    "endpoint": "/custom/login",
                    "email_payload": "custom@example.test",
                    "password_payload": "custom",
                }
            )
        )

    assert result["url"] == "http://localhost:3000/custom/login"
    assert result["payload"] == {
        "email": "custom@example.test",
        "password": "custom",
    }
    assert result["verdict"] == "ОК"


@pytest.mark.parametrize(
    ("status", "body", "expected_sign"),
    [
        (200, '{"token":"sample"}', "получен токен аутентификации"),
        (200, '{"authentication":"sample"}', "получен токен аутентификации"),
        (500, "SQL syntax error", "внутренняя ошибка"),
        (400, "SQL SYNTAX error", "SQL-ошибки: sql syntax"),
    ],
)
def test_sqli_login_reports_suspicious_response(status, body, expected_sign):
    with patch.object(
        requests, "post", return_value=SimpleNamespace(status_code=status, text=body)
    ):
        result = json.loads(sqli_login_tool.invoke({"base_url": "http://localhost:3000"}))

    assert result["verdict"] == "уязвимо"
    assert result["status"] == status
    assert expected_sign in result["sign"]


def test_sqli_login_reports_timeout():
    def fake_post(*args, **kwargs):
        raise requests.exceptions.Timeout()

    with patch.object(requests, "post", side_effect=fake_post):
        result = sqli_login_tool.invoke({"base_url": "http://localhost:3000"})

    assert result == "таймаут при запросе"


def test_sqli_login_reports_connection_error():
    def fake_post(*args, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    with patch.object(requests, "post", side_effect=fake_post):
        result = sqli_login_tool.invoke({"base_url": "http://localhost:3000"})

    assert result == "не удалось подключиться к http://localhost:3000/rest/user/login"


def test_nuclei_uses_default_command_and_parses_json_lines():
    output = '\n'.join([
        '{"template-id":"first","info":{"severity":"high"}}',
        'not json',
        '',
        '{"template-id":"second"}',
    ])
    with patch.object(
        subprocess, "run",
        return_value=SimpleNamespace(returncode=0, stdout=output, stderr=""),
    ) as run:
        result = json.loads(run_nuclei.invoke({"target_url": "http://example.test"}))

    run.assert_called_once_with(
        ["nuclei", "-u", "http://example.test", "-jsonl", "-silent"],
        capture_output=True, text=True, timeout=300,
    )
    assert result == [
        {"template-id": "first", "info": {"severity": "high"}},
        {"template-id": "second"},
    ]


def test_nuclei_passes_templates_and_severity():
    with patch.object(
        subprocess, "run",
        return_value=SimpleNamespace(returncode=1, stdout='{"id":"finding"}', stderr=""),
    ) as run:
        result = json.loads(run_nuclei.invoke({
            "target_url": "http://example.test",
            "templates": "custom-templates",
            "severity": "high,critical",
        }))

    run.assert_called_once_with(
        ["nuclei", "-u", "http://example.test", "-jsonl", "-silent",
         "-t", "custom-templates", "-severity", "high,critical"],
        capture_output=True, text=True, timeout=300,
    )
    assert result == [{"id": "finding"}]


@pytest.mark.parametrize("stdout", ["", "invalid json\n  "])
def test_nuclei_reports_no_findings(stdout):
    with patch.object(
        subprocess, "run",
        return_value=SimpleNamespace(returncode=0, stdout=stdout, stderr=""),
    ):
        result = run_nuclei.invoke({"target_url": "http://example.test"})

    assert result == "находок не обнаружено"


def test_nuclei_reports_process_failure():
    with patch.object(
        subprocess, "run",
        return_value=SimpleNamespace(returncode=2, stdout="", stderr="invalid option\n"),
    ):
        result = run_nuclei.invoke({"target_url": "http://example.test"})

    assert result == "ошибка запуска nuclei: invalid option"


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (subprocess.TimeoutExpired("nuclei", 300), "Error: таймаут выполнения nuclei"),
        (FileNotFoundError("nuclei"), "Error: nuclei не установлен или не найден в PATH"),
        (OSError("cannot start"), "ошибка запроса cannot start"),
    ],
)
def test_nuclei_reports_execution_errors(error, message):
    with patch.object(subprocess, "run", side_effect=error):
        result = run_nuclei.invoke({"target_url": "http://example.test"})

    assert result == message


@pytest.fixture
def zap_report_dir(tmp_path):
    report_dir = tmp_path / "reports"
    fake_path = SimpleNamespace(
        abspath=lambda path: str(report_dir),
        join=os.path.join,
        exists=os.path.exists,
    )
    fake_os = SimpleNamespace(path=fake_path, makedirs=os.makedirs)
    with patch.object(zap_module, "os", fake_os):
        yield report_dir


def test_zap_rejects_unknown_mode_before_running_docker():
    with patch.object(subprocess, "run") as run:
        result = run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "unknown",
        })

    assert result == "нет режима unknown"
    run.assert_not_called()


@pytest.mark.parametrize(
    ("mode", "script"),
    [
        ("baseline", "zap-baseline.py"),
        (" FULL ", "zap-full-scan.py"),
        ("api", "zap-api-scan.py"),
    ],
)
def test_zap_uses_selected_mode_and_summarizes_alerts(zap_report_dir, mode, script):
    target = "http://example.test"
    report = {"site": [{"alerts": [{
        "alert": "SQL Injection", "riskdesc": "High", "confidence": "Medium",
        "desc": "d" * 205, "solution": "s" * 205,
        "instances": [
            {"uri": target + "/login", "method": "POST", "param": "email", "evidence": "e" * 205},
            {"uri": target + "/other"},
        ],
    }]}]}

    def fake_run(command, **kwargs):
        if command == ["docker", "info"]:
            assert kwargs == {"capture_output": True, "text": True, "timeout": 5}
            return SimpleNamespace(returncode=0)
        assert command == [
            "docker", "run", "--rm", "--user", "root", "--network", "host",
            "-v", f"{zap_report_dir}:/zap/wrk/:rw", "zaproxy/zap-stable",
            script, "-t", target, "-J", "zap_report.json",
            "-r", "zap_report.html", "-I",
        ]
        assert kwargs == {"capture_output": True, "text": True, "timeout": 1800}
        (zap_report_dir / "zap_report.json").write_text(json.dumps(report), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run) as run:
        result = json.loads(run_zap_scan.invoke({"target_url": target, "scan_mode": mode}))

    assert run.call_count == 2
    assert result == {
        "scan_mode": mode.lower().strip(),
        "target_url": target,
        "total_alerts": 1,
        "alerts": [{
            "alert": "SQL Injection", "risk": "High", "confidence": "Medium",
            "url": target + "/login", "method": "POST", "param": "email",
            "evidence": "e" * 200, "description": "d" * 200,
            "solution": "s" * 200, "instances_count": 2,
        }],
        "reports": {
            "json": str(zap_report_dir / "zap_report.json"),
            "html": str(zap_report_dir / "zap_report.html"),
        },
    }


def test_zap_reports_docker_not_running(zap_report_dir):
    with patch.object(
        subprocess, "run", return_value=SimpleNamespace(returncode=1)
    ) as run:
        result = run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "baseline",
        })

    assert result == "Docker не запущен"
    run.assert_called_once_with(
        ["docker", "info"], capture_output=True, text=True, timeout=5,
    )


def test_zap_reports_docker_check_exception(zap_report_dir):
    with patch.object(subprocess, "run", side_effect=FileNotFoundError("docker")):
        result = run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "baseline",
        })

    assert result == "ошибка проверки Docker docker"


def test_zap_reports_scan_exception(zap_report_dir):
    with patch.object(subprocess, "run", side_effect=[
        SimpleNamespace(returncode=0), subprocess.TimeoutExpired("docker", 1800),
    ]):
        result = run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "baseline",
        })

    assert "возникла ошибка:" in result
    assert "timed out" in result


def test_zap_reports_missing_report(zap_report_dir):
    with patch.object(subprocess, "run", side_effect=[
        SimpleNamespace(returncode=0),
        SimpleNamespace(returncode=0, stdout="", stderr=""),
    ]):
        result = run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "baseline",
        })

    assert result == f"ZAP: отчёт не создан: {zap_report_dir / 'zap_report.json'}"


@pytest.mark.parametrize(
    ("report_text", "message"),
    [("not json", "при чтении json возникла ошибка"),
     ('{"site": []}', "алертов не найдено")],
)
def test_zap_handles_invalid_or_empty_report(zap_report_dir, report_text, message):
    def fake_run(command, **kwargs):
        if command == ["docker", "info"]:
            return SimpleNamespace(returncode=0)
        (zap_report_dir / "zap_report.json").write_text(report_text, encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run):
        result = run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "baseline",
        })

    assert message in result


def test_zap_limits_returned_alerts_to_thirty(zap_report_dir):
    report = {"site": [{"alerts": [
        {"alert": f"alert-{number}"} for number in range(31)
    ]}]}

    def fake_run(command, **kwargs):
        if command == ["docker", "info"]:
            return SimpleNamespace(returncode=0)
        (zap_report_dir / "zap_report.json").write_text(json.dumps(report), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run):
        result = json.loads(run_zap_scan.invoke({
            "target_url": "http://example.test", "scan_mode": "baseline",
        }))

    assert result["total_alerts"] == 31
    assert len(result["alerts"]) == 30
    assert result["alerts"][-1]["alert"] == "alert-29"
    assert result["alerts"][0]["instances_count"] == 0


def test_list_files_returns_sorted_files_and_total(tmp_path):
    (tmp_path / "z_last.py").write_text("last", encoding="utf-8")
    (tmp_path / "a_first.py").write_text("first", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "child.py").write_text("child", encoding="utf-8")

    result = list_files.invoke({"path": str(tmp_path)})

    assert result.startswith(f"Каталог {tmp_path} — 3 файлов:\n")
    assert f"{tmp_path.name}/" in result
    assert "nested/" in result
    assert "child.py" in result
    assert result.index("a_first.py") < result.index("z_last.py")


@pytest.mark.parametrize(
    "directory", [".git", "__pycache__", ".venv", "venv", "node_modules"]
)
def test_list_files_ignores_generated_and_dependency_directories(tmp_path, directory):
    ignored = tmp_path / directory / "nested"
    ignored.mkdir(parents=True)
    (ignored / "hidden_file.py").write_text("hidden", encoding="utf-8")
    (tmp_path / "visible.py").write_text("visible", encoding="utf-8")

    result = list_files.invoke({"path": str(tmp_path)})

    assert result.startswith(f"Каталог {tmp_path} — 1 файлов:\n")
    assert "visible.py" in result
    assert f"{directory}/" not in result
    assert "hidden_file.py" not in result


def test_list_files_reports_missing_path(tmp_path):
    missing = tmp_path / "missing"

    result = list_files.invoke({"path": str(missing)})

    assert result == f"не найден путь: {missing}"


def test_list_files_rejects_file_path(tmp_path):
    source = tmp_path / "example.py"
    source.write_text("sample", encoding="utf-8")

    result = list_files.invoke({"path": str(source)})

    assert result == f"это не каталог: {source}"


def test_list_files_reports_empty_directory(tmp_path):
    result = list_files.invoke({"path": str(tmp_path)})

    assert result == f"в {tmp_path} нет файлов"


@pytest.mark.xfail(
    os.name == "nt",
    strict=True,
    raises=AssertionError,
    reason="list_files counts only forward slashes when calculating directory depth",
)
def test_list_files_respects_max_depth(tmp_path):
    (tmp_path / "root.py").write_text("root", encoding="utf-8")
    child = tmp_path / "child"
    child.mkdir()
    (child / "included.py").write_text("included", encoding="utf-8")
    grandchild = child / "grandchild"
    grandchild.mkdir()
    (grandchild / "excluded.py").write_text("excluded", encoding="utf-8")

    result = list_files.invoke({"path": str(tmp_path), "max_depth": 1})

    assert "excluded.py" not in result
    assert "grandchild/" not in result
    assert result.startswith(f"Каталог {tmp_path} — 2 файлов:\n")
    assert "root.py" in result
    assert "included.py" in result


def test_sqli_lab_get_uses_default_parameter_and_reports_neutral_response():
    with patch.object(
        sqli_lab_module.requests, "get",
        return_value=SimpleNamespace(status_code=200, text="No matching user"),
    ) as get, patch.object(sqli_lab_module.requests, "post") as post:
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/check_user",
            "payload": "1 OR 1=1",
        })

    get.assert_called_once_with(
        "http://example.test/api/check_user", params={"q": "1 OR 1=1"}, timeout=30,
    )
    post.assert_not_called()
    assert result == (
        "URL: http://example.test/api/check_user\n"
        "payload: 1 OR 1=1\n"
        "status: 200\n"
        "вердикт: ОК\n"
        "indicators: []\n"
        "body: No matching user"
    )


def test_sqli_lab_post_uses_custom_parameter_and_accepts_lowercase_method():
    payload = "admin' --"
    with patch.object(
        sqli_lab_module.requests, "post",
        return_value=SimpleNamespace(status_code=401, text="Invalid credentials"),
    ) as post, patch.object(sqli_lab_module.requests, "get") as get:
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/login",
            "payload": payload, "param": "username", "method": "post",
        })

    post.assert_called_once_with(
        "http://example.test/api/login", json={"username": payload}, timeout=30,
    )
    get.assert_not_called()
    assert "status: 401\n" in result
    assert "вердикт: ОК\n" in result


@pytest.mark.parametrize(
    ("status", "body", "indicator"),
    [
        (200, '{"status": "OK"}', "auth bypass status OK"),
        (500, "SQL Syntax ERROR", "SQL-ошибка в ответе"),
        (200, "FLAG{test-secret-value}", "утечка секрета (FLAG)"),
        (200, "SECRET value exposed", "утечка secrets"),
    ],
)
def test_sqli_lab_reports_sqli_indicators(status, body, indicator):
    with patch.object(
        sqli_lab_module.requests, "get",
        return_value=SimpleNamespace(status_code=status, text=body),
    ):
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/check_user",
            "payload": "1'", "param": "id",
        })

    assert "вердикт: SQLi ПОДТВЕРЖДЁН\n" in result
    assert indicator in result.split("indicators: ", 1)[1].split("\n", 1)[0]
    assert f"status: {status}\n" in result
    assert result.endswith(f"body: {body}")


def test_sqli_lab_collects_all_indicators():
    body = '{"status": "OK", "error": "SQL", "secret": "FLAG{sample}"}'
    with patch.object(
        sqli_lab_module.requests, "get",
        return_value=SimpleNamespace(status_code=200, text=body),
    ):
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/login",
            "payload": "1'",
        })

    assert (
        "indicators: ['auth bypass status OK', 'SQL-ошибка в ответе', "
        "'утечка секрета (FLAG)', 'утечка secrets']\n"
    ) in result


@pytest.mark.parametrize(
    ("status", "body"),
    [(401, '{"status": "OK"}'), (200, "SQL query completed"), (500, "Internal error")],
)
def test_sqli_lab_does_not_flag_responses_without_matching_indicators(status, body):
    with patch.object(
        sqli_lab_module.requests, "get",
        return_value=SimpleNamespace(status_code=status, text=body),
    ):
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/check_user",
            "payload": "1",
        })

    assert "вердикт: ОК\n" in result
    assert "indicators: []\n" in result


@pytest.mark.parametrize("body", [None, ""])
def test_sqli_lab_handles_empty_response_body(body):
    with patch.object(
        sqli_lab_module.requests, "get",
        return_value=SimpleNamespace(status_code=204, text=body),
    ):
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/check_user",
            "payload": "1",
        })

    assert result.endswith("body: ")
    assert "вердикт: ОК\n" in result


def test_sqli_lab_limits_response_body_to_fifteen_hundred_characters():
    body = "x" * 1500 + "END"
    with patch.object(
        sqli_lab_module.requests, "get",
        return_value=SimpleNamespace(status_code=200, text=body),
    ):
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/check_user",
            "payload": "1",
        })

    assert result.split("body: ", 1)[1] == "x" * 1500


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize(
    "error",
    [requests.exceptions.Timeout("request timed out"),
     requests.exceptions.ConnectionError("connection refused")],
)
def test_sqli_lab_reports_request_errors(method, error):
    request_name = method.lower()
    with patch.object(sqli_lab_module.requests, request_name, side_effect=error):
        result = sqli_lab_tool.invoke({
            "base_url": "http://example.test", "endpoint": "/api/check_user",
            "payload": "1'", "method": method,
        })

    assert result == f"ошибка: {error}"
