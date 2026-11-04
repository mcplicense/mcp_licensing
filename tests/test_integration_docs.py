"""docs/integration.md: the license-check documentation agrees with the service, and its Python and Node
examples really run against a stub of the API, including the failure cases."""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core import config

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "integration.md"


def doc():
    return DOC.read_text(encoding="utf-8")


def example(name):
    block = re.search(r"<!-- example:{} -->\n```\w*\n(.*?)\n```".format(re.escape(name)), doc(), re.S)
    assert block, name
    return block.group(1)


# ------------------------------------------------------------- the docs agree with the code

def test_documented_limits_match_the_defaults_in_the_code():
    text, d = doc(), config.DEFAULTS
    assert "| Active licenses | {} |".format(d["limit_licenses_per_tenant"]) in text
    assert "| Seats per license | {} |".format(d["limit_seats_per_license"]) in text
    assert "| Seats across all active licenses | {} |".format(d["limit_seats_per_tenant"]) in text
    assert "| Active admin API keys | {} |".format(d["limit_api_keys_per_tenant"]) in text
    assert "| Verify requests per minute, per tenant | {} (more get".format(d["limit_verify_per_min"]) in text
    assert d["default_lease_duration_sec"] == "86400" and "24 hours" in text
    assert d["client_cache_ttl_seconds"] == "300" and "5 minutes" in text


def test_every_documented_response_field_is_really_returned():
    sample = json.loads(re.search(r'```json\n(\{\n  "valid": true.*?\n\})\n```', doc(), re.S).group(1))
    source = (ROOT / "src" / "handlers" / "mcp.py").read_text(encoding="utf-8")
    for field in sample:
        assert '"{}"'.format(field) in source, field


def test_every_documented_reason_code_exists_in_the_code():
    source = (ROOT / "src" / "handlers" / "mcp.py").read_text(encoding="utf-8")
    source += (ROOT / "src" / "core" / "service.py").read_text(encoding="utf-8")
    for reason in re.findall(r"\| \d{3} \| `([A-Z_]+)` \|", doc()):
        assert reason in source or reason in (ROOT / "src" / "core" / "http.py").read_text(encoding="utf-8"), reason


def test_the_public_url_is_the_same_everywhere():
    openapi = (ROOT / "docs" / "openapi-tenant.yaml").read_text(encoding="utf-8")
    assert "default: https://api.mcplicense.net" in openapi
    assert "https://api.mcplicense.net/v1/mcp/verify" in doc()


def test_the_mcp_server_examples_are_syntactically_valid():
    compile(example("mcp-python"), "mcp-python", "exec")
    json.loads(example("claude-desktop"))
    assert example("claude-code").startswith("claude mcp add ")
    assert 'require_license(api_url="https://api.mcplicense.net")' in example("mcp-python")
    if shutil.which("node"):
        with tempfile.TemporaryDirectory() as folder:
            script = pathlib.Path(folder) / "server.mjs"
            script.write_text("function checkLicense(){}\n" + example("mcp-node"), encoding="utf-8")
            result = subprocess.run(["node", "--check", str(script)], capture_output=True, text=True)
            assert result.returncode == 0, result.stderr


# ------------------------------------------------------ the examples really run

class Stub(BaseHTTPRequestHandler):
    requests = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Stub.requests.append({"path": self.path, "type": self.headers["Content-Type"], "body": body})
        key = body["license_key"]
        if key == "good":
            status, payload = 200, {"valid": True, "reason": "OK", "seats_used": 1, "seats_max": 1}
        elif key == "revoked":
            status, payload = 403, {"valid": False, "reason": "LICENSE_REVOKED",
                                    "message": "This license has been revoked."}
        elif key == "badkey":
            status, payload = 401, {"valid": False, "reason": "INVALID_KEY",
                                    "message": "License key is not valid."}
        elif key == "limited":
            status, payload = 429, {"valid": False, "reason": "RATE_LIMITED", "message": "slow down"}
        elif key == "waf":
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>Request blocked</html>")
            return
        else:
            status, payload = 500, {"error": {"code": "INTERNAL_ERROR"}}
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def stub():
    server = HTTPServer(("127.0.0.1", 0), Stub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:{}".format(server.server_port)
    server.shutdown()


def run_snippet(tmp_path, stub, language, license_key):
    source = example(language)
    assert 'API_URL = "https://api.mcplicense.net"' in source
    source = source.replace("https://api.mcplicense.net", stub)
    if language == "python":
        command, file = [sys.executable, "-I"], tmp_path / "check.py"
    else:
        command, file = ["node"], tmp_path / "check.mjs"
    file.write_text(source, encoding="utf-8")
    Stub.requests.clear()
    env = {"MCP_LICENSE_KEY": license_key, "PATH": os.environ["PATH"], "SystemRoot": os.environ.get("SystemRoot", "")}
    return subprocess.run(command + [str(file)], capture_output=True, text=True, timeout=60, env=env)


LANGUAGES = ["python"] + (["node"] if shutil.which("node") else [])


@pytest.mark.parametrize("language", LANGUAGES)
def test_example_accepts_a_valid_license_and_sends_the_documented_request(tmp_path, stub, language):
    result = run_snippet(tmp_path, stub, language, "good")
    assert result.returncode == 0, result.stderr
    assert "License OK" in result.stdout
    (request,) = Stub.requests
    assert request["path"] == "/v1/mcp/verify"
    assert request["type"] == "application/json"
    assert request["body"] == {"license_key": "good", "device_id": "my-device-id"}


@pytest.mark.parametrize("language", LANGUAGES)
@pytest.mark.parametrize("key,reason", [("revoked", "LICENSE_REVOKED"), ("badkey", "INVALID_KEY")])
def test_example_stops_on_a_decision_about_the_license(tmp_path, stub, language, key, reason):
    result = run_snippet(tmp_path, stub, language, key)
    assert result.returncode != 0
    assert "License check failed ({})".format(reason) in result.stderr
    assert "License OK" not in result.stdout


@pytest.mark.parametrize("language", LANGUAGES)
@pytest.mark.parametrize("key", ["limited", "waf", "boom"])
def test_example_does_not_mistake_a_failed_check_for_a_decision(tmp_path, stub, language, key):
    """A 429, a proxy block page and a 5xx mean "could not check": the example
    raises instead of printing a license verdict, so the tool can choose to keep running."""
    result = run_snippet(tmp_path, stub, language, key)
    assert result.returncode != 0
    assert "License check failed (" not in result.stderr
    assert "License OK" not in result.stdout
    assert "HTTPError" in result.stderr or "could not be made" in result.stderr


@pytest.mark.parametrize("language", LANGUAGES)
def test_example_fails_when_the_service_is_unreachable(tmp_path, language):
    result = run_snippet(tmp_path, "http://127.0.0.1:9", language, "good")
    assert result.returncode != 0 and "License OK" not in result.stdout
