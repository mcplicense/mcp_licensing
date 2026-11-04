"""docs/login-api.md: the minimal client in it really signs up, confirms, logs in and calls the console against
the real handlers (through scripts/dev_server.py, a separate process with its own in-memory AWS), and the page
states what the code enforces."""
import json
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "login-api.md"


def client_source():
    text = DOC.read_text(encoding="utf-8")
    block = re.search(r"<!-- example:login-client -->\n```javascript\n(.*?)\n```", text, re.S)
    assert block, "the login client example is missing from docs/login-api.md"
    return block.group(1)


def test_the_client_uses_the_documented_routes_header_and_credentials():
    from handlers import portal
    source = client_source()
    assert '"X-Requested-With": "{}"'.format(portal.CSRF_VALUE) in source
    assert '"/v1/portal/"' in source and '"/v1/console/"' in source
    assert 'credentials: "same-origin"' in source
    for route in ("login", "refresh"):
        assert 'portal("{}"'.format(route) in source
    assert not re.search(r"(local|session)Storage\.|document\.cookie|innerHTML", source)


@pytest.mark.skipif(not shutil.which("node"), reason="needs Node 18 or later")
def test_the_client_signs_up_confirms_logs_in_and_calls_the_console(tmp_path):
    (tmp_path / "pages").mkdir()
    (tmp_path / "pages" / "index.html").write_text("<!doctype html><title>x</title>", encoding="utf-8")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = subprocess.Popen([sys.executable, "-I", str(ROOT / "scripts" / "dev_server.py"), "--port", str(port),
                               "--dir", str(tmp_path / "pages")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    base = "http://127.0.0.1:{}".format(port)
    try:
        for _ in range(150):
            try:
                urllib.request.urlopen(base + "/__dev/codes", timeout=1).read()
                break
            except OSError:
                if server.poll() is not None:
                    pytest.fail("dev_server exited: " + server.stderr.read())
                time.sleep(0.2)
        else:
            pytest.fail("dev_server did not start")

        driver = client_source().replace('const BASE = "";', 'const BASE = "{}";'.format(base), 1) + """
const email = "jane@example.com";
const password = "Correct-Horse-9";
await portal("signup", { email, password, company_name: "Acme Tools", accept_terms: true });
const codes = await (await fetch(BASE + "/__dev/codes")).json();
await portal("confirm", { email, code: codes.filter((c) => c.email === email).at(-1).code });
const session = await login(email, password);
const tenant = await api("GET", "tenant");
let denied = null;
try { idToken = "not-a-token"; await api("GET", "tenant"); } catch (e) { denied = e.status; }
console.log(JSON.stringify({ session_tenant: session.tenant_id, console_tenant: tenant.tenant_id, denied }));
process.exit(0);
"""
        script = tmp_path / "client.mjs"
        script.write_text(driver, encoding="utf-8")
        result = subprocess.run(["node", str(script)], capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        out = json.loads(result.stdout.strip().splitlines()[-1])
        assert re.fullmatch(r"mcp-[a-z0-9]{6}", out["session_tenant"])
        assert out["console_tenant"] == out["session_tenant"]
        assert out["denied"] == 401
    finally:
        server.terminate()
        server.wait(timeout=10)
