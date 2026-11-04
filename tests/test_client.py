import time

import pytest

import mcp_auth
from helpers import create_license, create_tenant, verify as server_verify

URL = "https://licensing.example.test/prod"


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_auth, "STATE_DIR", str(tmp_path))
    monkeypatch.delenv("MCP_LICENSE_KEY", raising=False)
    monkeypatch.delenv("MCP_LICENSE_API_URL", raising=False)


@pytest.fixture
def licensed(super_key, monkeypatch):
    """A real license, with the client wired straight to the Lambda handler."""
    tenant = create_tenant(super_key)
    lic = create_license(tenant["admin_api_key"], seats_max=2)
    calls = {"n": 0, "down": False}

    def fake_post(url, license_key, dev_id):
        calls["n"] += 1
        if calls["down"]:
            raise OSError("network down")
        return server_verify(license_key, dev_id)

    monkeypatch.setattr(mcp_auth, "_post_verify", fake_post)
    return lic["license_key"], calls, tenant


def test_success_then_served_from_cache(licensed):
    key, calls, _ = licensed
    first = mcp_auth.verify(key, URL)
    assert first.valid and not first.from_cache
    second = mcp_auth.verify(key, URL)
    assert second.valid and second.from_cache
    assert calls["n"] == 1


def test_offline_grace_after_a_success(licensed, monkeypatch):
    key, calls, _ = licensed
    mcp_auth.verify(key, URL)
    cache = mcp_auth._read_json("cache.json")
    cache["fresh_until"] = time.time() - 1  # force a re-check
    mcp_auth._write_json("cache.json", cache)
    calls["down"] = True
    result = mcp_auth.verify(key, URL)
    assert result.valid and result.offline


def test_offline_grace_ends_when_the_server_lease_ends(licensed):
    """The server frees the seat at lease_expires_at, so the client must stop then."""
    key, calls, _ = licensed
    result = mcp_auth.verify(key, URL)
    cache = mcp_auth._read_json("cache.json")
    assert cache["grace_until"] == pytest.approx(time.time() + 86400, abs=5)  # default 24h lease
    assert cache["fresh_until"] < cache["grace_until"]
    assert result.valid


def test_offline_without_history_or_past_grace_fails(licensed):
    key, calls, _ = licensed
    calls["down"] = True
    with pytest.raises(mcp_auth.LicenseError) as exc:
        mcp_auth.verify(key, URL)
    assert exc.value.reason == "UNREACHABLE"

    calls["down"] = False
    mcp_auth.verify(key, URL)
    cache = mcp_auth._read_json("cache.json")
    cache.update(fresh_until=time.time() - 1, grace_until=time.time() - 1)
    mcp_auth._write_json("cache.json", cache)
    calls["down"] = True
    with pytest.raises(mcp_auth.LicenseError):
        mcp_auth.verify(key, URL)


def test_explicit_denial_beats_cache_and_grace(licensed, super_key):
    from helpers import call
    key, calls, _ = licensed
    mcp_auth.verify(key, URL)  # cached success
    call("PUT /v1/super/kill-switch", {"enabled": True}, key=super_key)
    cache = mcp_auth._read_json("cache.json")
    cache["fresh_until"] = time.time() - 1
    mcp_auth._write_json("cache.json", cache)
    with pytest.raises(mcp_auth.LicenseError) as exc:
        mcp_auth.verify(key, URL)
    assert exc.value.reason == "GLOBAL_DISABLED"
    assert mcp_auth._read_json("cache.json") is None

    # even if the network then drops, the cleared cache means no grace
    calls["down"] = True
    with pytest.raises(mcp_auth.LicenseError):
        mcp_auth.verify(key, URL)


def test_rate_limited_is_not_a_denial(licensed, monkeypatch):
    """429 RATE_LIMITED means "try again", so a licensed tool keeps running on
    its grace window and the cached success is not thrown away."""
    key, calls, _ = licensed
    mcp_auth.verify(key, URL)
    cache = mcp_auth._read_json("cache.json")
    cache["fresh_until"] = time.time() - 1  # force a re-check
    mcp_auth._write_json("cache.json", cache)

    monkeypatch.setattr(mcp_auth, "_post_verify", lambda *a: (
        429, {"valid": False, "reason": "RATE_LIMITED", "retry_after_seconds": 30}))
    result = mcp_auth.verify(key, URL)
    assert result.valid and result.offline
    assert mcp_auth._read_json("cache.json") is not None

    # with no earlier success there is nothing to fall back on
    mcp_auth._clear_cache()
    with pytest.raises(mcp_auth.LicenseError) as exc:
        mcp_auth.verify(key, URL)
    assert exc.value.reason == "UNREACHABLE"


@pytest.mark.parametrize("status,body", [
    (403, {}),                                                    # WAF block page, not JSON
    (403, {"error": {"code": "FORBIDDEN", "message": "Forbidden."}}),  # origin check
    (401, {"message": "Unauthorized"}),
])
def test_a_block_that_is_not_a_license_decision_keeps_the_cache(licensed, monkeypatch, status, body):
    key, calls, _ = licensed
    mcp_auth.verify(key, URL)
    cache = mcp_auth._read_json("cache.json")
    cache["fresh_until"] = time.time() - 1
    mcp_auth._write_json("cache.json", cache)

    monkeypatch.setattr(mcp_auth, "_post_verify", lambda *a: (status, body))
    result = mcp_auth.verify(key, URL)
    assert result.valid and result.offline
    assert mcp_auth._read_json("cache.json") is not None


def test_cache_is_bound_to_the_key(licensed):
    key, calls, _ = licensed
    mcp_auth.verify(key, URL)
    other = "acme_AAAAA-AAAAA-AAAAA-AAAAA-AAAAA"
    with pytest.raises(mcp_auth.LicenseError) as exc:
        mcp_auth.verify(other, URL)
    assert exc.value.reason == "INVALID_KEY"


def test_cache_file_does_not_contain_the_key(licensed, tmp_path):
    key, _, _ = licensed
    mcp_auth.verify(key, URL)
    assert key not in (tmp_path / "cache.json").read_text()


def test_key_sources(monkeypatch):
    assert mcp_auth.get_license_key(["--license-key", "abc"]) == "abc"
    assert mcp_auth.get_license_key(["--license-key=abc"]) == "abc"
    monkeypatch.setenv("MCP_LICENSE_KEY", "from-env")
    assert mcp_auth.get_license_key([]) == "from-env"
    monkeypatch.delenv("MCP_LICENSE_KEY")
    assert mcp_auth.get_license_key([]) is None
    with pytest.raises(mcp_auth.LicenseError) as exc:
        mcp_auth.verify(None, URL)
    assert exc.value.reason == "NO_KEY"


def test_url_must_be_configured_and_https():
    with pytest.raises(mcp_auth.LicenseError) as exc:
        mcp_auth.verify("k", None)
    assert exc.value.reason == "NOT_CONFIGURED"
    with pytest.raises(mcp_auth.LicenseError):
        mcp_auth.verify("k", "http://licensing.example.test")


def test_device_id_is_stable():
    assert mcp_auth.device_id() == mcp_auth.device_id()


def test_require_license_exits_with_message(capsys):
    with pytest.raises(SystemExit) as exc:
        mcp_auth.require_license("k", None)
    assert exc.value.code == 2
    assert "License check failed" in capsys.readouterr().err
