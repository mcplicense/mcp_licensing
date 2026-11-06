import time

import pytest

import mcp_auth
from helpers import create_license, create_tenant, verify as server_verify

URL = "https://licensing.example.test/prod"


SLEPT = []


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_auth, "STATE_DIR", str(tmp_path))
    monkeypatch.delenv("MCP_LICENSE_KEY", raising=False)
    monkeypatch.delenv("MCP_LICENSE_API_URL", raising=False)
    for name in ("MCP_LICENSE_TIMEOUT", "MCP_LICENSE_RETRIES", "MCP_LICENSE_DEADLINE"):
        monkeypatch.delenv(name, raising=False)
    SLEPT.clear()
    monkeypatch.setattr(mcp_auth, "_sleep", lambda seconds: SLEPT.append(seconds))  # recorded, not waited for


@pytest.fixture
def licensed(super_key, monkeypatch):
    """A real license, with the client wired straight to the Lambda handler."""
    tenant = create_tenant(super_key)
    lic = create_license(tenant["admin_api_key"], seats_max=2)
    calls = {"n": 0, "down": False}

    def fake_post(url, license_key, dev_id, timeout=None):
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

    monkeypatch.setattr(mcp_auth, "_post_verify", lambda *a, **k: (
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

    monkeypatch.setattr(mcp_auth, "_post_verify", lambda *a, **k: (status, body))
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


# ----------------------------------------- timeout, retries and deadline (the first call after idle can be slow)

def good_answer():
    return 200, {"valid": True, "reason": "OK", "cache_ttl_seconds": 300, "lease_expires_at": time.time() + 3600,
                 "seats_used": 1, "seats_max": 2, "expires_at": "2030-01-01"}


def script(monkeypatch, answers):
    """_post_verify answers from a list (an exception is raised, the last answer repeats); returns the timeouts used."""
    timeouts = []

    def fake(url, license_key, dev_id, timeout=None):
        timeouts.append(timeout)
        answer = answers[min(len(timeouts) - 1, len(answers) - 1)]
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(mcp_auth, "_post_verify", fake)
    return timeouts


def test_the_defaults_are_9_seconds_5_retries_and_a_45_second_deadline():
    assert mcp_auth.timing() == (9, 5, 45)


def test_environment_overrides_and_zero_retries_is_a_real_value(monkeypatch):
    monkeypatch.setenv("MCP_LICENSE_TIMEOUT", "4.5")
    monkeypatch.setenv("MCP_LICENSE_RETRIES", "0")
    monkeypatch.setenv("MCP_LICENSE_DEADLINE", "20")
    assert mcp_auth.timing() == (4.5, 0, 20)


def test_the_constants_are_the_defaults_a_distributor_can_set(monkeypatch):
    monkeypatch.setattr(mcp_auth, "TIMEOUT_SECONDS", 6)
    monkeypatch.setattr(mcp_auth, "RETRIES", 0)
    monkeypatch.setattr(mcp_auth, "DEADLINE_SECONDS", 30)
    assert mcp_auth.timing() == (6, 0, 30)
    monkeypatch.setenv("MCP_LICENSE_RETRIES", "2")  # the environment still wins
    assert mcp_auth.timing() == (6, 2, 30)


@pytest.mark.parametrize("name,value,index,default", [
    ("MCP_LICENSE_TIMEOUT", "abc", 0, 9), ("MCP_LICENSE_TIMEOUT", "0", 0, 9), ("MCP_LICENSE_TIMEOUT", "99", 0, 9),
    ("MCP_LICENSE_TIMEOUT", "nan", 0, 9), ("MCP_LICENSE_RETRIES", "many", 1, 5), ("MCP_LICENSE_RETRIES", "-1", 1, 5),
    ("MCP_LICENSE_RETRIES", "11", 1, 5), ("MCP_LICENSE_DEADLINE", "1", 2, 45), ("MCP_LICENSE_DEADLINE", "500", 2, 45),
])
def test_a_bad_value_falls_back_to_the_default(monkeypatch, name, value, index, default):
    monkeypatch.setenv(name, value)
    assert mcp_auth.timing()[index] == default


def test_the_post_gets_the_configured_timeout(monkeypatch):
    timeouts = script(monkeypatch, [good_answer()])
    mcp_auth.verify("k", URL)
    assert timeouts == [9]
    mcp_auth._clear_cache()
    monkeypatch.setenv("MCP_LICENSE_TIMEOUT", "3")
    mcp_auth.verify("k", URL)
    assert timeouts == [9, 3]


def test_a_slow_first_call_that_gives_no_answer_is_retried(monkeypatch):
    """The cold start: nothing comes back in time, then the service answers."""
    timeouts = script(monkeypatch, [OSError("timed out"), OSError("timed out"), good_answer()])
    result = mcp_auth.verify("k", URL)
    assert result.valid and not result.offline
    assert len(timeouts) == 3 and SLEPT == [0.5, 1]


def test_a_5xx_and_a_429_are_retried_and_the_429_names_its_pause(monkeypatch):
    timeouts = script(monkeypatch, [(503, {"message": "Service Unavailable"}),
                                    (429, {"valid": False, "reason": "RATE_LIMITED", "retry_after_seconds": 3}),
                                    good_answer()])
    assert mcp_auth.verify("k", URL).valid
    assert len(timeouts) == 3 and SLEPT == [0.5, 3]


def test_a_429_pause_is_capped(monkeypatch):
    script(monkeypatch, [(429, {"retry_after_seconds": 600}), good_answer()])
    mcp_auth.verify("k", URL)
    assert SLEPT == [mcp_auth.RETRY_AFTER_CAP_SECONDS]


@pytest.mark.parametrize("answer", [
    (403, {"valid": False, "reason": "LICENSE_REVOKED", "message": "revoked"}),
    (401, {"valid": False, "reason": "INVALID_KEY", "message": "bad"}),
])
def test_a_decision_is_final_and_asked_once(monkeypatch, answer):
    timeouts = script(monkeypatch, [answer])
    with pytest.raises(mcp_auth.LicenseError):
        mcp_auth.verify("k", URL)
    assert len(timeouts) == 1 and SLEPT == []


@pytest.mark.parametrize("answer", [(400, {}), (404, {}), (403, {"message": "Forbidden"})])
def test_an_answer_that_trying_again_cannot_change_is_asked_once(monkeypatch, answer):
    timeouts = script(monkeypatch, [answer])
    with pytest.raises(mcp_auth.LicenseError) as exc:
        mcp_auth.verify("k", URL)
    assert exc.value.reason == "UNREACHABLE" and len(timeouts) == 1 and SLEPT == []


@pytest.mark.parametrize("retries,calls", [("0", 1), ("2", 3), ("5", 6), ("10", 11)])
def test_every_retry_is_used_before_giving_up(monkeypatch, retries, calls):
    monkeypatch.setenv("MCP_LICENSE_RETRIES", retries)
    monkeypatch.setenv("MCP_LICENSE_DEADLINE", "120")
    timeouts = script(monkeypatch, [OSError("down")])
    with pytest.raises(mcp_auth.LicenseError) as exc:
        mcp_auth.verify("k", URL)
    assert exc.value.reason == "UNREACHABLE" and len(timeouts) == calls


def test_the_pauses_grow_then_stop_growing(monkeypatch):
    script(monkeypatch, [OSError("down")])
    with pytest.raises(mcp_auth.LicenseError):
        mcp_auth.verify("k", URL)
    assert SLEPT == [0.5, 1, 2, 4, 4]


def test_the_deadline_stops_the_tries_and_shortens_the_last_wait(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(mcp_auth, "_monotonic", lambda: now[0])
    monkeypatch.setattr(mcp_auth, "_sleep", lambda s: (SLEPT.append(s), now.__setitem__(0, now[0] + s)))
    monkeypatch.setenv("MCP_LICENSE_RETRIES", "10")
    monkeypatch.setenv("MCP_LICENSE_DEADLINE", "5")
    timeouts = script(monkeypatch, [OSError("down")])
    with pytest.raises(mcp_auth.LicenseError):
        mcp_auth.verify("k", URL)
    assert len(timeouts) == 4 and SLEPT == [0.5, 1, 2]
    assert timeouts[0] == 5  # one try may not outlast the deadline either (timeout 9 > deadline 5)
    assert now[0] - 100.0 <= 5


def test_with_an_offline_grace_window_it_asks_once_and_does_not_wait(licensed, monkeypatch):
    key, calls, _ = licensed
    mcp_auth.verify(key, URL)
    cache = mcp_auth._read_json("cache.json")
    cache["fresh_until"] = time.time() - 1  # a re-check is due, the grace window is still open
    mcp_auth._write_json("cache.json", cache)
    timeouts = script(monkeypatch, [OSError("down")])
    result = mcp_auth.verify(key, URL)
    assert result.valid and result.offline
    assert len(timeouts) == 1 and SLEPT == []


def test_without_a_grace_window_it_retries(licensed, monkeypatch):
    key, calls, _ = licensed
    timeouts = script(monkeypatch, [OSError("down")])  # nothing cached: there is nothing to fall back on
    with pytest.raises(mcp_auth.LicenseError) as exc:
        mcp_auth.verify(key, URL)
    assert exc.value.reason == "UNREACHABLE" and len(timeouts) == 6


def test_one_try_is_bounded_by_the_timeout_in_real_time(monkeypatch):
    """urlopen's timeout is per socket step and per address: a try that hangs must still end at the timeout."""
    monkeypatch.setattr(mcp_auth.urllib.request, "urlopen", lambda req, timeout=None: time.sleep(3))
    monkeypatch.setenv("MCP_LICENSE_TIMEOUT", "1")
    started = time.time()
    with pytest.raises(OSError):
        mcp_auth._post_verify("https://x.test", "k", "d")
    assert time.time() - started < 2


def test_a_hanging_service_ends_as_unreachable(monkeypatch):
    monkeypatch.setattr(mcp_auth.urllib.request, "urlopen", lambda req, timeout=None: time.sleep(3))
    monkeypatch.setenv("MCP_LICENSE_TIMEOUT", "1")
    monkeypatch.setenv("MCP_LICENSE_RETRIES", "1")
    started = time.time()
    with pytest.raises(mcp_auth.LicenseError) as exc:
        mcp_auth.verify("k", URL)
    assert exc.value.reason == "UNREACHABLE" and time.time() - started < 4
