"""mcp_auth - minimal client-side license check for MCP tools.

Standard library only. Python 3.8+.

    import mcp_auth
    mcp_auth.require_license()        # exits with a clear message when not licensed

The license key comes from --license-key or the MCP_LICENSE_KEY environment
variable. The API base URL comes from the MCP_LICENSE_API_URL environment
variable or the API_URL constant below (set it when you distribute the tool).

Timing (each is an environment variable, or the constant of the same name below it as the default):
  MCP_LICENSE_TIMEOUT   seconds to wait for one answer (default 9; 1 to 25). The first call after the service has
                        been idle can take a few seconds, so the default is generous.
  MCP_LICENSE_RETRIES   how many more times to ask when the service does not answer (default 5; 0 to 10)
  MCP_LICENSE_DEADLINE  the most seconds one check may take in all, tries and pauses included (default 45; 5 to 120).
                        Keep it under the time your host (a chat app, for example) gives a tool to start.
A bad value is ignored and the default is used. Only a missing answer is retried (a timeout, a network error, a 5xx, or
a 429 after the pause the service asks for): a decision is final. Asking twice is harmless, the same device only renews
its seat. When a recent success can still be honoured offline (see below) the check asks once and does not retry, so
an offline laptop starts at once.

Behaviour
  * A successful result is cached for the server's cache_ttl_seconds.
  * Every successful check renews the seat's lease. If the API is unreachable,
    a previous success is honoured only until the server's lease_expires_at:
    after that the server has already freed the seat for another device, so
    the tool must stop.
  * An explicit denial (401/403 carrying a license "reason") is final: the
    cache is cleared and the tool must not run. That is how the tenant and
    platform kill switches take effect.
  * Anything else is handled like a network failure, so the tool keeps running
    on its last success until lease_expires_at: 429 RATE_LIMITED (the tenant is
    over its requests per minute), a 5xx, and a 403 without a "reason" (a WAF
    or proxy block, which is not a license decision).
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Optional

API_URL = ""  # e.g. "https://abc123.execute-api.us-west-2.amazonaws.com/prod"
TIMEOUT_SECONDS = 9  # one answer; MCP_LICENSE_TIMEOUT overrides
RETRIES = 5  # more tries when there is no answer; MCP_LICENSE_RETRIES overrides
DEADLINE_SECONDS = 45  # all tries and pauses together; MCP_LICENSE_DEADLINE overrides
BACKOFF_FIRST_SECONDS = 0.5  # pauses between tries: 0.5, 1, 2, 4, 4 ... seconds
BACKOFF_MAX_SECONDS = 4
RETRY_AFTER_CAP_SECONDS = 10  # the longest pause honoured when the service answers 429 with retry_after_seconds
STATE_DIR = os.path.join(os.path.expanduser("~"), ".mcp_auth")
_sleep = time.sleep  # replaced in tests
_monotonic = time.monotonic  # replaced in tests


class LicenseError(Exception):
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
        self.message = message


@dataclass
class LicenseResult:
    valid: bool
    reason: str
    seats_used: Optional[int] = None
    seats_max: Optional[int] = None
    expires_at: Optional[str] = None
    from_cache: bool = False
    offline: bool = False


# --------------------------------------------------------------- local state

def _state_path(name: str) -> str:
    return os.path.join(STATE_DIR, name)


def _read_json(name: str):
    try:
        with open(_state_path(name), "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _write_json(name: str, data) -> None:
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(_state_path(name), "w", encoding="utf-8") as handle:
            json.dump(data, handle)
    except OSError:
        pass  # caching is best effort


def device_id() -> str:
    """Stable random id for this machine, created on first use."""
    try:
        with open(_state_path("device_id"), "r", encoding="utf-8") as handle:
            value = handle.read().strip()
            if value:
                return value
    except OSError:
        pass
    value = uuid.uuid4().hex
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(_state_path("device_id"), "w", encoding="utf-8") as handle:
            handle.write(value)
    except OSError:
        pass
    return value


def _key_fingerprint(license_key: str) -> str:
    return hashlib.sha256(license_key.strip().encode("utf-8")).hexdigest()


def _clear_cache() -> None:
    try:
        os.remove(_state_path("cache.json"))
    except OSError:
        pass


# ---------------------------------------------------------------- key lookup

def get_license_key(argv=None) -> Optional[str]:
    args = list(sys.argv[1:] if argv is None else argv)
    for i, arg in enumerate(args):
        if arg == "--license-key" and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("--license-key="):
            return arg.split("=", 1)[1]
    return os.environ.get("MCP_LICENSE_KEY")


def _base_url(api_url: Optional[str]) -> str:
    url = (api_url or os.environ.get("MCP_LICENSE_API_URL") or API_URL).rstrip("/")
    if not url:
        raise LicenseError("NOT_CONFIGURED", "License API URL is not configured.")
    if not (url.startswith("https://") or url.startswith("http://localhost")
            or url.startswith("http://127.0.0.1")):
        raise LicenseError("NOT_CONFIGURED", "License API URL must use https.")
    return url


# -------------------------------------------------------------------- verify

def _number(value, default, low, high, whole=False):
    """A setting that is a number in [low, high]; anything else (missing, text, out of range) is the default."""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    if n != n or n < low or n > high:  # NaN and out of range
        return default
    return int(n) if whole else n


def timing():
    """(timeout, retries, deadline) in seconds and counts: the environment first, then the constants above."""
    return (_number(os.environ.get("MCP_LICENSE_TIMEOUT") or TIMEOUT_SECONDS, 9, 1, 25),
            _number(os.environ.get("MCP_LICENSE_RETRIES") or RETRIES, 5, 0, 10, whole=True),
            _number(os.environ.get("MCP_LICENSE_DEADLINE") or DEADLINE_SECONDS, 45, 5, 120))


def _pause_for(attempt: int, body) -> float:
    """Seconds to wait after try number `attempt` (0-based) got no answer. A 429 names its own pause."""
    asked = body.get("retry_after_seconds") if isinstance(body, dict) else None
    if isinstance(asked, (int, float)) and not isinstance(asked, bool) and 0 <= asked < float("inf"):
        return min(float(asked), RETRY_AFTER_CAP_SECONDS)  # what the service asks for, but never a long wait
    return min(BACKOFF_FIRST_SECONDS * (2 ** attempt), BACKOFF_MAX_SECONDS)


def _ask(url: str, license_key: str, dev_id: str, retries: int):
    """Ask the service, trying again only when it gave no answer. Returns (status, body); status is None when the
    last try failed on the network, and a 5xx or 429 is returned as it came when the tries ran out."""
    timeout, _, deadline = timing()
    started = _monotonic()
    status, body = None, {}
    for attempt in range(retries + 1):
        left = deadline - (_monotonic() - started)
        if attempt and left < 0.5:
            break
        try:
            status, body = _post_verify(url, license_key, dev_id, max(0.5, min(timeout, left)))
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
            status, body = None, {}
        if status is not None and status != 429 and status < 500:
            return status, body  # an answer, valid or not: not a case for asking again
        if attempt >= retries:
            break
        pause = _pause_for(attempt, body)
        if deadline - (_monotonic() - started) <= pause:  # no room left for a pause and another try
            break
        _sleep(pause)
    return status, body


def _bounded(call, seconds):
    """Run call() and give up after `seconds` of real time. urlopen's own timeout applies to each socket step and to
    each address of a host in turn (a CloudFront name has several), so on a network that swallows packets one try
    could last many times the timeout. The abandoned try finishes by itself in a daemon thread."""
    box = {}

    def run():
        try:
            box["value"] = call()
        except BaseException as error:  # handed back to the caller below
            box["error"] = error

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        raise TimeoutError("no answer in {:g} s".format(seconds))
    if "error" in box:
        raise box["error"]
    return box["value"]


def _post_verify(url: str, license_key: str, dev_id: str, timeout: Optional[float] = None):
    """Return (http_status, body_dict). Raises OSError-family on network failure."""
    payload = json.dumps({"license_key": license_key.strip(), "device_id": dev_id}).encode()
    request = urllib.request.Request(
        url + "/v1/mcp/verify",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    timeout = timeout or timing()[0]

    def once():
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read().decode("utf-8") or "{}")
            except ValueError:
                body = {}
            return exc.code, body

    return _bounded(once, timeout)


def verify(license_key: Optional[str] = None, api_url: Optional[str] = None) -> LicenseResult:
    """Check the license. Raises LicenseError when the tool must not run."""
    license_key = license_key or get_license_key()
    if not license_key:
        raise LicenseError("NO_KEY", "No license key. Use --license-key or MCP_LICENSE_KEY.")
    url = _base_url(api_url)
    fingerprint = _key_fingerprint(license_key)
    now = time.time()

    cache = _read_json("cache.json")
    cached_ok = bool(cache and cache.get("fingerprint") == fingerprint and cache.get("ok"))
    if cached_ok and now < cache.get("fresh_until", 0):
        return LicenseResult(True, "OK", cache.get("seats_used"), cache.get("seats_max"),
                             cache.get("expires_at"), from_cache=True)

    # With a success that can still be honoured offline there is no need to wait through the retries.
    in_grace = cached_ok and now < cache.get("grace_until", 0)
    status, body = _ask(url, license_key, device_id(), 0 if in_grace else timing()[1])

    if status == 200 and body.get("valid"):
        ttl = int(body.get("cache_ttl_seconds", 300))
        lease_expires_at = float(body.get("lease_expires_at", now))
        _write_json("cache.json", {
            "fingerprint": fingerprint,
            "ok": True,
            "fresh_until": min(now + ttl, lease_expires_at),
            "grace_until": lease_expires_at,
            "seats_used": body.get("seats_used"),
            "seats_max": body.get("seats_max"),
            "expires_at": body.get("expires_at"),
        })
        return LicenseResult(True, "OK", body.get("seats_used"), body.get("seats_max"),
                             body.get("expires_at"))

    if status in (401, 403) and body.get("reason"):
        _clear_cache()  # explicit denial: never fall back to the grace window
        raise LicenseError(body["reason"], body.get("message", "License check failed."))

    # Network failure, a 5xx, a 429, or a 403 that is not one of our license
    # decisions (a WAF or proxy block carries no "reason"): only the grace window applies.
    if cached_ok and now < cache.get("grace_until", 0):
        return LicenseResult(True, "OFFLINE_GRACE", cache.get("seats_used"),
                             cache.get("seats_max"), cache.get("expires_at"),
                             from_cache=True, offline=True)
    raise LicenseError("UNREACHABLE", "Could not reach the license server.")


def require_license(license_key: Optional[str] = None, api_url: Optional[str] = None) -> LicenseResult:
    """Call at startup. Prints a clear message and exits when not licensed."""
    try:
        result = verify(license_key, api_url)
    except LicenseError as exc:
        sys.stderr.write("License check failed ({}): {}\n".format(exc.reason, exc.message))
        sys.exit(2)
    if result.offline:
        sys.stderr.write("Warning: license server unreachable; running on offline grace.\n")
    return result


if __name__ == "__main__":
    require_license()
    print("License OK")
