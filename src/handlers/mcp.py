"""POST /v1/mcp/verify - runtime license check called by MCP tools.

Request:  {"license_key": "...", "device_id": "..."}
Decision order: global kill switch -> key -> tenant -> license status ->
expiry -> tenant rate limit -> seat (lease).

Responses always carry "valid". A client must treat a 401/403 that carries a
"reason" as final and drop its cached result; network failures may keep running,
and only until lease_expires_at.
A 429 RATE_LIMITED is not a denial: the client treats it like a network failure.

The rate limit counts only requests that already hold a valid key for an
active license of an enabled tenant. Requests with a wrong, revoked or expired
key are never counted, so nobody without a working key can use up a tenant's
quota and lock its real users out.
"""
import logging

from core import config, keys, service, store
from core.http import ApiError, json_body, make_handler

logger = logging.getLogger()

MAX_DEVICE_ID = 128


def _deny(status, reason, message):
    return status, {"valid": False, "reason": reason, "message": message}


def _is_expired(expires_at):
    # expires_at is the last valid day (inclusive), UTC.
    return bool(expires_at) and expires_at < store.now_iso()[:10]


def register_seat(license_item, device_id, lease_sec):
    """Hold a seat for this device and return (seats_used, lease_expires_at),
    or None when every seat is held by a device with a live lease.

    Every successful call renews the lease to now + lease_sec. A device that
    stops checking in loses its seat when the lease runs out: the seat then
    counts as free and is handed to the next new device that asks.

    Concurrency: a new device claims its seat with one DynamoDB transaction
    (store.register_seat), and an expired seat is handed over with another
    (store.reclaim_seat), so concurrent first-time verifies can never exceed
    seats_max. license_item may be stale; the limits are enforced by the
    transactions, not by values read earlier.
    """
    tenant_id = license_item["tenant_id"]
    license_id = license_item["license_id"]
    now = store.now_epoch()
    now_iso = store.now_iso()
    lease_expires_at = now + lease_sec

    def done():
        used = store.get_license(tenant_id, license_id, consistent=True)["seats_used"]
        return int(used), lease_expires_at

    # Already holds a seat (live, or expired but not yet taken): renew it.
    if store.renew_seat(tenant_id, license_id, device_id, now_iso, lease_expires_at):
        return done()

    outcome = store.register_seat(tenant_id, license_id, device_id, now_iso, lease_expires_at)

    if outcome == store.SEAT_FULL:
        # Full on paper: take over a seat whose lease has expired, if any.
        for expired in store.find_expired_seats(tenant_id, license_id, now):
            outcome = store.reclaim_seat(tenant_id, license_id, expired, device_id,
                                         now_iso, lease_expires_at, now)
            if outcome is not None:
                break
        else:
            return None

    if outcome == store.SEAT_EXISTS:  # the same device raced itself
        store.renew_seat(tenant_id, license_id, device_id, now_iso, lease_expires_at)
    return done()


def verify(event):
    body = json_body(event)
    license_key = body.get("license_key")
    device_id = body.get("device_id")
    if not isinstance(license_key, str) or not license_key:
        raise ApiError(400, "BAD_REQUEST", "license_key is required.")
    if not isinstance(device_id, str) or not 0 < len(device_id) <= MAX_DEVICE_ID:
        raise ApiError(400, "BAD_REQUEST", "device_id is required (1-128 characters).")

    control = store.get_control("global_kill_switch")
    if control and control.get("enabled"):
        logger.info("verify denied: GLOBAL_DISABLED")
        return _deny(403, "GLOBAL_DISABLED", "Licensing is disabled platform-wide.")

    parsed = keys.parse_license_key(license_key)
    if parsed is None:
        return _deny(401, "INVALID_KEY", "License key is not valid.")
    tenant_id, normalized = parsed

    license_item = store.find_license_by_key_hash(tenant_id, keys.hash_key(normalized))
    tenant = store.get_tenant(tenant_id) if license_item else None
    if license_item is None or tenant is None:
        return _deny(401, "INVALID_KEY", "License key is not valid.")

    if tenant.get("disabled_by_platform") or tenant.get("suspended_by_tenant"):
        logger.info("verify denied: TENANT_DISABLED tenant=%s", tenant_id)
        return _deny(403, "TENANT_DISABLED", "This tenant is disabled.")

    if license_item.get("status") != "ACTIVE":
        return _deny(403, "LICENSE_REVOKED", "This license has been revoked.")

    if _is_expired(license_item.get("expires_at")):
        return _deny(403, "LICENSE_EXPIRED", "This license has expired.")

    allowed, retry_after = store.take_rate_slot(
        tenant_id, config.get_int("limit_verify_per_min", tenant_id))
    if not allowed:
        logger.warning("verify denied: RATE_LIMITED tenant=%s", tenant_id)
        status, body = _deny(429, "RATE_LIMITED", "Too many requests for this tenant. Retry shortly.")
        body["retry_after_seconds"] = retry_after
        return status, body

    lease_sec = service.effective_lease_sec(license_item, tenant)
    seat = register_seat(license_item, device_id, lease_sec)
    if seat is None:
        logger.info("verify denied: SEAT_LIMIT tenant=%s license=%s",
                    tenant_id, license_item["license_id"])
        return _deny(403, "SEAT_LIMIT", "All seats for this license are in use.")

    seats_used, lease_expires_at = seat
    return 200, {
        "valid": True,
        "reason": "OK",
        "tenant_id": tenant_id,
        "license_id": license_item["license_id"],
        "seats_used": seats_used,
        "seats_max": int(license_item["seats_max"]),
        "expires_at": license_item.get("expires_at"),
        "lease_duration_sec": lease_sec,
        "lease_expires_at": lease_expires_at,
        # Re-check often enough that one missed check does not cost the seat.
        "cache_ttl_seconds": min(config.get_int("client_cache_ttl_seconds"), lease_sec // 3),
    }


handler = make_handler({"POST /v1/mcp/verify": verify})
