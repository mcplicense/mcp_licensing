"""Logic shared by the admin and super handlers."""
import re
from datetime import datetime, timedelta, timezone

from core import audit, config, keys, store
from core.http import ApiError, query_param

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_PAGE = 100


def parse_page(event):
    raw = query_param(event, "limit", "50")
    try:
        limit = int(raw)
    except ValueError:
        raise ApiError(400, "BAD_REQUEST", "limit must be an integer.")
    limit = max(1, min(limit, MAX_PAGE))
    return limit, store.decode_token(query_param(event, "next_token"))


def page(items, last_key, view=lambda x: x):
    return {"items": [view(i) for i in items], "next_token": store.encode_token(last_key)}


def require_str(body, field, max_len=200, required=True):
    value = body.get(field)
    if value is None:
        if required:
            raise ApiError(400, "BAD_REQUEST", "{} is required.".format(field))
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > max_len:
        raise ApiError(400, "BAD_REQUEST", "{} must be a non-empty string.".format(field))
    return value.strip()


def require_bool(body, field):
    value = body.get(field)
    if not isinstance(value, bool):
        raise ApiError(400, "BAD_REQUEST", "{} must be true or false.".format(field))
    return value


def parse_date(value):
    if not isinstance(value, str) or not DATE_RE.match(value):
        raise ApiError(400, "BAD_REQUEST", "expires_at must be YYYY-MM-DD.")
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise ApiError(400, "BAD_REQUEST", "expires_at must be a real date.")
    return value


def parse_seats(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100000:
        raise ApiError(400, "BAD_REQUEST", "seats_max must be an integer from 1 to 100000.")
    return value


MIN_LEASE_SEC = 300          # 5 minutes
MAX_LEASE_SEC = 2592000      # 30 days


def parse_lease(value):
    if isinstance(value, bool) or not isinstance(value, int) \
            or not MIN_LEASE_SEC <= value <= MAX_LEASE_SEC:
        raise ApiError(400, "BAD_REQUEST",
                       "lease_duration_sec must be an integer from {} to {} (or null to use the default)."
                       .format(MIN_LEASE_SEC, MAX_LEASE_SEC))
    return value


def lease_update(body):
    """Return the value to store for lease_duration_sec: an int, or None to
    clear the override. Only call when the field is present in body."""
    return None if body["lease_duration_sec"] is None else parse_lease(body["lease_duration_sec"])


def effective_lease_sec(license_item, tenant):
    """License override, else tenant override, else the global default."""
    for source in (license_item, tenant):
        value = source.get("lease_duration_sec")
        if value is not None:
            return int(value)
    return config.get_int("default_lease_duration_sec")


# ------------------------------------------------------------------- limits
# The numbers live in SSM (/mcp/<stage>/limit_*), with an optional override per
# tenant (/mcp/<stage>/tenants/<tenant_id>/limit_*). Limits apply when
# something is created or enlarged, never retroactively.

def tenant_limits(tenant_id):
    return {
        "licenses": config.get_int("limit_licenses_per_tenant", tenant_id),
        "seats_per_license": config.get_int("limit_seats_per_license", tenant_id),
        "seats_per_tenant": config.get_int("limit_seats_per_tenant", tenant_id),
        "api_keys": config.get_int("limit_api_keys_per_tenant", tenant_id),
        "verify_per_min": config.get_int("limit_verify_per_min", tenant_id),
    }


def _active_licenses(tenant_id, exclude_license_id=None):
    return [r for r in store.license_quota_rows(tenant_id)
            if r.get("status") == "ACTIVE" and r["license_id"] != exclude_license_id]


def tenant_usage(tenant_id):
    active = _active_licenses(tenant_id)
    return {
        "licenses": len(active),
        "seats": sum(int(r["seats_max"]) for r in active),
        "api_keys": sum(1 for k in store.list_api_keys(tenant_id) if k["status"] == "ACTIVE"),
    }


def _limit_reached(message):
    return ApiError(403, "LIMIT_REACHED", message + " Contact support to raise this limit.")


def check_license_quota(tenant_id, seats, exclude_license_id=None, count_new=True):
    """Refuse an active license of `seats` seats that would break a limit.

    exclude_license_id is the license being changed, so it is not counted twice;
    count_new is False when it is already active and only its seats grow. The
    checks read and then write without a lock, so two simultaneous requests can
    overshoot by one: these are fair-use limits, not a security boundary."""
    per_license = config.get_int("limit_seats_per_license", tenant_id)
    if seats > per_license:
        raise _limit_reached("A license can have at most {} seats.".format(per_license))
    others = _active_licenses(tenant_id, exclude_license_id)
    max_licenses = config.get_int("limit_licenses_per_tenant", tenant_id)
    if count_new and len(others) + 1 > max_licenses:
        raise _limit_reached("This tenant can have at most {} active licenses.".format(max_licenses))
    max_seats = config.get_int("limit_seats_per_tenant", tenant_id)
    if sum(int(r["seats_max"]) for r in others) + seats > max_seats:
        raise _limit_reached("This tenant can have at most {} seats across its active licenses."
                             .format(max_seats))


def check_api_key_quota(tenant_id):
    max_keys = config.get_int("limit_api_keys_per_tenant", tenant_id)
    active = sum(1 for k in store.list_api_keys(tenant_id) if k["status"] == "ACTIVE")
    if active + 1 > max_keys:
        raise _limit_reached("This tenant can have at most {} active API keys.".format(max_keys))


GENERATE_ATTEMPTS = 8


def create_tenant(item, tenant_id=None):
    """Store a new tenant and return it. Without a tenant_id one is generated
    (mcp-xxxxxx); a collision with an existing tenant just tries another."""
    if tenant_id is not None:
        item = dict(item, tenant_id=tenant_id)
        store.create_tenant(item)
        return item
    for _ in range(GENERATE_ATTEMPTS):
        candidate = dict(item, tenant_id=keys.generate_tenant_id())
        try:
            store.create_tenant(candidate)
            return candidate
        except ApiError as exc:
            if exc.code != "TENANT_EXISTS":
                raise
    raise ApiError(503, "BUSY", "Could not allocate a tenant id; please retry.")


def provision_tenant(email, company, sub):
    """The tenant for a person who has just confirmed their address: a generated id, active at
    once, with the person recorded as its owner (which is how a ban finds their login)."""
    return create_tenant({
        "company_name": company,
        "email": email,
        "owner_email": email,
        "owner_sub": sub,
        "self_service": True,
        "suspended_by_tenant": False,
        "disabled_by_platform": False,
        "created_at": store.now_iso(),
    })


def tenant_view(tenant):
    disabled = bool(tenant.get("disabled_by_platform"))
    suspended = bool(tenant.get("suspended_by_tenant"))
    return {
        "tenant_id": tenant["tenant_id"],
        "company_name": tenant.get("company_name"),
        "email": tenant.get("email"),
        "status": "DISABLED" if (disabled or suspended) else "ACTIVE",
        "suspended_by_tenant": suspended,
        "disabled_by_platform": disabled,
        "lease_duration_sec": tenant.get("lease_duration_sec"),
        "created_at": tenant.get("created_at"),
    }


def tenant_detail_view(tenant):
    """tenant_view plus the limits that apply to this tenant and its usage."""
    view = tenant_view(tenant)
    view["limits"] = tenant_limits(tenant["tenant_id"])
    view["usage"] = tenant_usage(tenant["tenant_id"])
    return view


def license_view(lic):
    return {
        "license_id": lic["license_id"],
        "tenant_id": lic["tenant_id"],
        "label": lic.get("label"),
        "status": lic["status"],
        "seats_max": lic["seats_max"],
        "seats_used": lic["seats_used"],  # seat rows held, incl. expired leases not yet reclaimed
        "lease_duration_sec": lic.get("lease_duration_sec"),
        "expires_at": lic.get("expires_at"),
        "created_at": lic.get("created_at"),
    }


def seat_view(seat):
    lease = seat.get("lease_expires_at")
    return {
        "device_id": seat["device_id"],
        "license_id": seat["license_id"],
        "first_seen_at": seat.get("first_seen_at"),
        "last_seen_at": seat.get("last_seen_at"),
        "lease_expires_at": lease,
        "active": lease is not None and int(lease) >= store.now_epoch(),  # released once now > lease
    }


def api_key_view(record):
    return {
        "key_id": record["key_id"],
        "label": record.get("label"),
        "role": record["role"],
        "status": record["status"],
        "created_at": record.get("created_at"),
        "last_used_at": record.get("last_used_at"),
    }


def issue_api_key(tenant_id, role, label):
    """Create and store a key. The full key is returned here and never again."""
    key_id, full_key, key_hash = keys.generate_api_key()
    record = {
        "key_id": key_id,
        "key_hash": key_hash,
        "role": role,
        "status": "ACTIVE",
        "label": label,
        "created_at": store.now_iso(),
    }
    if tenant_id:
        record["tenant_id"] = tenant_id
    store.put_api_key(record)
    return record, full_key


def new_license(tenant_id, body):
    """Create a license row and return (license, license_key)."""
    label = require_str(body, "label", required=False)
    seats = body.get("seats_max")
    seats = config.get_int("default_seats_max") if seats is None else parse_seats(seats)
    check_license_quota(tenant_id, seats)
    if body.get("expires_at") is None:
        days = config.get_int("default_license_days")
        expires_at = (datetime.now(timezone.utc).date() + timedelta(days=days)).isoformat()
    else:
        expires_at = parse_date(body["expires_at"])

    license_key = keys.generate_license_key(tenant_id)
    item = {
        "tenant_id": tenant_id,
        "license_id": keys.new_license_id(),
        "key_hash": keys.hash_key(license_key),
        "status": "ACTIVE",
        "seats_max": seats,
        "seats_used": 0,
        "expires_at": expires_at,
        "created_at": store.now_iso(),
    }
    if label:
        item["label"] = label
    if body.get("lease_duration_sec") is not None:
        item["lease_duration_sec"] = parse_lease(body["lease_duration_sec"])
    store.create_license(item)
    return item, license_key


def rotate_license_key(tenant_id, license_id):
    lic = store.get_license(tenant_id, license_id)
    if lic is None:
        raise ApiError(404, "LICENSE_NOT_FOUND", "License not found.")
    license_key = keys.generate_license_key(tenant_id)
    updated = store.update_license(
        tenant_id, license_id, {"key_hash": keys.hash_key(license_key)}
    )
    return updated, license_key


def set_license_status(tenant_id, license_id, body, principal):
    status = body.get("status")
    if status not in ("ACTIVE", "REVOKED"):
        raise ApiError(400, "BAD_REQUEST", "status must be ACTIVE or REVOKED.")
    reason = require_str(body, "reason", required=False)
    current = store.get_license(tenant_id, license_id)
    if status == "ACTIVE" and current is not None and current.get("status") != "ACTIVE":
        check_license_quota(tenant_id, int(current["seats_max"]), license_id)  # reinstating
    updated = store.update_license(tenant_id, license_id, {"status": status})
    audit.record(tenant_id, principal, "license.status_changed",
                 {"license_id": license_id, "status": status, "reason": reason})
    return updated


def utc_today():
    return datetime.now(timezone.utc).date().isoformat()
