"""Tenant admin API (/v1/admin/*), and the same operations for a person signed in on the
website (/v1/console/*).

The tenant always comes from the caller's credential, never from the path or body, so a
tenant admin can only ever reach its own rows: from the API key record on /v1/admin, from the
signed custom:tenant_id claim of the ID token on /v1/console.
"""
from core import audit, auth, service, store
from core.http import ApiError, json_body, make_handler, path_param


def _principal(event):
    if "/v1/console/" in (event.get("routeKey") or ""):
        return auth.authenticate_console(event)
    return auth.authenticate(event, auth.ROLE_TENANT_ADMIN)


def _tenant(principal):
    tenant = store.get_tenant(principal.tenant_id)
    if tenant is None:
        raise ApiError(404, "TENANT_NOT_FOUND", "Tenant not found.")
    return tenant


def _license(principal, license_id):
    lic = store.get_license(principal.tenant_id, license_id)
    if lic is None:
        raise ApiError(404, "LICENSE_NOT_FOUND", "License not found.")
    return lic


# ------------------------------------------------------------------- tenant

def get_tenant(event):
    principal = _principal(event)
    return 200, service.tenant_detail_view(_tenant(principal))


def update_tenant(event):
    """Tenant settings. Today: lease_duration_sec, the default seat lease for
    every license of this tenant (null restores the platform default)."""
    principal = _principal(event)
    body = json_body(event)
    if "lease_duration_sec" not in body:
        raise ApiError(400, "BAD_REQUEST", "Nothing to update.")
    value = service.lease_update(body)
    tenant = store.update_tenant(principal.tenant_id, {"lease_duration_sec": value})
    audit.record(principal.tenant_id, principal, "tenant.updated",
                 {"fields": ["lease_duration_sec"], "lease_duration_sec": value})
    return 200, service.tenant_view(tenant)


def set_tenant_status(event):
    """Tenant-level kill switch. Only controls suspended_by_tenant; a platform
    disable can not be lifted from here."""
    principal = _principal(event)
    body = json_body(event)
    suspended = service.require_bool(body, "suspended")
    reason = service.require_str(body, "reason", required=False)
    tenant = store.update_tenant(
        principal.tenant_id,
        {"suspended_by_tenant": suspended, "suspended_reason": reason},
    )
    audit.record(principal.tenant_id, principal,
                 "tenant.suspended" if suspended else "tenant.resumed",
                 {"reason": reason})
    return 200, service.tenant_view(tenant)


# ----------------------------------------------------------------- api keys

def list_api_keys(event):
    principal = _principal(event)
    records = store.list_api_keys(principal.tenant_id)
    return 200, {"items": [service.api_key_view(r) for r in records]}


def create_api_key(event):
    principal = _principal(event)
    body = json_body(event)
    label = service.require_str(body, "label", required=False)
    service.check_api_key_quota(principal.tenant_id)
    record, full_key = service.issue_api_key(principal.tenant_id, auth.ROLE_TENANT_ADMIN, label)
    audit.record(principal.tenant_id, principal, "api_key.created", {"key_id": record["key_id"]})
    view = service.api_key_view(record)
    view["api_key"] = full_key  # shown once
    return 201, view


def revoke_api_key(event):
    principal = _principal(event)
    key_id = path_param(event, "key_id")
    record = store.get_api_key(key_id)
    if record is None or record.get("tenant_id") != principal.tenant_id:
        raise ApiError(404, "API_KEY_NOT_FOUND", "API key not found.")
    if record["status"] == "ACTIVE":
        active = [r for r in store.list_api_keys(principal.tenant_id) if r["status"] == "ACTIVE"]
        if len(active) <= 1:
            raise ApiError(409, "LAST_ACTIVE_KEY",
                           "Create another API key before revoking the last active one.")
    record = store.update_api_key(key_id, {"status": "REVOKED"})
    audit.record(principal.tenant_id, principal, "api_key.revoked", {"key_id": key_id})
    return 200, service.api_key_view(record)


# ----------------------------------------------------------------- licenses

def list_licenses(event):
    principal = _principal(event)
    limit, start = service.parse_page(event)
    items, last = store.list_licenses(principal.tenant_id, limit, start)
    return 200, service.page(items, last, service.license_view)


def create_license(event):
    principal = _principal(event)
    tenant = _tenant(principal)
    if tenant.get("disabled_by_platform"):
        raise ApiError(403, "TENANT_DISABLED", "This tenant is disabled by the platform.")
    item, license_key = service.new_license(principal.tenant_id, json_body(event))
    audit.record(principal.tenant_id, principal, "license.created",
                 {"license_id": item["license_id"]})
    view = service.license_view(item)
    view["license_key"] = license_key  # shown once
    return 201, view


def get_license(event):
    principal = _principal(event)
    lic = _license(principal, path_param(event, "license_id"))
    view = service.license_view(lic)
    now = store.now_epoch()
    seats = store.list_seats(principal.tenant_id, lic["license_id"])
    view["seats_active"] = sum(1 for s in seats if int(s.get("lease_expires_at", 0)) >= now)
    return 200, view


def update_license(event):
    principal = _principal(event)
    license_id = path_param(event, "license_id")
    current = _license(principal, license_id)
    body = json_body(event)
    updates = {}
    if "label" in body:
        updates["label"] = service.require_str(body, "label")
    if "seats_max" in body:
        updates["seats_max"] = service.parse_seats(body["seats_max"])
        if updates["seats_max"] > int(current["seats_max"]) and current.get("status") == "ACTIVE":
            service.check_license_quota(principal.tenant_id, updates["seats_max"],
                                        license_id, count_new=False)
    if "expires_at" in body:
        updates["expires_at"] = service.parse_date(body["expires_at"])
    if "lease_duration_sec" in body:
        updates["lease_duration_sec"] = service.lease_update(body)  # null clears the override
    if not updates:
        raise ApiError(400, "BAD_REQUEST", "Nothing to update.")
    updated = store.update_license(principal.tenant_id, license_id, updates)
    audit.record(principal.tenant_id, principal, "license.updated",
                 {"license_id": license_id, "fields": sorted(updates)})
    return 200, service.license_view(updated)


def set_license_status(event):
    principal = _principal(event)
    license_id = path_param(event, "license_id")
    _license(principal, license_id)
    updated = service.set_license_status(
        principal.tenant_id, license_id, json_body(event), principal)
    return 200, service.license_view(updated)


def rotate_license_key(event):
    principal = _principal(event)
    license_id = path_param(event, "license_id")
    updated, license_key = service.rotate_license_key(principal.tenant_id, license_id)
    audit.record(principal.tenant_id, principal, "license.key_rotated",
                 {"license_id": license_id})
    view = service.license_view(updated)
    view["license_key"] = license_key  # shown once
    return 200, view


def list_seats(event):
    principal = _principal(event)
    license_id = path_param(event, "license_id")
    _license(principal, license_id)
    seats = store.list_seats(principal.tenant_id, license_id)
    return 200, {"items": [service.seat_view(s) for s in seats]}


def release_seat(event):
    principal = _principal(event)
    license_id = path_param(event, "license_id")
    device_id = path_param(event, "device_id")
    _license(principal, license_id)
    if not store.release_seat(principal.tenant_id, license_id, device_id):
        raise ApiError(404, "SEAT_NOT_FOUND", "Seat not found.")
    audit.record(principal.tenant_id, principal, "seat.released",
                 {"license_id": license_id, "device_id": device_id})
    return 200, {"released": True}


# -------------------------------------------------------------------- audit

def audit_log(event):
    principal = _principal(event)
    limit, start = service.parse_page(event)
    items, last = store.list_audit(principal.tenant_id, limit, start)
    return 200, service.page(items, last, audit.public_view)


ROUTES = {
    "GET /v1/admin/tenant": get_tenant,
    "PATCH /v1/admin/tenant": update_tenant,
    "PUT /v1/admin/tenant/status": set_tenant_status,
    "GET /v1/admin/api-keys": list_api_keys,
    "POST /v1/admin/api-keys": create_api_key,
    "DELETE /v1/admin/api-keys/{key_id}": revoke_api_key,
    "GET /v1/admin/licenses": list_licenses,
    "POST /v1/admin/licenses": create_license,
    "GET /v1/admin/licenses/{license_id}": get_license,
    "PATCH /v1/admin/licenses/{license_id}": update_license,
    "PUT /v1/admin/licenses/{license_id}/status": set_license_status,
    "POST /v1/admin/licenses/{license_id}/rotate-key": rotate_license_key,
    "GET /v1/admin/licenses/{license_id}/seats": list_seats,
    "DELETE /v1/admin/licenses/{license_id}/seats/{device_id}": release_seat,
    "GET /v1/admin/audit-log": audit_log,
}
# The website's console calls the same operations with a signed-in person's ID token.
ROUTES.update({route.replace("/v1/admin/", "/v1/console/"): func for route, func in list(ROUTES.items())})

handler = make_handler(ROUTES)
