"""Platform owner API (/v1/super/*)."""
import logging

from core import audit, auth, cognito, identity, keys, service, store
from core.http import ApiError, json_body, make_handler, path_param

logger = logging.getLogger()

KILL_SWITCH_KEY = "global_kill_switch"


def _principal(event):
    return auth.authenticate(event, auth.ROLE_SUPER_ADMIN)


def _tenant(tenant_id):
    tenant = store.get_tenant(tenant_id)
    if tenant is None:
        raise ApiError(404, "TENANT_NOT_FOUND", "Tenant not found.")
    return tenant


# ------------------------------------------------------------------ tenants

def list_tenants(event):
    _principal(event)
    limit, start = service.parse_page(event)
    items, last = store.scan_tenants(limit, start)
    return 200, service.page(items, last, service.tenant_view)


def create_tenant(event):
    principal = _principal(event)
    body = json_body(event)
    tenant_id = body.get("tenant_id")
    if tenant_id is not None and not keys.is_valid_tenant_id(tenant_id):
        raise ApiError(400, "BAD_REQUEST",
                       "tenant_id must be 3-12 lowercase letters or digits (or omitted, to generate one).")
    item = {
        "company_name": service.require_str(body, "company_name"),
        "email": service.require_str(body, "email"),
        "suspended_by_tenant": False,
        "disabled_by_platform": False,
        "created_at": store.now_iso(),
    }
    item = service.create_tenant(item, tenant_id)
    tenant_id = item["tenant_id"]
    record, full_key = service.issue_api_key(
        tenant_id, auth.ROLE_TENANT_ADMIN, "initial admin key")
    audit.record(tenant_id, principal, "tenant.created", {})
    audit.record(audit.PLATFORM, principal, "tenant.created", {"tenant_id": tenant_id})
    view = service.tenant_view(item)
    view["admin_api_key"] = full_key  # shown once
    return 201, view


def get_tenant(event):
    _principal(event)
    return 200, service.tenant_detail_view(_tenant(path_param(event, "tenant_id")))


def update_tenant(event):
    principal = _principal(event)
    tenant_id = path_param(event, "tenant_id")
    body = json_body(event)
    updates = {}
    for field in ("company_name", "email"):
        if field in body:
            updates[field] = service.require_str(body, field)
    if "lease_duration_sec" in body:
        updates["lease_duration_sec"] = service.lease_update(body)
    if not updates:
        raise ApiError(400, "BAD_REQUEST", "Nothing to update.")
    tenant = store.update_tenant(tenant_id, updates)
    audit.record(tenant_id, principal, "tenant.updated", {"fields": sorted(updates)})
    return 200, service.tenant_view(tenant)


def set_tenant_status(event):
    """Disable or re-enable one tenant. Only the platform can lift this."""
    principal = _principal(event)
    tenant_id = path_param(event, "tenant_id")
    body = json_body(event)
    disabled = service.require_bool(body, "disabled")
    reason = service.require_str(body, "reason", required=False)
    tenant = store.update_tenant(
        tenant_id, {"disabled_by_platform": disabled, "disabled_reason": reason})
    event_type = "tenant.disabled_by_platform" if disabled else "tenant.enabled_by_platform"
    audit.record(tenant_id, principal, event_type, {"reason": reason})
    audit.record(audit.PLATFORM, principal, event_type,
                 {"tenant_id": tenant_id, "reason": reason})
    return 200, service.tenant_view(tenant)


def ban_tenant(event):
    """Ban a tenant: it is disabled (every license is refused and its admin access stops), its owner's
    login is disabled and signed out, and the owner's address cannot sign up again."""
    principal = _principal(event)
    tenant_id = path_param(event, "tenant_id")
    tenant = _tenant(tenant_id)
    reason = service.require_str(json_body(event), "reason", required=False)
    tenant = store.update_tenant(tenant_id, {"disabled_by_platform": True, "disabled_reason": reason,
                                             "banned": True})
    owner = tenant.get("owner_email")
    login_disabled = False
    if owner:
        store.put_banned({"email_hash": identity.email_hash(owner), "tenant_id": tenant_id,
                          "reason": reason, "banned_at": store.now_iso()})
        try:
            cognito.disable_user(tenant.get("owner_sub") or owner)
            login_disabled = True
        except Exception:
            logger.exception("could not disable the login of a banned tenant")
    audit.record(tenant_id, principal, "tenant.banned", {"reason": reason})
    audit.record(audit.PLATFORM, principal, "tenant.banned", {"tenant_id": tenant_id, "reason": reason})
    view = service.tenant_view(tenant)
    view["login_disabled"] = login_disabled
    return 200, view


def unban_tenant(event):
    """Undo a ban: the tenant is enabled, the login works again and the address may sign up."""
    principal = _principal(event)
    tenant_id = path_param(event, "tenant_id")
    tenant = _tenant(tenant_id)
    tenant = store.update_tenant(tenant_id, {"disabled_by_platform": False, "disabled_reason": None,
                                             "banned": False})
    owner = tenant.get("owner_email")
    if owner:
        store.delete_banned(identity.email_hash(owner))
        try:
            cognito.enable_user(tenant.get("owner_sub") or owner)
        except Exception:
            logger.exception("could not re-enable the login of an unbanned tenant")
    audit.record(tenant_id, principal, "tenant.unbanned", {})
    audit.record(audit.PLATFORM, principal, "tenant.unbanned", {"tenant_id": tenant_id})
    return 200, service.tenant_view(tenant)


def issue_tenant_api_key(event):
    """Issue a new tenant admin key, e.g. when a tenant lost all of its keys."""
    principal = _principal(event)
    tenant_id = path_param(event, "tenant_id")
    _tenant(tenant_id)
    label = service.require_str(json_body(event), "label", required=False)
    record, full_key = service.issue_api_key(tenant_id, auth.ROLE_TENANT_ADMIN, label)
    audit.record(tenant_id, principal, "api_key.created", {"key_id": record["key_id"]})
    view = service.api_key_view(record)
    view["api_key"] = full_key  # shown once
    return 201, view


def list_tenant_licenses(event):
    _principal(event)
    tenant_id = path_param(event, "tenant_id")
    _tenant(tenant_id)
    limit, start = service.parse_page(event)
    items, last = store.list_licenses(tenant_id, limit, start)
    return 200, service.page(items, last, service.license_view)


# -------------------------------------------------------------- kill switch

def _kill_switch_view(item):
    item = item or {}
    return {
        "enabled": bool(item.get("enabled", False)),
        "reason": item.get("reason"),
        "changed_at": item.get("changed_at"),
    }


def get_kill_switch(event):
    _principal(event)
    return 200, _kill_switch_view(store.get_control(KILL_SWITCH_KEY))


def set_kill_switch(event):
    """Disable (enabled=true) or restore (enabled=false) every tenant."""
    principal = _principal(event)
    body = json_body(event)
    enabled = service.require_bool(body, "enabled")
    reason = service.require_str(body, "reason", required=False)
    item = {
        "control_key": KILL_SWITCH_KEY,
        "enabled": enabled,
        "reason": reason,
        "changed_at": store.now_iso(),
        "changed_by": principal.key_id,
    }
    store.put_control(item)
    audit.record(audit.PLATFORM, principal,
                 "kill_switch.enabled" if enabled else "kill_switch.disabled",
                 {"reason": reason})
    return 200, _kill_switch_view(item)


def audit_log(event):
    _principal(event)
    limit, start = service.parse_page(event)
    items, last = store.list_audit(audit.PLATFORM, limit, start)
    return 200, service.page(items, last)


handler = make_handler({
    "GET /v1/super/tenants": list_tenants,
    "POST /v1/super/tenants": create_tenant,
    "GET /v1/super/tenants/{tenant_id}": get_tenant,
    "PATCH /v1/super/tenants/{tenant_id}": update_tenant,
    "PUT /v1/super/tenants/{tenant_id}/status": set_tenant_status,
    "POST /v1/super/tenants/{tenant_id}/ban": ban_tenant,
    "POST /v1/super/tenants/{tenant_id}/unban": unban_tenant,
    "POST /v1/super/tenants/{tenant_id}/api-keys": issue_tenant_api_key,
    "GET /v1/super/tenants/{tenant_id}/licenses": list_tenant_licenses,
    "GET /v1/super/kill-switch": get_kill_switch,
    "PUT /v1/super/kill-switch": set_kill_switch,
    "GET /v1/super/audit-log": audit_log,
})
