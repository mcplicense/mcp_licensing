import pytest

from core import keys, store
from helpers import call, create_license, create_tenant, verify


@pytest.fixture
def two_tenants(super_key):
    a = create_tenant(super_key, "acme")
    b = create_tenant(super_key, "globex", company_name="Globex")
    return a["admin_api_key"], b["admin_api_key"]


def test_auth_required_and_roles_enforced(super_key, two_tenants):
    admin_a, _ = two_tenants
    assert call("GET /v1/admin/tenant")[0] == 401
    assert call("GET /v1/admin/tenant", key="mcpk_000000000000.nope")[0] == 401
    assert call("GET /v1/admin/tenant", key="not a key")[0] == 401
    assert call("GET /v1/admin/tenant", key=admin_a)[0] == 200
    # super key is not a tenant key, and a tenant key is not a super key
    assert call("GET /v1/admin/tenant", key=super_key)[0] == 403
    assert call("GET /v1/super/tenants", key=admin_a)[0] == 403
    assert call("GET /v1/super/kill-switch", key=admin_a)[0] == 403


def test_tenant_isolation(super_key, two_tenants):
    admin_a, admin_b = two_tenants
    lic_a = create_license(admin_a)
    lic_b = create_license(admin_b)
    p_a = {"license_id": lic_a["license_id"]}
    p_b = {"license_id": lic_b["license_id"]}

    listed = call("GET /v1/admin/licenses", key=admin_a)[1]["items"]
    assert [i["license_id"] for i in listed] == [lic_a["license_id"]]

    for route in ("GET /v1/admin/licenses/{license_id}",
                  "GET /v1/admin/licenses/{license_id}/seats"):
        assert call(route, key=admin_a, params=p_b)[0] == 404
    assert call("PATCH /v1/admin/licenses/{license_id}", {"seats_max": 50},
                key=admin_a, params=p_b)[0] == 404
    assert call("PUT /v1/admin/licenses/{license_id}/status", {"status": "REVOKED"},
                key=admin_a, params=p_b)[0] == 404
    assert call("POST /v1/admin/licenses/{license_id}/rotate-key",
                key=admin_a, params=p_b)[0] == 404
    # tenant B's license is untouched
    assert verify(lic_b["license_key"])[0] == 200

    # tenant_id in the body or query is ignored; it only comes from the key
    status, body = call("POST /v1/admin/licenses", {"tenant_id": "globex"}, key=admin_a)
    assert status == 201 and body["tenant_id"] == "acme"

    # api keys are isolated too
    key_b = call("GET /v1/admin/api-keys", key=admin_b)[1]["items"][0]["key_id"]
    assert call("DELETE /v1/admin/api-keys/{key_id}", key=admin_a,
                params={"key_id": key_b})[0] == 404


def test_audit_log_is_per_tenant_and_hides_platform_key_ids(super_key, two_tenants):
    admin_a, admin_b = two_tenants
    create_license(admin_a)
    for disabled in (True, False):
        call("PUT /v1/super/tenants/{tenant_id}/status", {"disabled": disabled, "reason": "x"},
             key=super_key, params={"tenant_id": "acme"})
    items = call("GET /v1/admin/audit-log", key=admin_a)[1]["items"]
    types = [i["event_type"] for i in items]
    assert "license.created" in types and "tenant.disabled_by_platform" in types
    platform_event = next(i for i in items if i["event_type"] == "tenant.disabled_by_platform")
    assert platform_event["actor"] == "platform"
    assert not any(i["event_type"] == "license.created"
                   for i in call("GET /v1/admin/audit-log", key=admin_b)[1]["items"])


def test_platform_disabled_tenant_loses_all_admin_access_until_enabled(super_key, two_tenants):
    admin_a, admin_b = two_tenants
    call("PUT /v1/super/tenants/{tenant_id}/status", {"disabled": True},
         key=super_key, params={"tenant_id": "acme"})
    for route in ("GET /v1/admin/licenses", "GET /v1/admin/tenant", "GET /v1/admin/api-keys",
                  "GET /v1/admin/audit-log"):
        status, body = call(route, key=admin_a)
        assert status == 403 and body["error"]["code"] == "TENANT_DISABLED", route
    assert call("POST /v1/admin/licenses", {}, key=admin_a)[0] == 403
    assert call("PUT /v1/admin/tenant/status", {"suspended": False}, key=admin_a)[0] == 403  # cannot lift it
    assert call("GET /v1/admin/licenses", key=admin_b)[0] == 200  # other tenants unaffected

    call("PUT /v1/super/tenants/{tenant_id}/status", {"disabled": False},
         key=super_key, params={"tenant_id": "acme"})
    assert call("GET /v1/admin/licenses", key=admin_a)[0] == 200


def test_a_tenant_that_suspended_itself_can_still_resume(two_tenants):
    admin_a, _ = two_tenants
    call("PUT /v1/admin/tenant/status", {"suspended": True}, key=admin_a)
    assert call("PUT /v1/admin/tenant/status", {"suspended": False}, key=admin_a)[0] == 200


def test_license_validation(two_tenants):
    admin_a, _ = two_tenants
    for bad in [{"seats_max": 0}, {"seats_max": "3"}, {"seats_max": True},
                {"expires_at": "tomorrow"}, {"expires_at": "2025-13-45"}, {"label": ""}]:
        assert call("POST /v1/admin/licenses", bad, key=admin_a)[0] == 400, bad
    status, body = call("POST /v1/admin/licenses", {"label": "ci", "seats_max": 3,
                                                    "expires_at": "2099-01-01"}, key=admin_a)
    assert status == 201
    assert body["license_key"].startswith("acme_")
    assert body["seats_max"] == 3 and body["expires_at"] == "2099-01-01"
    assert "key_hash" not in body
    fetched = call("GET /v1/admin/licenses/{license_id}", key=admin_a,
                   params={"license_id": body["license_id"]})[1]
    assert "license_key" not in fetched and "key_hash" not in fetched


def test_default_seats_and_expiry_come_from_settings(two_tenants):
    admin_a, _ = two_tenants
    body = create_license(admin_a)
    assert body["seats_max"] == 1
    assert body["expires_at"] > "2026"


def test_seats_listing_and_release(two_tenants):
    admin_a, _ = two_tenants
    lic = create_license(admin_a, seats_max=1)
    params = {"license_id": lic["license_id"]}
    assert verify(lic["license_key"], "dev-a")[0] == 200
    assert verify(lic["license_key"], "dev-b")[0] == 403

    seats = call("GET /v1/admin/licenses/{license_id}/seats", key=admin_a, params=params)[1]
    assert [s["device_id"] for s in seats["items"]] == ["dev-a"]

    rel = {"license_id": lic["license_id"], "device_id": "dev-a"}
    assert call("DELETE /v1/admin/licenses/{license_id}/seats/{device_id}",
                key=admin_a, params=rel)[0] == 200
    assert call("DELETE /v1/admin/licenses/{license_id}/seats/{device_id}",
                key=admin_a, params=rel)[0] == 404
    assert verify(lic["license_key"], "dev-b")[0] == 200
    assert call("GET /v1/admin/licenses/{license_id}", key=admin_a,
                params=params)[1]["seats_used"] == 1


def test_api_key_lifecycle(two_tenants):
    admin_a, _ = two_tenants
    only = call("GET /v1/admin/api-keys", key=admin_a)[1]["items"]
    assert len(only) == 1
    # cannot revoke the last active key
    assert call("DELETE /v1/admin/api-keys/{key_id}", key=admin_a,
                params={"key_id": only[0]["key_id"]})[0] == 409

    status, new = call("POST /v1/admin/api-keys", {"label": "ci"}, key=admin_a)
    assert status == 201 and new["api_key"].startswith("mcpk_")
    assert "key_hash" not in new
    assert call("GET /v1/admin/tenant", key=new["api_key"])[0] == 200

    assert call("DELETE /v1/admin/api-keys/{key_id}", key=admin_a,
                params={"key_id": only[0]["key_id"]})[0] == 200
    assert call("GET /v1/admin/tenant", key=admin_a)[0] == 401  # revoked key stops working
    assert call("GET /v1/admin/tenant", key=new["api_key"])[0] == 200

    listed = call("GET /v1/admin/api-keys", key=new["api_key"])[1]["items"]
    assert all("api_key" not in i and "key_hash" not in i for i in listed)


def test_expired_api_key_is_rejected(super_key):
    tenant = create_tenant(super_key)
    key_id = keys.parse_api_key(tenant["admin_api_key"])
    store.update_api_key(key_id, {"expires_at": "2000-01-01T00:00:00Z"})
    assert call("GET /v1/admin/tenant", key=tenant["admin_api_key"])[0] == 401


def test_unknown_route_and_bad_json():
    assert call("GET /v1/admin/nothing", key="x")[0] == 404
    from handlers import admin
    resp = admin.handler({"routeKey": "POST /v1/admin/licenses", "body": "{not json",
                          "headers": {}}, None)
    assert resp["statusCode"] in (400, 401)
