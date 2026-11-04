import boto3

from core import config
from helpers import call, create_license, create_tenant


def test_create_tenant_validation_and_duplicates(super_key):
    for bad in [{"tenant_id": "AB"}, {"tenant_id": "has_underscore", "company_name": "x", "email": "e"},
                {"tenant_id": "okid"}]:
        assert call("POST /v1/super/tenants", bad, key=super_key)[0] == 400, bad
    create_tenant(super_key, "acme")
    status, body = call("POST /v1/super/tenants",
                        {"tenant_id": "acme", "company_name": "x", "email": "e"}, key=super_key)
    assert status == 409 and body["error"]["code"] == "TENANT_EXISTS"


def test_tenant_admin_key_is_returned_once_and_works(super_key):
    created = create_tenant(super_key)
    assert created["admin_api_key"].startswith("mcpk_")
    fetched = call("GET /v1/super/tenants/{tenant_id}", key=super_key,
                   params={"tenant_id": "acme"})[1]
    assert "admin_api_key" not in fetched
    assert call("GET /v1/admin/tenant", key=created["admin_api_key"])[0] == 200


def test_list_update_and_support_views(super_key):
    create_tenant(super_key, "acme")
    other = create_tenant(super_key, "globex")
    create_license(other["admin_api_key"])
    names = {t["tenant_id"] for t in call("GET /v1/super/tenants", key=super_key)[1]["items"]}
    assert names == {"acme", "globex"}
    assert call("PATCH /v1/super/tenants/{tenant_id}", {"company_name": "Acme Corp"},
                key=super_key, params={"tenant_id": "acme"})[1]["company_name"] == "Acme Corp"
    assert call("PATCH /v1/super/tenants/{tenant_id}", {}, key=super_key,
                params={"tenant_id": "acme"})[0] == 400
    lics = call("GET /v1/super/tenants/{tenant_id}/licenses", key=super_key,
                params={"tenant_id": "globex"})[1]["items"]
    assert len(lics) == 1 and "key_hash" not in lics[0]
    assert call("GET /v1/super/tenants/{tenant_id}", key=super_key,
                params={"tenant_id": "missing"})[0] == 404


def test_issue_replacement_admin_key(super_key):
    created = create_tenant(super_key)
    status, issued = call("POST /v1/super/tenants/{tenant_id}/api-keys", {"label": "recovery"},
                          key=super_key, params={"tenant_id": "acme"})
    assert status == 201
    assert call("GET /v1/admin/tenant", key=issued["api_key"])[0] == 200
    assert call("POST /v1/super/tenants/{tenant_id}/api-keys", {}, key=super_key,
                params={"tenant_id": "missing"})[0] == 404
    assert created["admin_api_key"] != issued["api_key"]


def test_kill_switch_state_and_audit(super_key):
    assert call("GET /v1/super/kill-switch", key=super_key)[1]["enabled"] is False
    assert call("PUT /v1/super/kill-switch", {"enabled": "yes"}, key=super_key)[0] == 400
    call("PUT /v1/super/kill-switch", {"enabled": True, "reason": "breach"}, key=super_key)
    state = call("GET /v1/super/kill-switch", key=super_key)[1]
    assert state["enabled"] is True and state["reason"] == "breach"
    events = [i["event_type"] for i in
              call("GET /v1/super/audit-log", key=super_key)[1]["items"]]
    assert events[0] == "kill_switch.enabled"


def test_pagination(super_key):
    for i in range(5):
        create_tenant(super_key, "t{}x".format(i))
    seen, token = [], None
    while True:
        query = {"limit": "2"}
        if token:
            query["next_token"] = token
        body = call("GET /v1/super/tenants", key=super_key, query=query)[1]
        seen.extend(t["tenant_id"] for t in body["items"])
        token = body["next_token"]
        if not token:
            break
    assert sorted(seen) == ["t0x", "t1x", "t2x", "t3x", "t4x"]
    assert call("GET /v1/super/tenants", key=super_key,
                query={"next_token": "garbage"})[0] == 400


def test_settings_are_read_from_ssm(monkeypatch):
    ssm = boto3.client("ssm")
    ssm.put_parameter(Name="/mcp/test/default_seats_max", Value="7", Type="String")
    ssm.put_parameter(Name="/mcp/test/client_cache_ttl_seconds", Value="60", Type="String")
    monkeypatch.setenv("SSM_PREFIX", "/mcp/test")
    config.reset_cache()
    assert config.get_int("default_seats_max") == 7
    assert config.get_int("client_cache_ttl_seconds") == 60
    assert config.get_int("default_lease_duration_sec") == 86400  # not set: default
