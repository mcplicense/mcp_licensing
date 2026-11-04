from core import store
from helpers import call, create_license, create_tenant, verify


def _setup(super_key, **license_body):
    tenant = create_tenant(super_key)
    lic = create_license(tenant["admin_api_key"], **license_body)
    return tenant["admin_api_key"], lic


def test_valid_license(super_key):
    _, lic = _setup(super_key, seats_max=2)
    status, body = verify(lic["license_key"])
    assert status == 200 and body["valid"] is True
    assert body["tenant_id"] == "acme"
    assert body["seats_used"] == 1 and body["seats_max"] == 2
    assert body["cache_ttl_seconds"] == 300 and body["lease_duration_sec"] == 86400
    assert body["lease_expires_at"] > 0


def test_client_sends_only_key_and_device(super_key):
    _, lic = _setup(super_key)
    status, body = call("POST /v1/mcp/verify",
                        {"license_key": lic["license_key"].lower(), "device_id": "d"})
    assert status == 200, body


def test_bad_input(super_key):
    assert call("POST /v1/mcp/verify", {"device_id": "d"})[0] == 400
    assert call("POST /v1/mcp/verify", {"license_key": "x"})[0] == 400
    assert call("POST /v1/mcp/verify", {"license_key": "x", "device_id": "d" * 200})[0] == 400


def test_unknown_wrong_and_malformed_keys_look_identical(super_key):
    _, lic = _setup(super_key)
    wrong = "acme_AAAAA-AAAAA-AAAAA-AAAAA-AAAAA"
    unknown_tenant = "nobody_AAAAA-AAAAA-AAAAA-AAAAA-AAAAA"
    results = [verify(k) for k in (wrong, unknown_tenant, "garbage")]
    assert all(r == results[0] for r in results)
    assert results[0][0] == 401 and results[0][1]["reason"] == "INVALID_KEY"


def test_key_does_not_work_under_another_tenant_prefix(super_key):
    _, lic = _setup(super_key)
    create_tenant(super_key, "other")
    swapped = "other_" + lic["license_key"].split("_", 1)[1]
    assert verify(swapped)[1]["reason"] == "INVALID_KEY"


def test_seat_limit_and_idempotent_device(super_key):
    _, lic = _setup(super_key, seats_max=1)
    assert verify(lic["license_key"], "a")[0] == 200
    assert verify(lic["license_key"], "a")[0] == 200  # same device, no extra seat
    status, body = verify(lic["license_key"], "b")
    assert status == 403 and body["reason"] == "SEAT_LIMIT"


def test_expired_license(super_key):
    admin_key, lic = _setup(super_key)
    call("PATCH /v1/admin/licenses/{license_id}", {"expires_at": "2000-01-01"},
         key=admin_key, params={"license_id": lic["license_id"]})
    status, body = verify(lic["license_key"])
    assert status == 403 and body["reason"] == "LICENSE_EXPIRED"


def test_revoked_license_and_reinstate(super_key):
    admin_key, lic = _setup(super_key)
    route, params = "PUT /v1/admin/licenses/{license_id}/status", {"license_id": lic["license_id"]}
    call(route, {"status": "REVOKED"}, key=admin_key, params=params)
    assert verify(lic["license_key"])[1]["reason"] == "LICENSE_REVOKED"
    call(route, {"status": "ACTIVE"}, key=admin_key, params=params)
    assert verify(lic["license_key"])[0] == 200


def test_tenant_kill_switch_by_tenant_admin(super_key):
    admin_key, lic = _setup(super_key)
    assert verify(lic["license_key"])[0] == 200
    call("PUT /v1/admin/tenant/status", {"suspended": True, "reason": "incident"}, key=admin_key)
    status, body = verify(lic["license_key"])
    assert status == 403 and body["reason"] == "TENANT_DISABLED"
    call("PUT /v1/admin/tenant/status", {"suspended": False}, key=admin_key)
    assert verify(lic["license_key"])[0] == 200


def test_tenant_kill_switch_by_platform_cannot_be_lifted_by_tenant(super_key):
    admin_key, lic = _setup(super_key)
    call("PUT /v1/super/tenants/{tenant_id}/status", {"disabled": True, "reason": "unpaid"},
         key=super_key, params={"tenant_id": "acme"})
    assert verify(lic["license_key"])[1]["reason"] == "TENANT_DISABLED"
    # tenant admin "resumes" - the platform flag still blocks
    call("PUT /v1/admin/tenant/status", {"suspended": False}, key=admin_key)
    assert verify(lic["license_key"])[1]["reason"] == "TENANT_DISABLED"
    call("PUT /v1/super/tenants/{tenant_id}/status", {"disabled": False},
         key=super_key, params={"tenant_id": "acme"})
    assert verify(lic["license_key"])[0] == 200


def test_global_kill_switch_hits_every_tenant(super_key):
    _, lic_a = _setup(super_key)
    other = create_tenant(super_key, "other")
    lic_b = create_license(other["admin_api_key"])
    assert call("PUT /v1/super/kill-switch", {"enabled": True, "reason": "breach"},
                key=super_key)[0] == 200
    for lic in (lic_a, lic_b):
        status, body = verify(lic["license_key"])
        assert status == 403 and body["reason"] == "GLOBAL_DISABLED"
    call("PUT /v1/super/kill-switch", {"enabled": False}, key=super_key)
    assert verify(lic_a["license_key"])[0] == 200
    assert verify(lic_b["license_key"])[0] == 200


def test_rotated_key_replaces_old_one(super_key):
    admin_key, lic = _setup(super_key)
    status, rotated = call("POST /v1/admin/licenses/{license_id}/rotate-key", key=admin_key,
                           params={"license_id": lic["license_id"]})
    assert status == 200
    assert verify(lic["license_key"])[1]["reason"] == "INVALID_KEY"
    assert verify(rotated["license_key"])[0] == 200


def test_stored_license_has_only_a_hash(super_key):
    _, lic = _setup(super_key)
    row = store.get_license("acme", lic["license_id"])
    assert lic["license_key"] not in str(row)
    assert "license_key" not in row
