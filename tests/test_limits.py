"""Platform limits and tenant ids.

Every number comes from SSM (/mcp/<stage>/limit_*) with an optional override per
tenant (/mcp/<stage>/tenants/<tenant_id>/limit_*), read by the Lambdas without a
redeploy."""
import re

import boto3
import pytest

from core import config, keys, service
from helpers import call, create_license, create_tenant, verify

PREFIX = "/mcp/test"


@pytest.fixture(autouse=True)
def ssm_prefix(monkeypatch):
    monkeypatch.setenv("SSM_PREFIX", PREFIX)
    config.reset_cache()


def put(name, value, tenant_id=None):
    path = "{}/tenants/{}/{}".format(PREFIX, tenant_id, name) if tenant_id else "{}/{}".format(PREFIX, name)
    boto3.client("ssm").put_parameter(Name=path, Value=str(value), Type="String", Overwrite=True)
    config.reset_cache()


@pytest.fixture
def tenant(super_key):
    return create_tenant(super_key)["admin_api_key"]


def limit_error(response):
    status, body = response
    return status == 403 and body["error"]["code"] == "LIMIT_REACHED"


# ------------------------------------------------------------------ defaults

def test_tenant_sees_its_limits_and_usage(tenant):
    status, view = call("GET /v1/admin/tenant", key=tenant)
    assert status == 200
    assert view["limits"] == {"licenses": 50, "seats_per_license": 10, "seats_per_tenant": 200,
                              "api_keys": 5, "verify_per_min": 100}
    assert view["usage"] == {"licenses": 0, "seats": 0, "api_keys": 1}  # the initial admin key
    create_license(tenant, seats_max=4)
    assert call("GET /v1/admin/tenant", key=tenant)[1]["usage"]["seats"] == 4


def test_defaults_can_be_changed_in_ssm_without_a_deploy(tenant):
    put("limit_seats_per_license", 3)
    assert limit_error(call("POST /v1/admin/licenses", {"seats_max": 4}, key=tenant))
    assert call("POST /v1/admin/licenses", {"seats_max": 3}, key=tenant)[0] == 201


# ------------------------------------------------------------------- licenses

def test_seats_per_license(tenant):
    assert limit_error(call("POST /v1/admin/licenses", {"seats_max": 11}, key=tenant))
    assert call("POST /v1/admin/licenses", {"seats_max": 10}, key=tenant)[0] == 201


def test_licenses_per_tenant_counts_active_ones_only(tenant):
    put("limit_licenses_per_tenant", 2, "acme")
    first = create_license(tenant)
    create_license(tenant)
    assert limit_error(call("POST /v1/admin/licenses", {}, key=tenant))

    call("PUT /v1/admin/licenses/{license_id}/status", {"status": "REVOKED"}, key=tenant,
         params={"license_id": first["license_id"]})
    assert call("POST /v1/admin/licenses", {}, key=tenant)[0] == 201  # a revoked license frees its place

    # bringing the revoked one back would be a third active license
    assert limit_error(call("PUT /v1/admin/licenses/{license_id}/status", {"status": "ACTIVE"},
                            key=tenant, params={"license_id": first["license_id"]}))


def test_seats_per_tenant(tenant):
    put("limit_seats_per_tenant", 15, "acme")
    create_license(tenant, seats_max=10)
    assert limit_error(call("POST /v1/admin/licenses", {"seats_max": 6}, key=tenant))
    assert call("POST /v1/admin/licenses", {"seats_max": 5}, key=tenant)[0] == 201


def test_growing_a_license_is_checked_shrinking_and_renaming_are_not(tenant):
    lic = create_license(tenant, seats_max=5)
    params = {"license_id": lic["license_id"]}
    assert limit_error(call("PATCH /v1/admin/licenses/{license_id}", {"seats_max": 11}, key=tenant,
                            params=params))
    assert call("PATCH /v1/admin/licenses/{license_id}", {"seats_max": 10}, key=tenant,
                params=params)[0] == 200
    assert call("PATCH /v1/admin/licenses/{license_id}", {"seats_max": 2}, key=tenant,
                params=params)[0] == 200


def test_limits_are_not_retroactive(tenant):
    """A license that was fine when it was made keeps working and stays editable
    after the limit is lowered."""
    put("limit_seats_per_license", 100, "acme")
    big = create_license(tenant, seats_max=60)
    boto3.client("ssm").delete_parameter(Name="{}/tenants/acme/limit_seats_per_license".format(PREFIX))
    config.reset_cache()

    params = {"license_id": big["license_id"]}
    assert call("PATCH /v1/admin/licenses/{license_id}", {"label": "renamed"}, key=tenant,
                params=params)[0] == 200
    assert verify(big["license_key"])[0] == 200
    assert limit_error(call("PATCH /v1/admin/licenses/{license_id}", {"seats_max": 61}, key=tenant,
                            params=params))


# -------------------------------------------------------------------- api keys

def test_api_keys_per_tenant(super_key, tenant):
    for _ in range(4):  # the initial key plus four more is the default five
        assert call("POST /v1/admin/api-keys", {}, key=tenant)[0] == 201
    assert limit_error(call("POST /v1/admin/api-keys", {}, key=tenant))

    keys_listed = call("GET /v1/admin/api-keys", key=tenant)[1]["items"]
    call("DELETE /v1/admin/api-keys/{key_id}", key=tenant, params={"key_id": keys_listed[-1]["key_id"]})
    assert call("POST /v1/admin/api-keys", {}, key=tenant)[0] == 201

    # the platform owner can still issue a recovery key
    assert call("POST /v1/super/tenants/{tenant_id}/api-keys", {}, key=super_key,
                params={"tenant_id": "acme"})[0] == 201


# ----------------------------------------------------------- per-tenant override

def test_an_override_applies_to_that_tenant_only(super_key, tenant):
    other = create_tenant(super_key, "globex")["admin_api_key"]
    put("limit_seats_per_license", 100, "acme")
    assert call("POST /v1/admin/licenses", {"seats_max": 50}, key=tenant)[0] == 201
    assert limit_error(call("POST /v1/admin/licenses", {"seats_max": 50}, key=other))
    assert call("GET /v1/admin/tenant", key=other)[1]["limits"]["seats_per_license"] == 10


def test_only_limits_can_be_overridden_per_tenant(tenant):
    put("default_seats_max", 9, "acme")  # not a limit: ignored for the tenant
    put("log_level", "DEBUG", "acme")
    assert config.get_int("default_seats_max", "acme") == 1
    assert config.tenant_overrides("acme") == {}


def test_a_tenant_path_cannot_be_forged(monkeypatch):
    def boom(path):
        raise AssertionError("SSM was queried for " + path)
    monkeypatch.setattr(config, "_read_path", boom)
    for bad in ("../acme", "acme/../x", "ACME", "a", "x" * 40, "", None):
        assert config.tenant_overrides(bad) == {}


# ------------------------------------------------------------------- freshness

def test_management_functions_read_ssm_on_every_request(monkeypatch, tenant):
    monkeypatch.setenv("CONFIG_CACHE_SECONDS", "0")
    put("limit_seats_per_license", 2)
    assert limit_error(call("POST /v1/admin/licenses", {"seats_max": 3}, key=tenant))
    # change the value in SSM only: no cache reset, no redeploy
    boto3.client("ssm").put_parameter(Name=PREFIX + "/limit_seats_per_license", Value="4",
                                      Type="String", Overwrite=True)
    assert call("POST /v1/admin/licenses", {"seats_max": 3}, key=tenant)[0] == 201


def test_a_warm_container_may_reuse_what_it_read_for_a_minute(monkeypatch, tenant):
    monkeypatch.setenv("CONFIG_CACHE_SECONDS", "60")
    put("limit_seats_per_license", 2)
    assert limit_error(call("POST /v1/admin/licenses", {"seats_max": 3}, key=tenant))
    boto3.client("ssm").put_parameter(Name=PREFIX + "/limit_seats_per_license", Value="4",
                                      Type="String", Overwrite=True)
    assert limit_error(call("POST /v1/admin/licenses", {"seats_max": 3}, key=tenant))  # still cached
    config.reset_cache()
    assert call("POST /v1/admin/licenses", {"seats_max": 3}, key=tenant)[0] == 201


def test_ssm_outage_falls_back_to_the_built_in_defaults(monkeypatch, tenant):
    def down(path):
        raise RuntimeError("SSM unavailable")
    monkeypatch.setattr(config, "_read_path", down)
    config.reset_cache()
    assert call("POST /v1/admin/licenses", {"seats_max": 10}, key=tenant)[0] == 201
    assert limit_error(call("POST /v1/admin/licenses", {"seats_max": 11}, key=tenant))


# ------------------------------------------------------------------ tenant ids

def test_generated_tenant_id_format():
    pattern = re.compile(r"^mcp-[a-hj-np-z2-9]{6}$")  # unambiguous alphabet: no 0/1/i/o
    ids = {keys.generate_tenant_id() for _ in range(200)}
    assert all(pattern.match(i) for i in ids)
    assert len(ids) == 200  # about a billion combinations: no repeats in 200 draws
    assert all(keys.is_valid_tenant_id(i) for i in ids)


@pytest.mark.parametrize("tenant_id,valid", [
    ("acme", True), ("sfs", True), ("a" * 12, True), ("mcp-k7m2x9", True),
    ("mcp-k7m2x0", False),   # 0 is not in the alphabet
    ("mcp-k7m2", False), ("mcp-k7m2x9z", False), ("MCP-K7M2X9", False),  # stored lowercase
    ("mcp_k7m2x9", False), ("ab", False), ("a" * 13, False), ("acme-co", False), (None, False),
])
def test_tenant_id_validation(tenant_id, valid):
    assert keys.is_valid_tenant_id(tenant_id) is valid


def test_platform_creates_a_tenant_with_a_generated_id(super_key):
    status, body = call("POST /v1/super/tenants", {"company_name": "Acme", "email": "a@example.com"},
                        key=super_key)
    assert status == 201 and re.match(r"^mcp-[a-hj-np-z2-9]{6}$", body["tenant_id"])

    lic = create_license(body["admin_api_key"])
    assert lic["license_key"].startswith(body["tenant_id"] + "_")
    status, result = verify(lic["license_key"])
    assert status == 200 and result["tenant_id"] == body["tenant_id"]
    # people type keys in any case, and the capitalised tenant id is the display form
    assert verify(lic["license_key"].upper())[0] == 200
    assert verify(lic["license_key"].lower())[0] == 200


def test_a_chosen_tenant_id_still_works_and_a_bad_one_is_refused(super_key):
    assert call("POST /v1/super/tenants", {"tenant_id": "sfs", "company_name": "S", "email": "s@example.com"},
                key=super_key)[0] == 201
    assert call("POST /v1/super/tenants", {"tenant_id": "SFS", "company_name": "S", "email": "s@example.com"},
                key=super_key)[0] == 400
    assert call("POST /v1/super/tenants", {"tenant_id": "sfs", "company_name": "S", "email": "s@example.com"},
                key=super_key)[0] == 409


def test_a_collision_on_a_generated_id_picks_another(super_key, monkeypatch):
    create_tenant(super_key, "mcp-aaaaaa")
    ids = iter(["mcp-aaaaaa", "mcp-aaaaaa", "mcp-bbbbbb"])
    monkeypatch.setattr(keys, "generate_tenant_id", lambda: next(ids))
    status, body = call("POST /v1/super/tenants", {"company_name": "B", "email": "b@example.com"},
                        key=super_key)
    assert status == 201 and body["tenant_id"] == "mcp-bbbbbb"


def test_service_gives_up_after_repeated_collisions(super_key, monkeypatch):
    create_tenant(super_key, "mcp-aaaaaa")
    monkeypatch.setattr(keys, "generate_tenant_id", lambda: "mcp-aaaaaa")
    status, body = call("POST /v1/super/tenants", {"company_name": "B", "email": "b@example.com"},
                        key=super_key)
    assert status == 503 and body["error"]["code"] == "BUSY"
    assert service.GENERATE_ATTEMPTS >= 3
