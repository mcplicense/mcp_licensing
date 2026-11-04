"""Per-tenant rate limit on verify: 100 requests per minute by default, set in
SSM (/mcp/<stage>/limit_verify_per_min) and overridable for one tenant
(/mcp/<stage>/tenants/<tenant_id>/limit_verify_per_min)."""
import time
from concurrent.futures import ThreadPoolExecutor

import boto3
import pytest
from botocore.exceptions import ClientError

from core import config, store
from helpers import call, create_license, create_tenant, verify

PREFIX = "/mcp/test"


@pytest.fixture(autouse=True)
def ssm_prefix(monkeypatch):
    monkeypatch.setenv("SSM_PREFIX", PREFIX)
    config.reset_cache()


@pytest.fixture
def clock(monkeypatch):
    """A controllable clock that starts 10 seconds into a minute."""
    state = {"t": (int(time.time()) // 60) * 60 + 10}
    monkeypatch.setattr(store, "now_epoch", lambda: state["t"])
    return state


@pytest.fixture
def tenant(super_key):
    return create_tenant(super_key)["admin_api_key"]


def _statuses(license_key, count, device="device-1"):  # same default device as helpers.verify
    return [verify(license_key, device)[0] for _ in range(count)]


def _set_limit(tenant_id, value):
    """Set (or, with None, remove) a tenant's override in SSM, as the operator would."""
    ssm = boto3.client("ssm")
    name = "{}/tenants/{}/limit_verify_per_min".format(PREFIX, tenant_id)
    if value is None:
        ssm.delete_parameter(Name=name)
    else:
        ssm.put_parameter(Name=name, Value=str(value), Type="String", Overwrite=True)
    config.reset_cache()


# ------------------------------------------------------------------ default

def test_default_is_100_requests_per_minute(tenant, clock):
    lic = create_license(tenant)
    statuses = _statuses(lic["license_key"], 101)
    assert statuses[:100] == [200] * 100
    assert statuses[100] == 429


def test_refusal_says_what_happened_and_when_to_retry(tenant, clock):
    lic = create_license(tenant)
    _statuses(lic["license_key"], 100)
    status, body = verify(lic["license_key"])
    assert status == 429
    assert body["valid"] is False and body["reason"] == "RATE_LIMITED"
    assert body["retry_after_seconds"] == 50  # the minute started 10 seconds ago


def test_a_new_minute_starts_a_new_count(tenant, clock):
    lic = create_license(tenant)
    assert _statuses(lic["license_key"], 101)[-1] == 429
    clock["t"] += 50  # next minute
    assert verify(lic["license_key"])[0] == 200


def test_1000_requests_in_two_minutes_are_cut_to_100_per_minute(tenant, clock):
    lic = create_license(tenant, seats_max=5)
    statuses = []
    for _ in range(2):  # two minutes of 500 requests each
        statuses += _statuses(lic["license_key"], 500)
        clock["t"] += 60
    assert len(statuses) == 1000
    assert statuses.count(200) == 200
    assert statuses.count(429) == 800


# ------------------------------------------------------------- SSM default

def test_default_comes_from_ssm(tenant, clock):
    boto3.client("ssm").put_parameter(Name=PREFIX + "/limit_verify_per_min", Value="3", Type="String")
    config.reset_cache()

    lic = create_license(tenant)
    assert _statuses(lic["license_key"], 4) == [200, 200, 200, 429]


# ----------------------------------------------------- per-tenant override

def test_operator_can_raise_the_limit_for_one_tenant(super_key, tenant, clock):
    other = create_tenant(super_key, "globex")["admin_api_key"]
    _set_limit("acme", 150)
    assert call("GET /v1/admin/tenant", key=tenant)[1]["limits"]["verify_per_min"] == 150

    acme = create_license(tenant)
    globex = create_license(other)
    assert _statuses(acme["license_key"], 150) == [200] * 150
    assert verify(acme["license_key"])[0] == 429

    # globex still has the default, and acme's traffic did not touch its count
    assert _statuses(globex["license_key"], 101)[-2:] == [200, 429]


def test_override_can_also_lower_the_limit(super_key, tenant, clock):
    _set_limit("acme", 2)
    lic = create_license(tenant)
    assert _statuses(lic["license_key"], 3) == [200, 200, 429]


def test_removing_the_override_restores_the_default(super_key, tenant, clock):
    _set_limit("acme", 2)
    _set_limit("acme", None)
    assert call("GET /v1/admin/tenant", key=tenant)[1]["limits"]["verify_per_min"] == 100
    assert _statuses(create_license(tenant)["license_key"], 5) == [200] * 5


def test_tenant_admin_sees_the_limit_but_cannot_change_it(super_key, tenant):
    _set_limit("acme", 250)
    status, view = call("GET /v1/admin/tenant", key=tenant)
    assert status == 200 and view["limits"]["verify_per_min"] == 250

    # no API route changes it: tenant admins and the platform API both ignore the field
    assert call("PATCH /v1/admin/tenant", {"limit_verify_per_min": 100000}, key=tenant)[0] == 400
    assert call("PATCH /v1/super/tenants/{tenant_id}", {"limit_verify_per_min": 5},
                key=super_key, params={"tenant_id": "acme"})[0] == 400
    assert call("GET /v1/admin/tenant", key=tenant)[1]["limits"]["verify_per_min"] == 250


@pytest.mark.parametrize("junk", ["abc", "", "1.5"])
def test_a_junk_value_in_ssm_falls_back_to_the_default(tenant, clock, junk):
    boto3.client("ssm").put_parameter(Name=PREFIX + "/tenants/acme/limit_verify_per_min",
                                      Value=junk or " ", Type="String")
    config.reset_cache()
    assert call("GET /v1/admin/tenant", key=tenant)[1]["limits"]["verify_per_min"] == 100


# ------------------------------------- nobody without a working key can count

def test_wrong_revoked_and_expired_keys_never_use_up_the_quota(super_key, tenant, clock):
    _set_limit("acme", 3)
    lic = create_license(tenant)
    params = {"license_id": lic["license_id"]}

    wrong = "acme_AAAAA-AAAAA-AAAAA-AAAAA-AAAAA"
    assert [verify(wrong)[0] for _ in range(20)] == [401] * 20

    call("PUT /v1/admin/licenses/{license_id}/status", {"status": "REVOKED"}, key=tenant, params=params)
    assert _statuses(lic["license_key"], 20) == [403] * 20
    call("PUT /v1/admin/licenses/{license_id}/status", {"status": "ACTIVE"}, key=tenant, params=params)

    assert _statuses(lic["license_key"], 4) == [200, 200, 200, 429]  # full quota was still there


def test_disabled_tenant_requests_are_not_counted(super_key, tenant, clock):
    _set_limit("acme", 3)
    lic = create_license(tenant)
    call("PUT /v1/super/tenants/{tenant_id}/status", {"disabled": True}, key=super_key,
         params={"tenant_id": "acme"})
    assert _statuses(lic["license_key"], 10) == [403] * 10
    call("PUT /v1/super/tenants/{tenant_id}/status", {"disabled": False}, key=super_key,
         params={"tenant_id": "acme"})
    assert _statuses(lic["license_key"], 4) == [200, 200, 200, 429]


# ----------------------------------------------------------- what is refused

def test_a_refused_request_takes_no_seat_and_renews_nothing(super_key, tenant, clock):
    _set_limit("acme", 2)
    lic = create_license(tenant, seats_max=5)
    verify(lic["license_key"], "dev-a")
    verify(lic["license_key"], "dev-b")
    first_lease = int(store.get_seat("acme", lic["license_id"], "dev-a")["lease_expires_at"])

    clock["t"] += 5
    assert verify(lic["license_key"], "dev-c")[0] == 429
    assert verify(lic["license_key"], "dev-a")[0] == 429

    assert store.get_seat("acme", lic["license_id"], "dev-c") is None
    assert int(store.get_license("acme", lic["license_id"], consistent=True)["seats_used"]) == 2
    assert int(store.get_seat("acme", lic["license_id"], "dev-a")["lease_expires_at"]) == first_lease


def test_global_kill_switch_still_comes_first(super_key, tenant, clock):
    _set_limit("acme", 1)
    lic = create_license(tenant)
    verify(lic["license_key"])
    call("PUT /v1/super/kill-switch", {"enabled": True}, key=super_key)
    assert verify(lic["license_key"])[1]["reason"] == "GLOBAL_DISABLED"


# ------------------------------------------------------------ concurrency

def test_concurrent_requests_cannot_exceed_the_limit(super_key, tenant, clock):
    _set_limit("acme", 50)
    boto3.client("ssm").put_parameter(Name=PREFIX + "/tenants/acme/limit_seats_per_license",
                                      Value="100", Type="String")  # an operator override
    config.reset_cache()
    lic = create_license(tenant, seats_max=100)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda i: verify(lic["license_key"], "dev-{}".format(i))[0], range(80)))

    assert results.count(200) == 50
    assert results.count(429) == 30


# --------------------------------------------------------------- resilience

def test_counter_outage_does_not_take_verification_down(tenant, clock, monkeypatch):
    lic = create_license(tenant)
    real_table = store._table

    class BrokenTable:
        def update_item(self, **kwargs):
            raise ClientError({"Error": {"Code": "InternalServerError", "Message": "boom"}}, "UpdateItem")

    monkeypatch.setattr(store, "_table",
                        lambda env_var: BrokenTable() if env_var == "RATE_TABLE" else real_table(env_var))
    assert verify(lic["license_key"])[0] == 200
