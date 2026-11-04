"""Seat leases: a device that stops checking in loses its seat automatically."""
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from core import store
from helpers import call, create_license, create_tenant, verify

DAY = 86400


@pytest.fixture
def clock(monkeypatch):
    state = {"t": int(time.time())}
    monkeypatch.setattr(store, "now_epoch", lambda: state["t"])
    return state


@pytest.fixture
def tenant(super_key):
    return create_tenant(super_key)["admin_api_key"]


def _seat(license_id, device_id):
    return store.get_seat("acme", license_id, device_id)


def _used(license_id):
    return int(store.get_license("acme", license_id, consistent=True)["seats_used"])


def _devices(license_id):
    return sorted(s["device_id"] for s in store.list_seats("acme", license_id))


# ----------------------------------------------------------------- the lease

def test_default_lease_is_24_hours_and_stored_on_the_seat(tenant, clock):
    lic = create_license(tenant)
    status, body = verify(lic["license_key"], "dev-a")
    assert status == 200
    assert body["lease_duration_sec"] == DAY
    assert body["lease_expires_at"] == clock["t"] + DAY
    assert int(_seat(lic["license_id"], "dev-a")["lease_expires_at"]) == clock["t"] + DAY


def test_every_check_in_renews_the_lease(tenant, clock):
    lic = create_license(tenant, seats_max=2)
    verify(lic["license_key"], "dev-a")
    clock["t"] += 5000
    status, body = verify(lic["license_key"], "dev-a")
    assert body["lease_expires_at"] == clock["t"] + DAY
    assert int(_seat(lic["license_id"], "dev-a")["lease_expires_at"]) == clock["t"] + DAY
    assert _used(lic["license_id"]) == 1  # renewing does not take a second seat


def test_denied_checks_do_not_renew(tenant, clock):
    lic = create_license(tenant, seats_max=1)
    verify(lic["license_key"], "dev-a")
    first = int(_seat(lic["license_id"], "dev-a")["lease_expires_at"])
    clock["t"] += 100
    call("PUT /v1/admin/licenses/{license_id}/status", {"status": "REVOKED"}, key=tenant,
         params={"license_id": lic["license_id"]})
    assert verify(lic["license_key"], "dev-a")[0] == 403
    assert int(_seat(lic["license_id"], "dev-a")["lease_expires_at"]) == first


# --------------------------------------------------------------- overrides

def test_override_precedence_license_then_tenant_then_global(tenant, clock):
    plain = create_license(tenant)
    special = create_license(tenant, lease_duration_sec=3600)

    assert verify(plain["license_key"])[1]["lease_duration_sec"] == DAY

    status, view = call("PATCH /v1/admin/tenant", {"lease_duration_sec": 7200}, key=tenant)
    assert status == 200 and view["lease_duration_sec"] == 7200
    assert verify(plain["license_key"])[1]["lease_duration_sec"] == 7200
    assert verify(special["license_key"])[1]["lease_duration_sec"] == 3600  # license wins

    call("PATCH /v1/admin/licenses/{license_id}", {"lease_duration_sec": None}, key=tenant,
         params={"license_id": special["license_id"]})
    assert verify(special["license_key"])[1]["lease_duration_sec"] == 7200  # falls back to tenant

    call("PATCH /v1/admin/tenant", {"lease_duration_sec": None}, key=tenant)
    assert verify(plain["license_key"])[1]["lease_duration_sec"] == DAY  # falls back to global


def test_super_admin_can_set_a_tenant_lease(super_key, tenant):
    status, view = call("PATCH /v1/super/tenants/{tenant_id}", {"lease_duration_sec": 1800},
                        key=super_key, params={"tenant_id": "acme"})
    assert status == 200 and view["lease_duration_sec"] == 1800
    assert verify(create_license(tenant)["license_key"])[1]["lease_duration_sec"] == 1800


def test_tenant_override_is_per_tenant(super_key, tenant):
    other = create_tenant(super_key, "globex")["admin_api_key"]
    call("PATCH /v1/admin/tenant", {"lease_duration_sec": 600}, key=tenant)
    assert verify(create_license(other)["license_key"])[1]["lease_duration_sec"] == DAY


@pytest.mark.parametrize("bad", [10, 299, 2592001, "3600", True, 1.5])
def test_lease_bounds_are_validated(tenant, bad):
    assert call("PATCH /v1/admin/tenant", {"lease_duration_sec": bad}, key=tenant)[0] == 400
    assert call("POST /v1/admin/licenses", {"lease_duration_sec": bad}, key=tenant)[0] == 400
    lic = create_license(tenant)
    assert call("PATCH /v1/admin/licenses/{license_id}", {"lease_duration_sec": bad},
                key=tenant, params={"license_id": lic["license_id"]})[0] == 400


def test_empty_tenant_patch_is_rejected(tenant):
    assert call("PATCH /v1/admin/tenant", {}, key=tenant)[0] == 400


def test_client_recheck_interval_stays_inside_the_lease(tenant, clock):
    call("PATCH /v1/admin/tenant", {"lease_duration_sec": 600}, key=tenant)
    body = verify(create_license(tenant)["license_key"])[1]
    assert body["cache_ttl_seconds"] == 200  # a third of the lease, below the 300s default


# ---------------------------------------------------- automatic release

def test_expired_seat_is_given_to_a_new_device(tenant, clock):
    lic = create_license(tenant, seats_max=1)
    assert verify(lic["license_key"], "dev-a")[0] == 200
    clock["t"] += DAY - 1
    assert verify(lic["license_key"], "dev-b")[1]["reason"] == "SEAT_LIMIT"  # still leased

    clock["t"] += 2  # now > lease_expires_at
    status, body = verify(lic["license_key"], "dev-b")
    assert status == 200 and body["seats_used"] == 1
    assert _devices(lic["license_id"]) == ["dev-b"]  # dev-a's seat was taken over
    assert _used(lic["license_id"]) == 1

    # dev-a comes back after losing its seat: dev-b holds the only one now
    status, body = verify(lic["license_key"], "dev-a")
    assert status == 403 and body["reason"] == "SEAT_LIMIT"


def test_seat_is_held_through_the_expiry_second_and_released_after(tenant, clock):
    lic = create_license(tenant, seats_max=1)
    verify(lic["license_key"], "dev-a")
    clock["t"] += DAY  # current_epoch == lease_expires_at: not yet released
    assert verify(lic["license_key"], "dev-b")[0] == 403
    clock["t"] += 1  # current_epoch > lease_expires_at
    assert verify(lic["license_key"], "dev-b")[0] == 200


def test_device_returning_before_anyone_took_its_seat_keeps_it(tenant, clock):
    lic = create_license(tenant, seats_max=1)
    verify(lic["license_key"], "dev-a")
    clock["t"] += 3 * DAY
    status, body = verify(lic["license_key"], "dev-a")
    assert status == 200 and body["seats_used"] == 1
    assert body["lease_expires_at"] == clock["t"] + DAY
    assert verify(lic["license_key"], "dev-b")[0] == 403  # it is live again


def test_only_expired_seats_are_taken_oldest_first(tenant, clock):
    lic = create_license(tenant, seats_max=3)
    verify(lic["license_key"], "old")
    clock["t"] += 100
    verify(lic["license_key"], "mid")
    clock["t"] += 100
    verify(lic["license_key"], "new")

    clock["t"] += DAY - 50  # leases end at +DAY, +DAY+100, +DAY+200; now is +DAY+150
    assert verify(lic["license_key"], "x")[0] == 200
    assert verify(lic["license_key"], "y")[0] == 200
    assert _devices(lic["license_id"]) == ["new", "x", "y"]
    assert verify(lic["license_key"], "z")[1]["reason"] == "SEAT_LIMIT"


def test_free_capacity_is_used_before_taking_over_an_expired_seat(tenant, clock):
    lic = create_license(tenant, seats_max=2)
    verify(lic["license_key"], "dev-a")
    clock["t"] += 2 * DAY
    verify(lic["license_key"], "dev-b")
    assert _devices(lic["license_id"]) == ["dev-a", "dev-b"]  # dev-a not disturbed
    assert _used(lic["license_id"]) == 2


def test_admin_sees_lease_state_and_can_free_an_expired_seat(tenant, clock):
    lic = create_license(tenant, seats_max=2)
    params = {"license_id": lic["license_id"]}
    verify(lic["license_key"], "dev-a")
    clock["t"] += 100
    verify(lic["license_key"], "dev-b")
    clock["t"] += DAY - 50  # dev-a expired, dev-b live

    seats = call("GET /v1/admin/licenses/{license_id}/seats", key=tenant, params=params)[1]["items"]
    by_device = {s["device_id"]: s for s in seats}
    assert by_device["dev-a"]["active"] is False and by_device["dev-b"]["active"] is True
    assert by_device["dev-b"]["lease_expires_at"] == clock["t"] + 50  # dev-b checked in 100s after dev-a

    view = call("GET /v1/admin/licenses/{license_id}", key=tenant, params=params)[1]
    assert view["seats_used"] == 2 and view["seats_active"] == 1

    assert call("DELETE /v1/admin/licenses/{license_id}/seats/{device_id}", key=tenant,
                params={"license_id": lic["license_id"], "device_id": "dev-a"})[0] == 200
    assert _used(lic["license_id"]) == 1


# ---------------------------------------------------------- concurrency

def test_reclaim_gives_an_expired_seat_to_exactly_one_device(tenant, clock):
    lic = create_license(tenant, seats_max=1)
    verify(lic["license_key"], "dev-a")
    clock["t"] += DAY + 1
    expired = _seat(lic["license_id"], "dev-a")
    now = clock["t"]

    first = store.reclaim_seat("acme", lic["license_id"], expired, "dev-b", "t", now + DAY, now)
    second = store.reclaim_seat("acme", lic["license_id"], expired, "dev-c", "t", now + DAY, now)
    assert first == store.SEAT_CREATED and second is None
    assert _devices(lic["license_id"]) == ["dev-b"]
    assert _used(lic["license_id"]) == 1


def test_a_device_that_renews_first_cannot_be_taken_over(tenant, clock):
    lic = create_license(tenant, seats_max=1)
    verify(lic["license_key"], "dev-a")
    clock["t"] += DAY + 1
    stale_view = _seat(lic["license_id"], "dev-a")  # a contender read it as expired
    now = clock["t"]

    verify(lic["license_key"], "dev-a")  # ...but dev-a checks in before the takeover lands
    result = store.reclaim_seat("acme", lic["license_id"], stale_view, "dev-b", "t",
                                now + DAY, now)
    assert result is None
    assert _devices(lic["license_id"]) == ["dev-a"]


def test_renew_never_resurrects_a_released_seat(tenant, clock):
    lic = create_license(tenant, seats_max=1)
    verify(lic["license_key"], "dev-a")
    store.release_seat("acme", lic["license_id"], "dev-a")
    assert store.renew_seat("acme", lic["license_id"], "dev-a", "t", clock["t"] + DAY) is False
    assert _devices(lic["license_id"]) == [] and _used(lic["license_id"]) == 0


def test_many_new_devices_race_for_one_expired_seat(tenant, clock):
    lic = create_license(tenant, seats_max=1)
    verify(lic["license_key"], "dev-a")
    clock["t"] += DAY + 1

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda i: verify(lic["license_key"], "new-{}".format(i)),
                                range(10)))

    statuses = [s for s, _ in results]
    assert statuses.count(200) == 1 and statuses.count(403) == 9
    assert _used(lic["license_id"]) == 1
    assert len(_devices(lic["license_id"])) == 1
    assert "dev-a" not in _devices(lic["license_id"])


def test_expired_and_live_seats_under_concurrency_never_exceed_max(tenant, clock):
    lic = create_license(tenant, seats_max=4)
    for device in ("a", "b", "c", "d"):
        verify(lic["license_key"], device)
    clock["t"] += DAY + 1  # all four expired

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda i: verify(lic["license_key"], "n{}".format(i)),
                                range(16)))

    assert [s for s, _ in results].count(200) == 4
    assert _used(lic["license_id"]) == 4
    assert len(_devices(lic["license_id"])) == 4
