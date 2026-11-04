"""Seat registration under contention.

The deterministic tests prove the logic: the seat limit is enforced by the
DynamoDB transaction, not by values read earlier. The threaded tests add real
interleaving on top (against moto, which is not DynamoDB, so they complement
rather than replace the deterministic ones)."""
from concurrent.futures import ThreadPoolExecutor

import pytest
from botocore.exceptions import ClientError

from core import store
from handlers import mcp
from helpers import call, create_license, create_tenant, verify


LEASE = 86400


@pytest.fixture
def license_1(super_key):
    tenant = create_tenant(super_key)
    return tenant["admin_api_key"], create_license(tenant["admin_api_key"], seats_max=1)


def _seat_rows(license_id):
    return store.list_seats("acme", license_id)


def _seats_used(license_id):
    return int(store.get_license("acme", license_id, consistent=True)["seats_used"])


def test_stale_license_read_cannot_oversell(license_1):
    """The old read-check-write trusted a license row read earlier. Two callers
    that both read seats_used=0 must still not both get the last seat."""
    _, lic = license_1
    stale = store.get_license("acme", lic["license_id"])
    assert int(stale["seats_used"]) == 0

    assert mcp.register_seat(stale, "device-a", LEASE)[0] == 1
    assert mcp.register_seat(stale, "device-b", LEASE) is None  # stale says 0 used; the transaction says full

    assert _seats_used(lic["license_id"]) == 1
    assert [s["device_id"] for s in _seat_rows(lic["license_id"])] == ["device-a"]


def test_failed_registration_writes_nothing(license_1):
    _, lic = license_1
    verify(lic["license_key"], "device-a")
    assert verify(lic["license_key"], "device-b")[0] == 403
    assert [s["device_id"] for s in _seat_rows(lic["license_id"])] == ["device-a"]
    assert _seats_used(lic["license_id"]) == 1


def test_lowering_seats_max_is_respected_atomically(license_1):
    admin_key, lic = license_1
    params = {"license_id": lic["license_id"]}
    call("PATCH /v1/admin/licenses/{license_id}", {"seats_max": 3}, key=admin_key, params=params)
    stale = store.get_license("acme", lic["license_id"])  # says 0 used of 3
    verify(lic["license_key"], "a")
    verify(lic["license_key"], "b")
    # the admin lowers the limit after the stale read
    call("PATCH /v1/admin/licenses/{license_id}", {"seats_max": 2}, key=admin_key, params=params)
    assert mcp.register_seat(stale, "c", LEASE) is None
    assert _seats_used(lic["license_id"]) == 2


def test_concurrent_new_devices_never_exceed_seats_max(super_key):
    tenant = create_tenant(super_key)
    lic = create_license(tenant["admin_api_key"], seats_max=3)

    with ThreadPoolExecutor(max_workers=25) as pool:
        results = list(pool.map(lambda i: verify(lic["license_key"], "dev-{}".format(i)),
                                range(25)))

    statuses = [status for status, _ in results]
    assert statuses.count(200) == 3
    assert statuses.count(403) == 22
    assert {body["reason"] for status, body in results if status == 403} == {"SEAT_LIMIT"}
    assert _seats_used(lic["license_id"]) == 3
    assert len(_seat_rows(lic["license_id"])) == 3  # counter and rows agree


def test_same_device_concurrently_takes_one_seat(super_key):
    tenant = create_tenant(super_key)
    lic = create_license(tenant["admin_api_key"], seats_max=5)

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda _: verify(lic["license_key"], "same-device"), range(10)))

    assert all(status == 200 for status, _ in results)
    assert _seats_used(lic["license_id"]) == 1
    assert len(_seat_rows(lic["license_id"])) == 1


def test_concurrent_release_frees_exactly_one_seat(super_key):
    tenant = create_tenant(super_key)
    admin_key = tenant["admin_api_key"]
    lic = create_license(admin_key, seats_max=2)
    verify(lic["license_key"], "a")
    verify(lic["license_key"], "b")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: store.release_seat("acme", lic["license_id"], "a"),
                                range(8)))

    assert results.count(True) == 1
    assert _seats_used(lic["license_id"]) == 1  # never double-decremented
    assert [s["device_id"] for s in _seat_rows(lic["license_id"])] == ["b"]


def test_mixed_register_and_release_keeps_counter_equal_to_rows(super_key):
    tenant = create_tenant(super_key)
    lic = create_license(tenant["admin_api_key"], seats_max=4)
    for device in ("keep-1", "keep-2"):
        verify(lic["license_key"], device)

    def work(i):
        if i % 2:
            return verify(lic["license_key"], "new-{}".format(i))[0]
        return store.release_seat("acme", lic["license_id"], "keep-{}".format(1 + (i // 2) % 2))

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(work, range(12)))

    used = _seats_used(lic["license_id"])
    assert used == len(_seat_rows(lic["license_id"]))
    assert 0 <= used <= 4


# ------------------------------------------------- DynamoDB contention (retry)

class _FlakyClient:
    """Makes the first N transactions fail the way DynamoDB does under contention."""

    def __init__(self, real, failures):
        self.real, self.failures, self.calls = real, failures, 0

    def transact_write_items(self, **kwargs):
        self.calls += 1
        if self.failures > 0:
            self.failures -= 1
            raise ClientError(
                {"Error": {"Code": "TransactionCanceledException", "Message": "conflict"},
                 "CancellationReasons": [{"Code": "TransactionConflict"}, {"Code": "None"}]},
                "TransactWriteItems")
        return self.real.transact_write_items(**kwargs)


def test_transaction_conflict_is_retried(license_1, monkeypatch):
    _, lic = license_1
    monkeypatch.setattr(store.time, "sleep", lambda _: None)
    flaky = _FlakyClient(store._client(), failures=2)
    monkeypatch.setattr(store, "_client", lambda: flaky)

    status, body = verify(lic["license_key"], "device-a")
    assert status == 200 and body["seats_used"] == 1
    assert flaky.calls == 3
    assert _seats_used(lic["license_id"]) == 1


def test_persistent_conflict_returns_503_not_a_wrong_answer(license_1, monkeypatch):
    _, lic = license_1
    monkeypatch.setattr(store.time, "sleep", lambda _: None)
    flaky = _FlakyClient(store._client(), failures=99)
    monkeypatch.setattr(store, "_client", lambda: flaky)

    status, body = verify(lic["license_key"], "device-a")
    assert status == 503 and body["error"]["code"] == "BUSY"
    assert flaky.calls == store.TRANSACT_ATTEMPTS
    monkeypatch.undo()
    assert _seats_used(lic["license_id"]) == 0
    assert _seat_rows(lic["license_id"]) == []
