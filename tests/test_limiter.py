"""The visitor limiter (3 attempts, then a 30-minute lock), the window counter and
how a visitor's address is read from CloudFront's header."""
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from botocore.exceptions import ClientError

from core import clientip, store

LOCK = 1800


@pytest.fixture
def clock(monkeypatch):
    state = {"t": (int(time.time()) // 86400) * 86400 + 100}
    monkeypatch.setattr(store, "now_epoch", lambda: state["t"])
    return state


def attempt(key="203.0.113.9", scope="contact", maximum=3):
    return store.take_attempt(scope, key, maximum, LOCK)


# ----------------------------------------------------------------- attempts

def test_three_attempts_pass_and_the_fourth_is_locked_for_30_minutes(clock):
    assert [attempt() for _ in range(3)] == [(True, 0)] * 3
    assert attempt() == (False, LOCK)


def test_the_lock_runs_30_minutes_from_the_moment_it_starts(clock):
    for _ in range(3):
        attempt()
    assert attempt() == (False, LOCK)          # the lock starts now
    clock["t"] += 600
    assert attempt() == (False, LOCK - 600)    # asking again does not extend it
    clock["t"] += LOCK - 601
    assert attempt() == (False, 1)
    clock["t"] += 1                            # exactly 30 minutes after it started
    assert attempt() == (True, 0)


def test_after_the_lock_the_visitor_starts_again_from_zero(clock):
    for _ in range(4):
        attempt()
    clock["t"] += LOCK
    assert [attempt()[0] for _ in range(3)] == [True, True, True]
    assert attempt()[0] is False


def test_a_visitor_who_comes_back_later_starts_fresh(clock):
    attempt()
    attempt()
    clock["t"] += LOCK + 1                     # idle for longer than the window
    assert [attempt()[0] for _ in range(3)] == [True, True, True]


def test_visitors_are_counted_separately(clock):
    for _ in range(4):
        attempt("198.51.100.1")
    assert attempt("198.51.100.1")[0] is False
    assert attempt("198.51.100.2") == (True, 0)
    assert attempt("198.51.100.1", scope="signup") == (True, 0)  # and per kind of attempt


def test_the_maximum_is_configurable(clock):
    assert [attempt(maximum=1)[0] for _ in range(2)] == [True, False]


def test_simultaneous_attempts_cannot_get_extra_tries_through(clock):
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: attempt()[0], range(12)))
    assert results.count(True) == 3 and results.count(False) == 9


def test_a_storage_failure_does_not_block_visitors(clock, monkeypatch):
    class Broken:
        def get_item(self, **kwargs):
            raise ClientError({"Error": {"Code": "InternalServerError", "Message": "x"}}, "GetItem")
    monkeypatch.setattr(store, "_table", lambda name: Broken())
    assert attempt() == (True, 0)


# ------------------------------------------------------------ window counter

def test_window_slot_counts_per_window(clock):
    def slot():
        return store.take_window_slot("contact-day", "all", 2, 86400)
    assert slot() == (True, 0) and slot() == (True, 0)
    allowed, retry = slot()
    assert allowed is False and retry == 86400 - 100
    clock["t"] += 86400
    assert slot() == (True, 0)


def test_window_slots_are_separate_per_scope_and_key(clock):
    assert store.take_window_slot("a", "x", 1, 60) == (True, 0)
    assert store.take_window_slot("a", "x", 1, 60)[0] is False
    assert store.take_window_slot("a", "y", 1, 60) == (True, 0)
    assert store.take_window_slot("b", "x", 1, 60) == (True, 0)


# ------------------------------------------------------------------ address

def event(value):
    return {"headers": {"cloudfront-viewer-address": value} if value is not None else {}}


@pytest.mark.parametrize("header,expected", [
    ("203.0.113.9:4430", "203.0.113.9"),
    (" 203.0.113.9:4430 ", "203.0.113.9"),
    ("[2001:db8::1]:4430", "2001:db8::1"),
    ("2001:db8::1:4430", "2001:db8::1"),                      # port appended to a bare IPv6 address
    ("2001:0db8:85a3:0:0:8a2e:0370:7334:46532", "2001:db8:85a3::8a2e:370:7334"),
])
def test_client_ip_parses_every_form_cloudfront_uses(header, expected):
    assert clientip.client_ip(event(header)) == ipaddress.ip_address(expected)


@pytest.mark.parametrize("header", [None, "", "garbage", "999.1.1.1:80", "not:an:address", ":4430"])
def test_client_ip_is_none_for_anything_else(header):
    assert clientip.client_ip(event(header)) is None
    assert clientip.rate_key(event(header)) == "unknown"


def test_ipv6_visitors_are_counted_per_64():
    one = clientip.rate_key(event("[2001:db8:aaaa:bbbb::1]:4430"))
    other_in_same_64 = clientip.rate_key(event("[2001:db8:aaaa:bbbb:ffff:1:2:3]:9"))
    different_64 = clientip.rate_key(event("[2001:db8:aaaa:cccc::1]:4430"))
    assert one == other_in_same_64 == "2001:db8:aaaa:bbbb::/64"
    assert different_64 != one
    assert clientip.rate_key(event("203.0.113.9:4430")) == "203.0.113.9"


def test_a_forged_forwarded_for_header_is_ignored():
    forged = {"headers": {"x-forwarded-for": "192.0.2.1", "cloudfront-viewer-address": "203.0.113.9:1"}}
    assert clientip.rate_key(forged) == "203.0.113.9"
    assert clientip.rate_key({"headers": {"x-forwarded-for": "192.0.2.1"}}) == "unknown"
