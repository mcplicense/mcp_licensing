"""Self-service sign-up, login and password reset (/v1/portal/*), against a stand-in for Cognito."""
import json
import re
import time

import boto3
import pytest

from core import cognito, config, identity, store
from fake_cognito import CLIENT_ID, CLIENT_SECRET, POOL_ID, FakeCognito
from handlers import portal
from helpers import call as api_call

STRONG = "Correct-Horse-9"
HEADERS = {"x-requested-with": "mcp-portal"}
TENANT_ID = re.compile(r"^mcp-[a-hj-np-z2-9]{6}$")


class FakeSns:
    def __init__(self):
        self.published = []
        self.fail = False

    def publish(self, **kwargs):
        if self.fail:
            raise RuntimeError("SNS down")
        self.published.append(kwargs)


@pytest.fixture(autouse=True)
def pool(monkeypatch):
    fake = FakeCognito()
    monkeypatch.setitem(cognito._client, "obj", fake)
    sns = FakeSns()
    monkeypatch.setitem(portal._sns_client, "obj", sns)
    for name, value in (("USER_POOL_ID", POOL_ID), ("USER_POOL_CLIENT_ID", CLIENT_ID),
                        ("USER_POOL_CLIENT_SECRET", CLIENT_SECRET), ("NOTIFY_TOPIC_ARN", "arn:aws:sns:us-east-1:1:notify")):
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SITE_ORIGIN", raising=False)
    monkeypatch.delenv("ORIGIN_SECRET", raising=False)
    fake.sns = sns
    return fake


@pytest.fixture
def clock(monkeypatch):
    state = {"t": (int(time.time()) // 86400) * 86400 + 100}
    monkeypatch.setattr(store, "now_epoch", lambda: state["t"])
    return state


def post(route, body=None, ip="203.0.113.9", headers=None, cookies=None):
    event = {"routeKey": "POST /v1/portal/" + route, "headers": dict(HEADERS, **{"cloudfront-viewer-address": ip + ":443",
                                                                                 "cloudfront-viewer-country": "IN"}),
             "body": json.dumps(body) if body is not None else None, "cookies": cookies or []}
    if headers is not None:
        event["headers"] = dict(event["headers"], **headers)
    result = portal.handler(event, None)
    return result["statusCode"], json.loads(result["body"] or "{}"), result.get("cookies")


def signup_body(email="owner@example.com", **overrides):
    body = {"email": email, "password": STRONG, "company_name": "Acme Tools", "accept_terms": True}
    body.update(overrides)
    return body


def register(pool, email="owner@example.com", ip="203.0.113.9"):
    """Sign up and confirm: returns the confirm response."""
    assert post("signup", signup_body(email), ip=ip)[0] == 200
    return post("confirm", {"email": email, "code": pool.last_code(email)}, ip=ip)


def login(email="owner@example.com", password=STRONG, ip="203.0.113.9"):
    return post("login", {"email": email, "password": password}, ip=ip)


# -------------------------------------------------------------------- sign-up

def test_signup_emails_a_code_and_creates_no_tenant_yet(pool):
    status, body, _ = post("signup", signup_body())
    assert status == 200 and body == {"status": "code_sent"}
    (sign_up,) = [kw for op, kw in pool.calls if op == "sign_up"]
    assert sign_up["Username"] == "owner@example.com"
    assert {"Name": "custom:company", "Value": "Acme Tools"} in sign_up["UserAttributes"]
    assert pool.sent_codes[0][:2] == ("signup", "owner@example.com")
    assert store.scan_tenants(10, None)[0] == []  # no tenant until the address is confirmed


def test_confirming_creates_the_tenant_and_tells_the_operator(pool):
    status, body, _ = register(pool)
    assert status == 200 and body == {"status": "confirmed"}

    (tenant,) = store.scan_tenants(10, None)[0]
    assert TENANT_ID.match(tenant["tenant_id"])
    assert tenant["company_name"] == "Acme Tools" and tenant["owner_email"] == "owner@example.com"
    assert tenant["self_service"] is True and tenant["disabled_by_platform"] is False  # active at once
    (sub, user), = pool.users.items()
    assert tenant["owner_sub"] == sub
    assert user["attrs"]["custom:tenant_id"] == tenant["tenant_id"]

    (note,) = pool.sns.published
    assert note["Subject"] == "MCP Licensing: new tenant " + tenant["tenant_id"].upper()
    for expected in ("Acme Tools", "owner@example.com", "Country: IN", "/ban"):
        assert expected in note["Message"]
    assert STRONG not in note["Message"] and STRONG not in json.dumps(pool.calls[-1:][0][1])


def test_a_failed_notification_does_not_stop_the_sign_up(pool):
    pool.sns.fail = True
    assert register(pool)[0] == 200
    assert len(store.scan_tenants(10, None)[0]) == 1


def test_signing_up_again_looks_the_same_and_creates_nothing_new(pool):
    register(pool)
    first = post("signup", signup_body("fresh@example.com"))
    again = post("signup", signup_body("owner@example.com"))  # an address that already has an account
    assert again[:2] == first[:2] == (200, {"status": "code_sent"})  # nothing tells the two apart
    assert len(store.scan_tenants(10, None)[0]) == 1


def test_signing_up_again_before_confirming_sends_a_new_code(pool):
    post("signup", signup_body())
    first = pool.last_code("owner@example.com")
    assert post("signup", signup_body())[0] == 200
    assert pool.last_code("owner@example.com") != first and pool.sent_codes[-1][0] == "resend"
    assert post("confirm", {"email": "owner@example.com", "code": pool.last_code("owner@example.com")})[0] == 200


@pytest.mark.parametrize("override,fragment", [
    ({"email": "not-an-email"}, "valid email"),
    ({"email": ""}, "valid email"),
    ({"company_name": "x"}, "company"),
    ({"company_name": "x" * 101}, "company"),
    ({"accept_terms": False}, "accept the terms"),
    ({"accept_terms": "yes"}, "accept the terms"),
    ({"password": "short1A"}, "at least 12"),
    ({"password": "alllowercase1234"}, "capital letter"),
    ({"password": "NOLOWERCASE1234"}, "lower-case"),
    ({"password": "NoDigitsHereAtAll"}, "number"),
    ({"password": "password1234"}, "capital letter"),  # fails the class rule before the common-password rule
    ({"password": "Passw0rd1234"}, "too common"),
    ({"password": "x" * 129}, "at most 128"),
    ({"password": "Owner-Is-In-9-Password"}, "email name"),
])
def test_invalid_sign_ups_are_refused_with_a_reason_and_not_counted(pool, override, fragment):
    if override.get("password") == "Passw0rd1234":
        identity.COMMON_PASSWORDS.add("passw0rd1234")
    status, body, _ = post("signup", signup_body(**override))
    assert status == 400 and fragment in body["error"]["message"]
    assert [op for op, _ in pool.calls if op == "sign_up"] == []
    for _ in range(3):  # none of that used up the visitor's three attempts
        assert post("signup", signup_body(email="ok{}@example.com".format(_)))[0] == 200


def test_company_names_are_tidied(pool):
    post("signup", signup_body(company_name="  Acme\x00   Tools\n"))
    (kw,) = [k for op, k in pool.calls if op == "sign_up"]
    assert {"Name": "custom:company", "Value": "Acme Tools"} in kw["UserAttributes"]


# ----------------------------------------------------------------- the limits

def test_three_sign_ups_per_visitor_then_a_30_minute_lock(pool, clock):
    for n in range(3):
        assert post("signup", signup_body("p{}@example.com".format(n)))[0] == 200
    status, body, _ = post("signup", signup_body("p9@example.com"))
    assert status == 429 and "30 minutes" in body["error"]["message"]
    clock["t"] += 1799
    assert post("signup", signup_body("p9@example.com"))[0] == 429
    clock["t"] += 1
    assert post("signup", signup_body("p9@example.com"))[0] == 200


def test_another_visitor_is_not_affected_by_the_lock(pool, clock):
    for n in range(4):
        post("signup", signup_body("p{}@example.com".format(n)), ip="198.51.100.1")
    assert post("signup", signup_body("q@example.com"), ip="198.51.100.2")[0] == 200


def test_one_address_cannot_be_sent_more_than_three_codes_an_hour(pool, clock):
    for n in range(3):
        assert post("signup", signup_body("victim@example.com"), ip="198.51.100.{}".format(n + 1))[0] == 200
    status, body, _ = post("signup", signup_body("victim@example.com"), ip="198.51.100.9")
    assert status == 429 and "this address" in body["error"]["message"]
    # tag and case variants are the same mailbox
    assert post("signup", signup_body("Victim+x@Example.com"), ip="198.51.100.10")[0] == 429
    clock["t"] += 3600
    assert post("signup", signup_body("victim@example.com"), ip="198.51.100.11")[0] == 200


def test_resend_and_forgot_share_the_per_address_limit(pool, clock):
    post("signup", signup_body())
    assert post("resend", {"email": "owner@example.com"}, ip="198.51.100.1")[0] == 200
    assert post("forgot", {"email": "owner@example.com"}, ip="198.51.100.2")[0] == 200
    assert post("resend", {"email": "owner@example.com"}, ip="198.51.100.3")[0] == 429


def test_a_daily_cap_covers_all_sign_ups(pool, clock, monkeypatch):
    monkeypatch.setenv("SSM_PREFIX", "/mcp/test")
    boto3.client("ssm").put_parameter(Name="/mcp/test/signup_daily_cap", Value="2", Type="String")
    config.reset_cache()
    assert post("signup", signup_body("a@example.com"), ip="198.51.100.1")[0] == 200
    assert post("signup", signup_body("b@example.com"), ip="198.51.100.2")[0] == 200
    status, body, _ = post("signup", signup_body("c@example.com"), ip="198.51.100.3")
    assert status == 429 and "tomorrow" in body["error"]["message"]
    clock["t"] += 86400
    assert post("signup", signup_body("c@example.com"), ip="198.51.100.4")[0] == 200


def test_a_filled_hidden_field_looks_like_success_but_signs_nobody_up(pool):
    assert post("signup", signup_body(website="http://spam.example"))[:2] == (200, {"status": "code_sent"})
    assert [op for op, _ in pool.calls if op == "sign_up"] == []
    for _ in range(2):
        post("signup", signup_body(website="x"))
    assert post("signup", signup_body())[0] == 429  # three attempts used by the bot


def test_only_the_sites_own_pages_may_call_the_portal(pool, monkeypatch):
    assert post("signup", signup_body(), headers={"x-requested-with": ""})[0] == 403
    monkeypatch.setenv("SITE_ORIGIN", "https://mcplicense.net")
    assert post("signup", signup_body(), headers={"origin": "https://evil.example"})[0] == 403
    assert post("signup", signup_body(), headers={"origin": "https://mcplicense.net"}, ip="198.51.100.1")[0] == 200
    assert post("signup", signup_body(), headers={})[0] == 403  # neither Origin nor Referer
    assert [op for op, _ in pool.calls if op == "sign_up"] != []
    assert post("signup", signup_body("z@example.com"), headers={"referer": "https://mcplicense.net/signup/"},
                ip="198.51.100.2")[0] == 200


def test_the_origin_secret_check_still_applies(pool, monkeypatch):
    monkeypatch.setenv("ORIGIN_SECRET", "s" * 40)
    event = {"routeKey": "POST /v1/portal/signup", "headers": dict(HEADERS), "body": json.dumps(signup_body())}
    assert portal.handler(event, None)["statusCode"] == 403


# ------------------------------------------------------------------- confirming

@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 456"])
def test_a_code_must_be_six_digits(pool, code):
    post("signup", signup_body())
    status, body, _ = post("confirm", {"email": "owner@example.com", "code": code})
    assert status == 400 and body["error"]["code"] == "BAD_CODE"


def test_a_wrong_code_is_refused_and_nothing_is_created(pool):
    post("signup", signup_body())
    right = pool.last_code("owner@example.com")
    wrong = "000000" if right != "000000" else "111111"
    status, body, _ = post("confirm", {"email": "owner@example.com", "code": wrong})
    assert status == 400 and body["error"]["code"] == "BAD_CODE"
    assert store.scan_tenants(10, None)[0] == []
    assert post("confirm", {"email": "owner@example.com", "code": right})[0] == 200


def test_confirming_twice_does_not_create_a_second_tenant(pool):
    register(pool)
    status, body, _ = post("confirm", {"email": "owner@example.com", "code": "123456"})
    assert status == 400 and "already confirmed" in body["error"]["message"]
    assert len(store.scan_tenants(10, None)[0]) == 1


def test_guessing_codes_is_limited_per_address(pool, clock):
    post("signup", signup_body())
    outcomes = [post("confirm", {"email": "owner@example.com", "code": "{:06d}".format(n)}, ip="198.51.100.{}".format(n + 1))[0]
                for n in range(1, 8)]
    assert 429 in outcomes and outcomes[:3] == [400, 400, 400]


# ---------------------------------------------------------------------- login

def test_login_returns_an_id_token_for_the_tenant_and_a_locked_down_cookie(pool):
    register(pool)
    status, body, cookies = login()
    assert status == 200
    claims = cognito.token_claims(body["id_token"])
    (tenant,) = store.scan_tenants(10, None)[0]
    assert claims["custom:tenant_id"] == tenant["tenant_id"] == body["tenant_id"]
    assert body["expires_in"] == 900 and body["email"] == "owner@example.com"
    assert set(body) == {"id_token", "expires_in", "email", "tenant_id"}  # no access or refresh token in the page

    (cookie,) = cookies
    assert cookie.startswith("mcp_rt=sub-")
    for flag in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/v1/portal/", "Max-Age=43200"):
        assert flag in cookie
    assert "refresh" not in json.dumps(body) and "rt-sub" not in json.dumps(body)


def test_wrong_password_and_unknown_address_are_indistinguishable(pool):
    register(pool)
    wrong = login(password="Wrong-Password-9")
    unknown = login(email="nobody@example.com")
    assert wrong[:2] == unknown[:2] == (401, {"error": {"code": "BAD_LOGIN", "message": "Incorrect email or password."}})
    assert wrong[2] is None and unknown[2] is None  # no cookie


def test_an_unconfirmed_address_is_told_to_confirm(pool):
    post("signup", signup_body())
    status, body, _ = login()
    assert status == 403 and body["error"]["code"] == "NOT_CONFIRMED"


def test_login_attempts_are_limited_per_visitor(pool, clock):
    register(pool)
    results = [login(password="Wrong-Password-{}".format(n))[0] for n in range(21)]
    assert results[:20] == [401] * 20 and results[20] == 429
    clock["t"] += 900
    assert login()[0] == 200


def test_the_ids_in_the_cookie_refresh_the_session(pool):
    register(pool)
    _, first, cookies = login()
    status, body, set_cookies = post("refresh", cookies=[c.split(";")[0] for c in cookies])
    assert status == 200 and body["tenant_id"] == first["tenant_id"] and body["id_token"] != ""
    assert set_cookies is None  # the existing cookie stays


def test_refresh_without_a_cookie_is_refused(pool):
    status, body, cookies = post("refresh")
    assert status == 401 and body["error"]["code"] == "NO_SESSION" and cookies is None
    assert post("refresh", cookies=["other=1", "mcp_rt=no-tilde-here"])[0] == 401


def test_a_revoked_or_forged_cookie_is_refused_and_cleared(pool):
    register(pool)
    _, _, cookies = login()
    value = cookies[0].split(";")[0]
    status, _, cleared = post("refresh", cookies=[value[:-1] + "9"])  # not the issued token
    assert status == 401 and "Max-Age=0" in cleared[0]
    post("logout", cookies=[value])
    status, _, cleared = post("refresh", cookies=[value])
    assert status == 401 and "Max-Age=0" in cleared[0]


def test_logout_revokes_the_token_and_clears_the_cookie(pool):
    register(pool)
    _, _, cookies = login()
    status, body, cleared = post("logout", cookies=[cookies[0].split(";")[0]])
    assert status == 200 and body == {"status": "signed_out"}
    assert "Max-Age=0" in cleared[0] and "HttpOnly" in cleared[0]
    assert len(pool.revoked) == 1
    assert post("logout")[0] == 200  # logging out twice is harmless


def test_a_rate_limited_refresh_keeps_the_cookie(pool, monkeypatch):
    register(pool)
    _, _, cookies = login()
    monkeypatch.setattr(pool, "initiate_auth", lambda **kw: (_ for _ in ()).throw(
        __import__("fake_cognito").error("TooManyRequestsException", "InitiateAuth")))
    status, _, cleared = post("refresh", cookies=[cookies[0].split(";")[0]])
    assert status == 429 and cleared is None


def test_login_finishes_the_job_when_the_tenant_was_never_created(pool):
    """The address was confirmed (say, the tenant write failed) but no tenant exists: logging in creates it."""
    post("signup", signup_body())
    (sub, user), = pool.users.items()
    user["confirmed"] = True  # confirmed directly, bypassing the portal
    assert store.scan_tenants(10, None)[0] == []
    status, body, cookies = login()
    assert status == 200 and TENANT_ID.match(body["tenant_id"])
    assert len(store.scan_tenants(10, None)[0]) == 1 and cookies
    assert login()[2] is not None and len(store.scan_tenants(10, None)[0]) == 1  # and only once


def test_the_password_is_never_logged(pool, caplog):
    caplog.set_level("DEBUG")
    register(pool)
    login()
    assert STRONG not in caplog.text


# ------------------------------------------------------------- password reset

def test_forgot_looks_the_same_for_known_and_unknown_addresses(pool):
    register(pool)
    known = post("forgot", {"email": "owner@example.com"}, ip="198.51.100.1")
    unknown = post("forgot", {"email": "nobody@example.com"}, ip="198.51.100.2")
    assert known[:2] == unknown[:2] == (200, {"status": "code_sent"})
    assert pool.sent_codes[-1][0] == "reset" and len([c for c in pool.sent_codes if c[0] == "reset"]) == 1


def test_resetting_the_password_with_the_emailed_code(pool):
    register(pool)
    post("forgot", {"email": "owner@example.com"})
    code = pool.last_code("owner@example.com")
    new = "Brand-New-Pass-7"
    assert post("reset", {"email": "owner@example.com", "code": code, "password": new})[:2] == (200, {"status": "password_changed"})
    assert login(password=STRONG)[0] == 401 and login(password=new)[0] == 200


def test_reset_refuses_a_wrong_code_and_a_weak_password(pool):
    register(pool)
    post("forgot", {"email": "owner@example.com"})
    code = pool.last_code("owner@example.com")
    assert post("reset", {"email": "owner@example.com", "code": "000000", "password": STRONG})[1]["error"]["code"] == "BAD_CODE"
    assert post("reset", {"email": "owner@example.com", "code": code, "password": "weak"})[1]["error"]["code"] == "WEAK_PASSWORD"
    assert login()[0] == 200  # the old password still works


# ------------------------------------------------------------------- the pool

def test_cognitos_own_wording_is_never_shown_to_a_visitor(pool, monkeypatch):
    def boom(**kw):
        raise __import__("fake_cognito").error("InternalErrorException", "SignUp", "Arn:aws:cognito:secret-details")
    monkeypatch.setattr(pool, "sign_up", boom)
    status, body, _ = post("signup", signup_body())
    assert status == 502 and "secret-details" not in json.dumps(body) and body["error"]["code"] == "UPSTREAM_ERROR"


def test_every_call_proves_knowledge_of_the_client_secret(pool):
    """The fake refuses any call whose secret hash is wrong, so a successful run through every
    flow shows each one computes it, including refresh, which uses the sub and not the email."""
    register(pool)
    _, _, cookies = login()
    assert post("refresh", cookies=[cookies[0].split(";")[0]])[0] == 200
    post("forgot", {"email": "owner@example.com"})
    post("reset", {"email": "owner@example.com", "code": pool.last_code("owner@example.com"), "password": "Another-Pass-5x"})
    ops = {op for op, _ in pool.calls}
    assert {"sign_up", "confirm_sign_up", "initiate_auth", "forgot_password", "confirm_forgot_password"} <= ops


def test_unknown_routes_and_methods_are_not_found(pool):
    event = {"routeKey": "POST /v1/portal/nothing", "headers": dict(HEADERS), "body": "{}"}
    assert portal.handler(event, None)["statusCode"] == 404
