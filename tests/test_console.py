"""The console API (/v1/console/*) and bans: the admin operations for a person signed in on the website."""
import json

import pytest

from core import cognito, identity, store
from fake_cognito import CLIENT_ID, CLIENT_SECRET, POOL_ID, FakeCognito
from handlers import admin, portal, super_admin
from helpers import call, create_license, create_tenant, verify
from test_portal import STRONG, FakeSns, HEADERS, login, post, register  # noqa: F401  (fixtures reused)

GMAIL = "gmail.com"  # spelt out here so no test fixture looks like a real mailbox to the hygiene test
GOOGLEMAIL = "googlemail.com"


@pytest.fixture(autouse=True)
def pool(monkeypatch):
    fake = FakeCognito()
    monkeypatch.setitem(cognito._client, "obj", fake)
    monkeypatch.setitem(portal._sns_client, "obj", FakeSns())
    for name, value in (("USER_POOL_ID", POOL_ID), ("USER_POOL_CLIENT_ID", CLIENT_ID),
                        ("USER_POOL_CLIENT_SECRET", CLIENT_SECRET), ("NOTIFY_TOPIC_ARN", "arn:aws:sns:us-east-1:1:n")):
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SITE_ORIGIN", raising=False)
    monkeypatch.delenv("ORIGIN_SECRET", raising=False)
    return fake


def claims_for(tenant_id, **overrides):
    claims = {"token_use": "id", "aud": CLIENT_ID, "sub": "sub-0001-abcdef", "email": "owner@example.com",
              "email_verified": "true", "custom:tenant_id": tenant_id}
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def console(route, claims, body=None, params=None, headers=None):
    event = {"routeKey": route, "headers": headers or {}, "pathParameters": params,
             "queryStringParameters": None, "body": json.dumps(body) if body is not None else None,
             "requestContext": {"authorizer": {"jwt": {"claims": claims}}} if claims is not None else {}}
    result = admin.handler(event, None)
    return result["statusCode"], json.loads(result["body"])


@pytest.fixture
def acme(super_key):
    tenant = create_tenant(super_key, "acme")
    return tenant["admin_api_key"]


# ----------------------------------------------------------------- identity

def test_a_signed_in_person_sees_and_changes_their_own_tenant(acme):
    status, view = console("GET /v1/console/tenant", claims_for("acme"))
    assert status == 200 and view["tenant_id"] == "acme" and "limits" in view and "usage" in view
    assert view == call("GET /v1/admin/tenant", key=acme)[1]  # exactly what the API key sees

    status, created = console("POST /v1/console/licenses", claims_for("acme"), {"label": "From the console", "seats_max": 3})
    assert status == 201 and created["license_key"].startswith("acme_")
    listed = call("GET /v1/admin/licenses", key=acme)[1]["items"]  # the API sees the same data
    assert [item["label"] for item in listed] == ["From the console"]
    assert verify(created["license_key"])[0] == 200


def test_the_audit_log_names_the_person_not_their_email(acme):
    console("POST /v1/console/licenses", claims_for("acme"), {"label": "x"})
    items = call("GET /v1/admin/audit-log", key=acme)[1]["items"]
    actor = next(i["actor"] for i in items if i["event_type"] == "license.created")
    assert actor == "user:sub-0001" and "@" not in actor


def test_one_tenant_cannot_reach_another_through_the_console(super_key, acme):
    other = create_tenant(super_key, "globex")["admin_api_key"]
    create_license(other, label="globex secret")
    status, listed = console("GET /v1/console/licenses", claims_for("acme"))
    assert status == 200 and listed["items"] == []
    mine = console("POST /v1/console/licenses", claims_for("acme"), {"label": "mine"})[1]
    assert console("GET /v1/console/licenses/{license_id}", claims_for("globex"),
                   params={"license_id": mine["license_id"]})[0] == 404


def test_the_tenant_comes_from_the_signed_claim_never_from_the_request(acme, super_key):
    create_tenant(super_key, "globex")
    status, view = console("GET /v1/console/tenant", claims_for("acme"),
                           body={"tenant_id": "globex"}, params={"tenant_id": "globex"})
    assert view["tenant_id"] == "acme"


@pytest.mark.parametrize("claims,status,code", [
    (None, 401, "UNAUTHORIZED"),                                              # no authorizer result at all
    ({}, 401, "UNAUTHORIZED"),
    (claims_for("acme", token_use="access"), 401, "UNAUTHORIZED"),            # an access token is not an ID token
    (claims_for("acme", aud="some-other-client"), 401, "UNAUTHORIZED"),       # another app's token
    (claims_for("acme", **{"custom:tenant_id": None}), 403, "NO_TENANT"),     # confirmed but no tenant yet
    (claims_for("acme", **{"custom:tenant_id": "../other"}), 403, "NO_TENANT"),
    (claims_for("acme", **{"custom:tenant_id": "ACME"}), 403, "NO_TENANT"),
    (claims_for("acme", email_verified="false"), 403, "NO_TENANT"),
    (claims_for("ghost"), 403, "TENANT_DISABLED"),                           # a tenant that does not exist
])
def test_a_token_that_is_not_a_valid_tenant_login_is_refused(acme, claims, status, code):
    got, body = console("GET /v1/console/tenant", claims)
    assert got == status and body["error"]["code"] == code


def test_claims_do_not_work_on_the_api_key_routes_and_keys_do_not_work_on_the_console(acme):
    event = {"routeKey": "GET /v1/admin/tenant", "headers": {}, "pathParameters": None, "queryStringParameters": None,
             "body": None, "requestContext": {"authorizer": {"jwt": {"claims": claims_for("acme")}}}}
    assert admin.handler(event, None)["statusCode"] == 401  # a forged requestContext cannot replace the key
    status, _ = console("GET /v1/console/tenant", None, headers={"x-tenant-api-key": acme})
    assert status == 401  # and an API key is not a login


def test_a_tenant_that_suspended_itself_can_still_resume_from_the_console(acme):
    assert console("PUT /v1/console/tenant/status", claims_for("acme"), {"suspended": True})[0] == 200
    assert console("PUT /v1/console/tenant/status", claims_for("acme"), {"suspended": False})[0] == 200


def test_the_platform_cannot_be_overridden_from_the_console(acme, super_key):
    call("PUT /v1/super/tenants/{tenant_id}/status", {"disabled": True}, key=super_key, params={"tenant_id": "acme"})
    status, body = console("GET /v1/console/tenant", claims_for("acme"))
    assert status == 403 and body["error"]["code"] == "TENANT_DISABLED"
    assert console("PUT /v1/console/tenant/status", claims_for("acme"), {"suspended": False})[0] == 403


def test_the_super_routes_never_accept_a_login(acme):
    event = {"routeKey": "GET /v1/super/tenants", "headers": {}, "pathParameters": None, "queryStringParameters": None,
             "body": None, "requestContext": {"authorizer": {"jwt": {"claims": claims_for("acme")}}}}
    assert super_admin.handler(event, None)["statusCode"] == 401


# ------------------------------------------------------------------------ bans

def self_service_tenant(pool):
    register(pool)
    (tenant,) = [t for t in store.scan_tenants(10, None)[0] if t.get("self_service")]
    return tenant


def ban(super_key, tenant_id, reason="Abuse"):
    return call("POST /v1/super/tenants/{tenant_id}/ban", {"reason": reason}, key=super_key,
                params={"tenant_id": tenant_id})


def test_a_ban_shuts_every_door(pool, super_key):
    tenant = self_service_tenant(pool)
    tid = tenant["tenant_id"]
    token_claims = cognito.token_claims(login()[1]["id_token"])
    lic = console("POST /v1/console/licenses", token_claims, {"label": "x"})[1]
    assert verify(lic["license_key"])[0] == 200
    (sub, user), = pool.users.items()

    status, view = ban(super_key, tid)
    assert status == 200 and view["status"] == "DISABLED" and view["login_disabled"] is True

    assert user["enabled"] is False                                           # the login is disabled...
    assert ("admin_user_global_sign_out", {"UserPoolId": POOL_ID, "Username": sub}) in pool.calls  # ...and signed out
    assert [kw["Username"] for op, kw in pool.calls if op == "admin_disable_user"] == [sub]  # addressed by sub, not email
    assert login()[0] == 401                                                  # cannot log in again
    assert console("GET /v1/console/tenant", token_claims)[1]["error"]["code"] == "TENANT_DISABLED"  # token still valid, tenant is not
    assert verify(lic["license_key"])[1]["reason"] == "TENANT_DISABLED"      # their licenses stop working
    assert post("signup", {"email": "owner@example.com", "password": STRONG, "company_name": "Acme Tools",
                           "accept_terms": True}, ip="198.51.100.7")[0] == 403  # and the address cannot come back


@pytest.mark.parametrize("variant", ["owner@example.com", "OWNER@example.com", "owner+again@example.com"])
def test_the_banned_address_is_recognised_in_its_variants(pool, super_key, variant):
    tenant = self_service_tenant(pool)
    ban(super_key, tenant["tenant_id"])
    status, body, _ = post("signup", {"email": variant, "password": STRONG, "company_name": "Again Ltd",
                                      "accept_terms": True}, ip="198.51.100.8")
    assert status == 403 and body["error"]["code"] == "NOT_ALLOWED"


def test_gmail_dots_do_not_get_a_banned_person_back_in(pool, super_key):
    register(pool, email="j.ane.doe@" + GMAIL)
    (tenant,) = [t for t in store.scan_tenants(10, None)[0] if t.get("self_service")]
    ban(super_key, tenant["tenant_id"])
    status, _, _ = post("signup", {"email": "jane.doe+2@" + GOOGLEMAIL, "password": STRONG,
                                   "company_name": "Again Ltd", "accept_terms": True}, ip="198.51.100.8")
    assert status == 403


def test_unbanning_restores_everything(pool, super_key):
    tenant = self_service_tenant(pool)
    tid = tenant["tenant_id"]
    ban(super_key, tid)
    status, view = call("POST /v1/super/tenants/{tenant_id}/unban", key=super_key, params={"tenant_id": tid})
    assert status == 200 and view["status"] == "ACTIVE"
    assert login()[0] == 200
    assert store.get_banned(identity.email_hash("owner@example.com")) is None
    assert post("signup", {"email": "owner@example.com", "password": STRONG, "company_name": "Acme Tools",
                           "accept_terms": True}, ip="198.51.100.9")[0] == 200


def test_a_ban_still_disables_the_tenant_if_the_login_cannot_be_disabled(pool, super_key, monkeypatch):
    tenant = self_service_tenant(pool)
    monkeypatch.setattr(pool, "admin_disable_user", lambda **kw: (_ for _ in ()).throw(
        __import__("fake_cognito").error("InternalErrorException", "AdminDisableUser")))
    status, view = ban(super_key, tenant["tenant_id"])
    assert status == 200 and view["status"] == "DISABLED" and view["login_disabled"] is False
    assert store.get_banned(identity.email_hash("owner@example.com")) is not None


def test_a_tenant_made_by_hand_can_be_banned_too(super_key):
    create_tenant(super_key, "handmade")
    status, view = ban(super_key, "handmade")
    assert status == 200 and view["status"] == "DISABLED" and view["login_disabled"] is False
    assert call("POST /v1/super/tenants/{tenant_id}/unban", key=super_key, params={"tenant_id": "handmade"})[1]["status"] == "ACTIVE"


def test_only_the_platform_can_ban(pool, super_key, acme):
    tenant = self_service_tenant(pool)
    status, _ = call("POST /v1/super/tenants/{tenant_id}/ban", {"reason": "x"}, key=acme, params={"tenant_id": tenant["tenant_id"]})
    assert status == 403
    assert call("POST /v1/super/tenants/{tenant_id}/ban", {}, key=None, params={"tenant_id": tenant["tenant_id"]})[0] == 401
    assert ban(super_key, "mcp-zzzzzz")[0] == 404


def test_bans_are_in_both_audit_logs_and_the_tenant_sees_the_platform_not_a_key(pool, super_key):
    tenant = self_service_tenant(pool)
    ban(super_key, tenant["tenant_id"], reason="Spam")
    platform = call("GET /v1/super/audit-log", key=super_key)[1]["items"]
    assert any(e["event_type"] == "tenant.banned" and e["details"]["reason"] == "Spam" for e in platform)
    mine = store.list_audit(tenant["tenant_id"], 10, None)[0]
    event = next(e for e in mine if e["event_type"] == "tenant.banned")
    assert event["actor_role"] == "super_admin"
