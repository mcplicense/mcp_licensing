"""Requests must come through CloudFront (and so WAF): the Lambda refuses a
call to the raw API Gateway URL when it lacks the secret header."""
import pytest

from helpers import call, create_license, create_tenant

SECRET = "s3cret-value-that-is-long-enough-for-the-origin-check-0123456789"
OLD_SECRET = "previous-secret-value-kept-while-rotating-0123456789abcdef"
HEADER = "x-origin-verify"

ROUTES = [
    ("POST /v1/mcp/verify", {"license_key": "acme_AAAAA-AAAAA-AAAAA-AAAAA-AAAAA", "device_id": "d"}),
    ("GET /v1/admin/tenant", None),
    ("GET /v1/super/tenants", None),
]


@pytest.fixture
def enforced(monkeypatch):
    monkeypatch.setenv("ORIGIN_SECRET", SECRET)
    monkeypatch.delenv("ORIGIN_SECRET_PREVIOUS", raising=False)


@pytest.mark.parametrize("route,body", ROUTES)
def test_every_function_refuses_a_call_without_the_header(enforced, route, body):
    status, data = call(route, body)
    assert status == 403 and data["error"]["code"] == "FORBIDDEN"


@pytest.mark.parametrize("route,body", ROUTES)
def test_wrong_header_is_refused(enforced, route, body):
    assert call(route, body, headers={HEADER: SECRET + "x"})[0] == 403
    assert call(route, body, headers={HEADER: ""})[0] == 403


def test_unknown_routes_are_refused_too(enforced):
    event = {"routeKey": "GET /v1/mcp/nothing", "headers": {}}
    from handlers import mcp
    assert mcp.handler(event, None)["statusCode"] == 403  # not a 404 that reveals which paths exist


def test_correct_header_lets_the_request_through(enforced, super_key):
    headers = {HEADER: SECRET}
    status, tenant = call("POST /v1/super/tenants",
                          {"tenant_id": "acme", "company_name": "Acme", "email": "a@example.com"},
                          key=super_key, headers=headers)
    assert status == 201
    lic = call("POST /v1/admin/licenses", {}, key=tenant["admin_api_key"], headers=headers)[1]
    status, body = call("POST /v1/mcp/verify",
                        {"license_key": lic["license_key"], "device_id": "d"}, headers=headers)
    assert status == 200 and body["valid"] is True


def test_the_refusal_does_not_reveal_the_secret(enforced):
    status, data = call("GET /v1/super/tenants", headers={HEADER: "wrong"})
    assert SECRET not in str(data) and "wrong" not in str(data)


def test_previous_secret_is_accepted_while_rotating(enforced, monkeypatch):
    monkeypatch.setenv("ORIGIN_SECRET_PREVIOUS", OLD_SECRET)
    route, body = ROUTES[0]
    assert call(route, body, headers={HEADER: SECRET})[0] == 401   # reached the handler (bad key)
    assert call(route, body, headers={HEADER: OLD_SECRET})[0] == 401
    assert call(route, body, headers={HEADER: "neither"})[0] == 403


def test_check_is_off_when_no_secret_is_configured(monkeypatch, super_key):
    monkeypatch.delenv("ORIGIN_SECRET", raising=False)
    monkeypatch.setenv("ORIGIN_SECRET", "")  # an empty value must not turn the check on
    assert call("GET /v1/super/tenants", key=super_key)[0] == 200


def test_header_name_is_case_insensitive_as_http_api_lowercases_it(enforced):
    route, body = ROUTES[0]
    assert call(route, body, headers={"x-origin-verify": SECRET})[0] == 401
