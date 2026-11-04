import json

from handlers import admin, mcp, super_admin

HANDLERS = {"mcp": mcp.handler, "admin": admin.handler, "super": super_admin.handler}


def call(route, body=None, key=None, params=None, query=None, headers=None):
    """Invoke a Lambda handler the way HTTP API (payload v2) would.

    route is the routeKey, e.g. "POST /v1/admin/licenses". Returns
    (status_code, parsed_json_body). headers adds request headers (lowercase
    names, as HTTP API delivers them).
    """
    prefix = route.split(" ", 1)[1].split("/")[2]  # mcp | admin | super
    event = {
        "routeKey": route,
        "headers": dict({"x-tenant-api-key": key} if key else {}, **(headers or {})),
        "pathParameters": params or None,
        "queryStringParameters": query or None,
        "body": json.dumps(body) if body is not None else None,
    }
    resp = HANDLERS[prefix](event, None)
    return resp["statusCode"], json.loads(resp["body"])


def create_tenant(super_key, tenant_id="acme", **extra):
    body = {"tenant_id": tenant_id, "company_name": "Acme Inc", "email": "ops@example.com"}
    body.update(extra)
    status, data = call("POST /v1/super/tenants", body, key=super_key)
    assert status == 201, data
    return data


def create_license(admin_key, **body):
    status, data = call("POST /v1/admin/licenses", body, key=admin_key)
    assert status == 201, data
    return data


def verify(license_key, device_id="device-1"):
    return call("POST /v1/mcp/verify", {"license_key": license_key, "device_id": device_id})
