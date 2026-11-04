"""Generate the API documentation from one route table.

    python scripts/build_docs.py

Writes to docs/:
  openapi-tenant.yaml    /v1/mcp + /v1/admin   (safe to hand to customers)
  openapi-internal.yaml  everything incl. /v1/super
  openapi-portal.yaml    /v1/portal (sign-up and login) + /v1/console (the admin API for a signed-in person)
  postman/mcp_licensing_tenant.postman_collection.json + environment
  postman/mcp_licensing_super.postman_collection.json  + environment

tests/test_docs.py checks that these tables match the routes in template.yml and the handlers.
"""
import json
import os
import re

import yaml

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DOCS = os.path.join(ROOT, "docs")

# The public endpoint (CloudFront in front of the API, see edge.yml). It has
# no stage in the path, unlike the raw API Gateway URL.
PUBLIC_URL = "https://api.mcplicense.net"

# Placeholder values used in OpenAPI examples. Postman keeps the {{variables}}.
SAMPLES = {
    "license_key": "acme_7K2M9-X4QPD-8WHT3-NB6RC-ZV5YA",
    "device_id": "laptop-7f3a",
    "license_id": "9f1c2ab34d5e",
    "key_id": "a1b2c3d4e5f6",
    "tenant_id": "acme",
}


def R(scope, group, method, path, summary, body=None, query=None, saves=None, auth=True):
    return dict(scope=scope, group=group, method=method, path=path, summary=summary,
                body=body, query=query or [], saves=saves or {}, auth=auth)


ROUTES = [
    R("mcp", "Verify (end user)", "POST", "/v1/mcp/verify",
      "Check a license key and register this device. Called by the MCP tool at startup.",
      body={"license_key": "{{license_key}}", "device_id": "{{device_id}}"}, auth=False),

    R("admin", "Tenant", "GET", "/v1/admin/tenant",
      "Show your tenant, its status, the limits that apply to it (licenses, seats, API keys, verify requests "
      "per minute) and how much of them you use. Creating more than a limit allows returns 403 LIMIT_REACHED."),
    R("admin", "Tenant", "PATCH", "/v1/admin/tenant",
      "Set your default seat lease in seconds (300 to 2592000; null restores the platform default of 24h). "
      "A device that does not check in within its lease loses its seat automatically.",
      body={"lease_duration_sec": 43200}),
    R("admin", "Tenant", "PUT", "/v1/admin/tenant/status",
      "Tenant kill switch: suspend or resume all of your licenses. A platform-level disable cannot be lifted here.",
      body={"suspended": True, "reason": "Security incident"}),
    R("admin", "API keys", "GET", "/v1/admin/api-keys", "List your admin API keys."),
    R("admin", "API keys", "POST", "/v1/admin/api-keys",
      "Create another admin API key. The key is returned once.",
      body={"label": "ci pipeline"}, saves={"key_id": "key_id"}),
    R("admin", "API keys", "DELETE", "/v1/admin/api-keys/{key_id}",
      "Revoke an admin API key. The last active key cannot be revoked."),
    R("admin", "Licenses", "GET", "/v1/admin/licenses", "List licenses.", query=["limit", "next_token"]),
    R("admin", "Licenses", "POST", "/v1/admin/licenses",
      "Create a license. The license_key is returned once; give it to the end user. "
      "Optional lease_duration_sec overrides the tenant and platform default for this license.",
      body={"label": "Jane's laptop", "seats_max": 2, "expires_at": "2027-12-31",
            "lease_duration_sec": 86400},
      saves={"license_id": "license_id", "license_key": "license_key"}),
    R("admin", "Licenses", "GET", "/v1/admin/licenses/{license_id}", "Show one license."),
    R("admin", "Licenses", "PATCH", "/v1/admin/licenses/{license_id}",
      "Change label, seats_max, expires_at or lease_duration_sec (null clears the override).",
      body={"seats_max": 5}),
    R("admin", "Licenses", "PUT", "/v1/admin/licenses/{license_id}/status",
      "Revoke or reinstate one license.", body={"status": "REVOKED", "reason": "Left the company"}),
    R("admin", "Licenses", "POST", "/v1/admin/licenses/{license_id}/rotate-key",
      "Issue a new license_key (returned once). The old key stops working immediately.",
      saves={"license_key": "license_key"}),
    R("admin", "Seats", "GET", "/v1/admin/licenses/{license_id}/seats",
      "List devices using a license, with each seat's lease_expires_at (epoch seconds) and whether it is active."),
    R("admin", "Seats", "DELETE", "/v1/admin/licenses/{license_id}/seats/{device_id}",
      "Free the seat held by a device."),
    R("admin", "Audit log", "GET", "/v1/admin/audit-log", "Recent changes to your tenant.",
      query=["limit", "next_token"]),

    R("super", "Tenants", "GET", "/v1/super/tenants", "List tenants.", query=["limit", "next_token"]),
    R("super", "Tenants", "POST", "/v1/super/tenants",
      "Create a tenant. Returns its first admin API key once. tenant_id is optional: leave it out and one "
      "is generated (mcp-xxxxxx); it becomes the prefix of every license key and can not change.",
      body={"company_name": "Acme Inc", "email": "ops@example.com"},
      saves={"tenant_id": "tenant_id"}),
    R("super", "Tenants", "GET", "/v1/super/tenants/{tenant_id}", "Show a tenant."),
    R("super", "Tenants", "PATCH", "/v1/super/tenants/{tenant_id}",
      "Change company_name, email or lease_duration_sec. A tenant's limits are not set here but in SSM "
      "(/mcp/<stage>/tenants/<tenant_id>/limit_*).",
      body={"company_name": "Acme Corporation"}),
    R("super", "Tenants", "PUT", "/v1/super/tenants/{tenant_id}/status",
      "Disable or re-enable one tenant. Only the platform can lift this.",
      body={"disabled": True, "reason": "Unpaid invoice"}),
    R("super", "Tenants", "POST", "/v1/super/tenants/{tenant_id}/ban",
      "Ban a tenant: it is disabled, its owner's login is disabled and signed out, and the owner's email "
      "address cannot sign up again. Reversible with unban.",
      body={"reason": "Abuse"}),
    R("super", "Tenants", "POST", "/v1/super/tenants/{tenant_id}/unban",
      "Undo a ban: the tenant is enabled, the owner can log in again and the address may sign up."),
    R("super", "Tenants", "POST", "/v1/super/tenants/{tenant_id}/api-keys",
      "Issue a new tenant admin key (for example when a tenant lost all of theirs).",
      body={"label": "recovery"}),
    R("super", "Tenants", "GET", "/v1/super/tenants/{tenant_id}/licenses",
      "List a tenant's licenses (support).", query=["limit", "next_token"]),
    R("super", "Kill switch", "GET", "/v1/super/kill-switch", "Show the global kill switch."),
    R("super", "Kill switch", "PUT", "/v1/super/kill-switch",
      "Disable (enabled=true) or restore (enabled=false) every tenant at once.",
      body={"enabled": True, "reason": "Incident response"}),
    R("super", "Audit log", "GET", "/v1/super/audit-log", "Platform-level audit events.",
      query=["limit", "next_token"]),
]

# The sign-up and login routes (src/handlers/portal.py). They are called by a web page on the service's own
# domain: no API key, but every call must carry X-Requested-With and come from SITE_ORIGIN.
SITE_URL = "https://mcplicense.net"
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "mcp-portal"
COOKIE = "mcp_rt"
COOKIE_PATH = "/v1/portal/"
SESSION = {"id_token": "eyJraWQiOi...", "expires_in": 900, "email": "jane@example.com", "tenant_id": "mcp-k7m2x9"}


def P(path, summary, body, ok, errors, cookie_in=False, cookie_out=None):
    return dict(path=path, summary=summary, body=body, ok=ok, errors=errors, cookie_in=cookie_in,
                cookie_out=cookie_out)


PORTAL = [
    P("/v1/portal/signup",
      "Start a sign-up. A 6-digit code is emailed to the address. The answer is the same whether or not the "
      "address already has an account. Leave the hidden field `website` out (or empty): a bot that fills it in "
      "gets a fake success.",
      {"email": "jane@example.com", "password": "Correct-Horse-9", "company_name": "Acme Tools", "accept_terms": True},
      {"status": "code_sent"},
      [(400, "BAD_REQUEST", "invalid email, company name, or terms not accepted"),
       (400, "WEAK_PASSWORD", "12 to 128 characters with a capital, a lower-case letter and a number"),
       (403, "FORBIDDEN", "missing X-Requested-With, or the request did not come from the site"),
       (403, "NOT_ALLOWED", "this address was banned"),
       (429, "TOO_MANY", "per-visitor, per-address or daily limit reached; the message says how long to wait")]),
    P("/v1/portal/resend", "Send the sign-up code again.", {"email": "jane@example.com"}, {"status": "code_sent"},
      [(400, "BAD_REQUEST", "invalid email"), (403, "FORBIDDEN", "see signup"),
       (429, "TOO_MANY", "limit reached")]),
    P("/v1/portal/confirm",
      "Confirm the address with the emailed code. The first confirmation creates the person's tenant (active at "
      "once, generated id `mcp-xxxxxx`) and tells the operator by email. They then log in.",
      {"email": "jane@example.com", "code": "123456"}, {"status": "confirmed"},
      [(400, "BAD_CODE", "wrong code, or the address is already confirmed"),
       (400, "CODE_EXPIRED", "ask for a new code with resend"), (403, "FORBIDDEN", "see signup"),
       (429, "TOO_MANY", "limit reached")]),
    P("/v1/portal/login",
      "Log in. Returns an ID token to send as `Authorization: Bearer` on /v1/console/* (valid `expires_in` "
      "seconds, 15 minutes) and sets the refresh cookie. Keep the token in memory only.",
      {"email": "jane@example.com", "password": "Correct-Horse-9"}, SESSION,
      [(400, "BAD_REQUEST", "invalid email or empty password"),
       (400, "UNSUPPORTED", "the account needs a sign-in step that is not available"),
       (401, "BAD_LOGIN", "wrong password or unknown address (the same answer for both)"),
       (403, "NOT_CONFIRMED", "confirm the address first"), (403, "RESET_REQUIRED", "reset the password"),
       (403, "FORBIDDEN", "see signup"), (429, "TOO_MANY", "limit reached")],
      cookie_out="sets the refresh cookie"),
    P("/v1/portal/refresh",
      "Exchange the refresh cookie for a fresh ID token (a page does this on load and before the token expires). "
      "No request body.", None, SESSION,
      [(401, "NO_SESSION", "no cookie, or it was rejected (the cookie is cleared): log in again"),
       (403, "FORBIDDEN", "see signup"), (429, "TOO_MANY", "keep the cookie and try again later")],
      cookie_in=True),
    P("/v1/portal/logout", "Revoke the refresh token and clear the cookie. No request body.", None,
      {"status": "signed_out"}, [(403, "FORBIDDEN", "see signup")], cookie_in=True, cookie_out="clears the cookie"),
    P("/v1/portal/forgot", "Email a password reset code. The same answer for every address.",
      {"email": "jane@example.com"}, {"status": "code_sent"},
      [(400, "BAD_REQUEST", "invalid email"), (403, "FORBIDDEN", "see signup"), (429, "TOO_MANY", "limit reached")]),
    P("/v1/portal/reset", "Set a new password with the emailed code.",
      {"email": "jane@example.com", "code": "123456", "password": "Another-Horse-9"}, {"status": "password_changed"},
      [(400, "WEAK_PASSWORD", "see signup"), (400, "BAD_CODE", "wrong code"), (400, "CODE_EXPIRED", "ask again"),
       (403, "FORBIDDEN", "see signup"), (429, "TOO_MANY", "limit reached")]),
]


def portal_route_keys():
    return {"POST " + p["path"] for p in PORTAL}


def console_route_keys():
    return {"{} {}".format(r["method"], r["path"].replace("/v1/admin/", "/v1/console/"))
            for r in ROUTES if r["scope"] == "admin"}


def openapi_portal():
    paths = {}
    for p in PORTAL:
        responses = {"200": {"description": "Success" + (" and " + p["cookie_out"] if p["cookie_out"] else ""),
                             "content": {"application/json": {"example": p["ok"]}}}}
        by_status = {}
        for status, code, meaning in p["errors"]:
            by_status.setdefault(str(status), []).append("`{}`: {}".format(code, meaning))
        for status, lines in by_status.items():
            responses[status] = {"description": "Error body `{\"error\": {\"code\", \"message\"}}`. " + "; ".join(lines)}
        parameters = [{"name": CSRF_HEADER, "in": "header", "required": True, "schema": {"type": "string", "enum": [CSRF_VALUE]},
                       "description": "Marks a deliberate call from the site's own page. The request's Origin must also "
                                      "be the site's origin (a browser sets it)."}]
        if p["cookie_in"]:
            parameters.append({"name": COOKIE, "in": "cookie", "required": True, "schema": {"type": "string"},
                               "description": "The refresh cookie set by login (HttpOnly; Secure; SameSite=Strict; "
                                              "Path={}). The browser sends it by itself.".format(COOKIE_PATH)})
        op = {"summary": p["summary"], "tags": ["Sign-up and login"], "parameters": parameters, "security": [],
              "responses": responses}
        if p["body"] is not None:
            op["requestBody"] = {"required": True, "content": {"application/json": {
                "schema": {"type": "object"}, "example": p["body"]}}}
        paths[p["path"]] = {"post": op}

    for r in ROUTES:
        if r["scope"] != "admin":
            continue
        path = r["path"].replace("/v1/admin/", "/v1/console/")
        op = {
            "summary": r["summary"] + " (Same operation as the admin API, for a signed-in person.)",
            "tags": ["Console"],
            "parameters": [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}}
                           for n in re.findall(r"\{(\w+)\}", r["path"])]
            + [{"name": q, "in": "query", "schema": {"type": "string"}} for q in r["query"]],
            "security": [{"BearerAuth": []}],
            "responses": {
                "200": {"description": "Success"},
                "401": {"description": "Missing, invalid or expired ID token: refresh it or log in again."},
                "403": {"description": "`TENANT_DISABLED` (the tenant was suspended or banned) or `NO_TENANT`."},
                "4XX": {"description": "Error: {\"error\": {\"code\": ..., \"message\": ...}}"},
            },
        }
        if r["body"] is not None:
            op["requestBody"] = {"required": True, "content": {"application/json": {
                "schema": {"type": "object"}, "example": _fill(r["body"])}}}
        paths.setdefault(path, {})[r["method"].lower()] = op
    return {
        "openapi": "3.0.3",
        "info": {"title": "MCP Licensing - Sign-up, login and console API", "version": "1.0.0",
                 "description": "Called by a web page served from the same domain as these routes (there is no CORS). "
                                "See docs/login-api.md for the flow, the cookie and the headers."},
        "servers": [{"url": "{site_url}", "variables": {"site_url": {"default": SITE_URL}}}],
        "components": {"securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}},
        "paths": paths,
    }


# Variables each path placeholder maps to in Postman.
PATH_VARS = {"key_id": "key_id", "license_id": "license_id", "device_id": "device_id",
             "tenant_id": "tenant_id"}


def route_keys():
    return {"{} {}".format(r["method"], r["path"]) for r in ROUTES}


# ------------------------------------------------------------------ OpenAPI

def _fill(value):
    if isinstance(value, dict):
        return {k: _fill(v) for k, v in value.items()}
    if isinstance(value, str):
        return re.sub(r"\{\{(\w+)\}\}", lambda m: SAMPLES[m.group(1)], value)
    return value


def openapi(scopes, title):
    paths = {}
    for r in ROUTES:
        if r["scope"] not in scopes:
            continue
        op = {
            "summary": r["summary"],
            "tags": [r["group"]],
            "parameters": [],
            "responses": {
                "200": {"description": "Success"},
                "4XX": {"description": "Error: {\"error\": {\"code\": ..., \"message\": ...}}"},
            },
        }
        for name in re.findall(r"\{(\w+)\}", r["path"]):
            op["parameters"].append({"name": name, "in": "path", "required": True,
                                     "schema": {"type": "string"}})
        for name in r["query"]:
            op["parameters"].append({"name": name, "in": "query", "schema": {"type": "string"}})
        if r["body"] is not None:
            op["requestBody"] = {"required": True, "content": {"application/json": {
                "schema": {"type": "object"}, "example": _fill(r["body"])}}}
        if r["auth"]:
            op["security"] = [{"TenantApiKey": []}]
        else:
            op["security"] = []
            op["responses"]["401"] = {"description": "INVALID_KEY"}
            op["responses"]["403"] = {
                "description": "GLOBAL_DISABLED, TENANT_DISABLED, LICENSE_REVOKED, "
                               "LICENSE_EXPIRED or SEAT_LIMIT. The client must stop and clear its cache."}
            op["responses"]["429"] = {
                "description": "RATE_LIMITED: this tenant exceeded its verify requests per minute "
                               "(default 100). Not a denial. Retry after retry_after_seconds; "
                               "meanwhile keep running on the last successful result."}
        paths.setdefault(r["path"], {})[r["method"].lower()] = op
    return {
        "openapi": "3.0.3",
        "info": {"title": title, "version": "1.0.0"},
        "servers": [{"url": "{base_url}", "variables": {"base_url": {"default": PUBLIC_URL}}}],
        "components": {"securitySchemes": {"TenantApiKey": {
            "type": "apiKey", "in": "header", "name": "X-Tenant-Api-Key"}}},
        "paths": paths,
    }


# ------------------------------------------------------------------ Postman

def _postman_item(r):
    path = re.sub(r"\{(\w+)\}", lambda m: "{{" + PATH_VARS[m.group(1)] + "}}", r["path"])
    item = {
        "name": "{} {}".format(r["method"], r["summary"].split(".")[0]),
        "request": {
            "method": r["method"],
            "header": [],
            "url": {
                "raw": "{{base_url}}" + path,
                "host": ["{{base_url}}"],
                "path": [p for p in path.split("/") if p],
                "query": [{"key": q, "value": "", "disabled": True} for q in r["query"]],
            },
            "description": r["summary"],
        },
    }
    if r["body"] is not None:
        item["request"]["header"].append({"key": "Content-Type", "value": "application/json"})
        item["request"]["body"] = {"mode": "raw", "raw": json.dumps(r["body"], indent=2),
                                   "options": {"raw": {"language": "json"}}}
    if not r["auth"]:
        item["request"]["auth"] = {"type": "noauth"}
    if r["saves"]:
        lines = ["const data = pm.response.json();"]
        for var, field in r["saves"].items():
            lines.append("if (data.{f}) pm.environment.set('{v}', data.{f});".format(f=field, v=var))
        item["event"] = [{"listen": "test", "script": {"type": "text/javascript", "exec": lines}}]
    return item


def postman_collection(scopes, name, key_var, description):
    folders = {}
    for r in ROUTES:
        if r["scope"] in scopes:
            folders.setdefault(r["group"], []).append(_postman_item(r))
    return {
        "info": {
            "name": name,
            "description": description,
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "auth": {"type": "apikey", "apikey": [
            {"key": "key", "value": "X-Tenant-Api-Key", "type": "string"},
            {"key": "value", "value": "{{%s}}" % key_var, "type": "string"},
            {"key": "in", "value": "header", "type": "string"}]},
        "item": [{"name": g, "item": items} for g, items in folders.items()],
    }


def postman_environment(name, values):
    return {
        "name": name,
        "values": [{"key": k, "value": v, "type": "secret" if "key" in k and k != "key_id" and
                    k != "base_url" else "default", "enabled": True} for k, v in values],
        "_postman_variable_scope": "environment",
    }


def write(path, data, as_yaml=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        if as_yaml:
            yaml.safe_dump(data, handle, sort_keys=False, width=100)
        else:
            json.dump(data, handle, indent=2)
            handle.write("\n")


def main():
    write(os.path.join(DOCS, "openapi-tenant.yaml"),
          openapi({"mcp", "admin"}, "MCP Licensing - Tenant API"), as_yaml=True)
    write(os.path.join(DOCS, "openapi-internal.yaml"),
          openapi({"mcp", "admin", "super"}, "MCP Licensing - Full API (internal)"), as_yaml=True)

    write(os.path.join(DOCS, "openapi-portal.yaml"), openapi_portal(), as_yaml=True)

    pm = os.path.join(DOCS, "postman")
    write(os.path.join(pm, "mcp_licensing_tenant.postman_collection.json"),
          postman_collection(
              {"mcp", "admin"}, "MCP Licensing - Tenant API", "tenant_api_key",
              "Manage your licenses. Import the environment file, set base_url and "
              "tenant_api_key, then run requests. Keys and license keys are shown once."))
    write(os.path.join(pm, "mcp_licensing_tenant.postman_environment.json"),
          postman_environment("MCP Licensing - Tenant", [
              ("base_url", PUBLIC_URL),
              ("tenant_api_key", ""), ("license_key", ""), ("device_id", "postman-test-device"),
              ("license_id", ""), ("key_id", "")]))
    write(os.path.join(pm, "mcp_licensing_super.postman_collection.json"),
          postman_collection(
              {"super"}, "MCP Licensing - Platform (internal)", "super_api_key",
              "Platform owner operations. Do not share this collection with customers."))
    write(os.path.join(pm, "mcp_licensing_super.postman_environment.json"),
          postman_environment("MCP Licensing - Platform", [
              ("base_url", PUBLIC_URL),
              ("super_api_key", ""), ("tenant_id", "")]))
    print("docs written to", os.path.normpath(DOCS))


if __name__ == "__main__":
    main()
