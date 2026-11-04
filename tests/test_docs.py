import json
import pathlib
import sys

from conftest import ROOT, load_template

sys.path.insert(0, str(ROOT / "scripts"))
import build_docs  # noqa: E402


def _template_routes():
    routes = set()
    for resource in load_template()["Resources"].values():
        if resource["Type"] != "AWS::Serverless::Function":
            continue
        for event in resource["Properties"]["Events"].values():
            props = event["Properties"]
            routes.add("{} {}".format(props["Method"], props["Path"]))
    return routes


# The contact form is for a website's own visitors, not part of the documented API. The sign-up and login routes
# are documented in openapi-portal.yaml (with the console, which mirrors the admin API).
SITE_PREFIXES = ("/v1/site/", "/v1/console/")


def _is_site_route(route):
    return route.split(" ", 1)[1].startswith(SITE_PREFIXES)


def test_doc_routes_match_template_and_handlers():
    from handlers import admin, contact, mcp, portal, super_admin
    template_routes = _template_routes()
    documented = build_docs.route_keys() | build_docs.portal_route_keys()
    assert documented == {r for r in template_routes if not _is_site_route(r)}
    assert build_docs.console_route_keys() == {r for r in template_routes if "/v1/console/" in r}
    in_code = set()
    for module in (admin, contact, mcp, portal, super_admin):
        in_code |= set(module.handler.__closure__[0].cell_contents)
    assert in_code == template_routes


def test_the_login_contract_uses_the_values_the_code_uses():
    from handlers import portal
    assert build_docs.CSRF_VALUE == portal.CSRF_VALUE and build_docs.CSRF_HEADER.lower() == portal.CSRF_HEADER
    assert build_docs.COOKIE == portal.COOKIE and build_docs.COOKIE_PATH == portal.COOKIE_PATH
    login_api = (ROOT / "docs" / "login-api.md").read_text(encoding="utf-8")
    for value in (portal.CSRF_VALUE, portal.COOKIE, portal.COOKIE_PATH, "SameSite=Strict", "HttpOnly"):
        assert value in login_api, value


def test_every_documented_login_error_code_exists_in_the_code():
    source = "".join((ROOT / "src" / part).read_text(encoding="utf-8")
                     for part in ("handlers/portal.py", "core/cognito.py", "core/http.py"))
    for p in build_docs.PORTAL:
        for status, code, _ in p["errors"]:
            assert '"{}"'.format(code) in source, code


def test_the_login_docs_response_fields_are_what_the_handler_returns():
    source = (ROOT / "src" / "handlers" / "portal.py").read_text(encoding="utf-8")
    for field in build_docs.SESSION:
        assert '"{}"'.format(field) in source, field


def test_every_console_route_mirrors_an_admin_route():
    """The console is the admin API for a signed-in person: same operations, same handlers."""
    routes = _template_routes()
    console = {r for r in routes if "/v1/console/" in r}
    admin_routes = {r for r in routes if "/v1/admin/" in r}
    assert console == {r.replace("/v1/admin/", "/v1/console/") for r in admin_routes}


def test_generated_docs_are_current(tmp_path, monkeypatch):
    monkeypatch.setattr(build_docs, "DOCS", str(tmp_path))
    build_docs.main()
    for path in tmp_path.rglob("*"):
        if path.is_file():
            committed = ROOT / "docs" / path.relative_to(tmp_path)
            assert committed.read_text(encoding="utf-8") == path.read_text(encoding="utf-8"), \
                "docs are stale; run python scripts/build_docs.py: {}".format(committed)


def test_tenant_collection_has_no_platform_endpoints():
    for name in ("mcp_licensing_tenant.postman_collection.json",
                 "openapi-tenant.yaml",
                 "mcp_licensing_tenant.postman_environment.json"):
        text = (pathlib.Path(ROOT) / "docs" / ("postman" if name.startswith("mcp_") else "") / name
                ).read_text(encoding="utf-8")
        assert "/v1/super" not in text and "super_api_key" not in text


def test_postman_collections_are_well_formed():
    folder = pathlib.Path(ROOT) / "docs" / "postman"
    for path in folder.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        if "item" in data:
            assert data["info"]["schema"].endswith("collection.json")
            assert data["auth"]["apikey"][0]["value"] == "X-Tenant-Api-Key"
