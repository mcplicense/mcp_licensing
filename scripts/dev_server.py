"""Run the API (and a frontend, if you have one) locally, with nothing in AWS.

    python scripts/dev_server.py                       # the API only, on http://localhost:8780
    python scripts/dev_server.py --dir path/to/pages   # ... and your static pages on the same origin

With --dir it serves that folder (a folder with an index.html; /x/ serves /x/index.html). Without it, and when
a site_dist/ folder with an index.html exists, it serves that. It routes /v1/portal, /v1/console and /v1/site to the real handlers, backed by
in-memory AWS (moto) and the stand-in for Cognito from the tests. It stands in for the two things API
Gateway and CloudFront do: the JWT check on /v1/console (it reads the Authorization header the way the
authorizer would) and the index-page rewrite. The emailed codes are not sent anywhere: they are listed at
/__dev/codes so you can finish a sign-up, and the operator's notifications at /__dev/notifications.

For development only: the token check here does not verify signatures, which the real authorizer does.
"""
import argparse
import json
import os
import pathlib
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

os.environ.update({"AWS_ACCESS_KEY_ID": "dev", "AWS_SECRET_ACCESS_KEY": "dev", "AWS_DEFAULT_REGION": "us-east-1"})
os.environ.pop("SSM_PREFIX", None)

from moto import mock_aws  # noqa: E402

from conftest import _create_tables_from_template, load_template  # noqa: E402
from core import cognito, config, store  # noqa: E402
from fake_cognito import CLIENT_ID, CLIENT_SECRET, POOL_ID, FakeCognito  # noqa: E402

API_PREFIXES = ("/v1/portal/", "/v1/console/", "/v1/site/")
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml",
        ".txt": "text/plain", ".xml": "application/xml", ".json": "application/json", ".yaml": "text/plain", ".py": "text/plain"}


class Dev:
    def __init__(self, directory):
        self.directory = directory
        self.pool = FakeCognito()
        self.notifications = []
        self.lock = threading.RLock()  # moto is not thread safe

    def start(self):
        self.mock = mock_aws()
        self.mock.start()
        _create_tables_from_template(load_template())
        store.reset()
        config.reset_cache()
        cognito._client["obj"] = self.pool
        for name, value in (("USER_POOL_ID", POOL_ID), ("USER_POOL_CLIENT_ID", CLIENT_ID),
                            ("USER_POOL_CLIENT_SECRET", CLIENT_SECRET), ("NOTIFY_TOPIC_ARN", "arn:aws:sns:us-east-1:1:dev"),
                            ("CONTACT_TOPIC_ARN", "arn:aws:sns:us-east-1:1:dev")):
            os.environ[name] = value
        from handlers import contact, portal

        class Sns:
            def publish(inner, **kwargs):
                self.notifications.append({"subject": kwargs["Subject"], "message": kwargs["Message"]})

        portal._sns_client["obj"] = Sns()
        contact._sns_client["obj"] = Sns()

    def route(self, method, path):
        """(handler module, routeKey, path parameters) for a concrete request, or None."""
        from handlers import admin, contact, portal
        for module in (portal, admin, contact):
            for key in module.handler.__closure__[0].cell_contents:
                key_method, pattern = key.split(" ", 1)
                if key_method != method:
                    continue
                names = re.findall(r"\{(\w+)\}", pattern)
                match = re.fullmatch(re.sub(r"\{\w+\}", "([^/]+)", pattern), path)
                if match:
                    return module, key, dict(zip(names, match.groups()))
        return None

    def api(self, request):
        """Answer one API request: returns (status, headers, cookies, body)."""
        url = urlsplit(request.path)
        found = self.route(request.command, url.path)
        if found is None:
            return 404, {}, [], b'{"message":"Not Found"}'
        module, key, params = found
        length = int(request.headers.get("Content-Length") or 0)
        body = request.rfile.read(length).decode("utf-8") if length else None
        headers = {k.lower(): v for k, v in request.headers.items()}
        headers["cloudfront-viewer-address"] = "127.0.0.1:50000"
        headers["cloudfront-viewer-country"] = "IN"
        event = {"routeKey": key, "headers": headers, "pathParameters": params or None, "body": body,
                 "queryStringParameters": {k: v[0] for k, v in parse_qs(url.query).items()} or None,
                 "cookies": [c.strip() for c in request.headers.get("Cookie", "").split(";") if c.strip()],
                 "requestContext": {}}
        if "/v1/console/" in key:  # what API Gateway's JWT authorizer does before the Lambda runs
            token = headers.get("authorization", "")[7:]
            claims = cognito.token_claims(token)
            if not token or claims.get("aud") != CLIENT_ID:
                return 401, {}, [], b'{"message":"Unauthorized"}'
            event["requestContext"] = {"authorizer": {"jwt": {"claims": claims}}}
        with self.lock:
            result = module.handler(event, None)
        return result["statusCode"], result.get("headers", {}), result.get("cookies", []), (result.get("body") or "").encode("utf-8")


def make_handler(dev):
    class Handler(BaseHTTPRequestHandler):
        server_version = "mcp-dev"

        def log_message(self, fmt, *args):
            sys.stderr.write("  %s %s -> %s\n" % (self.command, self.path.split("?")[0], args[1] if len(args) > 1 else ""))

        def _send(self, status, headers, cookies, body):
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle(self):
            path = urlsplit(self.path).path
            if path == "/__dev/codes":
                return self._send(200, {"Content-Type": "application/json"}, [], json.dumps(
                    [{"kind": k, "email": e, "code": c} for k, e, c in dev.pool.sent_codes]).encode())
            if path == "/__dev/notifications":
                return self._send(200, {"Content-Type": "application/json"}, [], json.dumps(dev.notifications).encode())
            if path.startswith(API_PREFIXES):
                status, headers, cookies, body = dev.api(self)
                headers.setdefault("Content-Type", "application/json")
                return self._send(status, headers, cookies, body)
            if self.command not in ("GET", "HEAD"):
                return self._send(403, {}, [], b"Forbidden")
            if dev.directory is None:
                return self._send(404, {"Content-Type": "text/plain"}, [], b"API only: pass --dir to serve pages")
            if path.endswith("/"):
                path += "index.html"
            elif "." not in path.rsplit("/", 1)[-1]:
                return self._send(301, {"Location": path + "/"}, [], b"")
            file = (dev.directory / path.lstrip("/")).resolve()
            if dev.directory.resolve() not in file.parents or not file.is_file():
                page = dev.directory / "404.html"
                if page.is_file():
                    return self._send(404, {"Content-Type": MIME[".html"]}, [], page.read_bytes())
                return self._send(404, {"Content-Type": "text/plain"}, [], b"Not found")
            self._send(200, {"Content-Type": MIME.get(file.suffix, "application/octet-stream"), "Cache-Control": "no-store"},
                       [], file.read_bytes())

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int, default=8780)
    parser.add_argument("--dir", default=None, help="folder of static pages to serve on the same origin")
    args = parser.parse_args()
    directory = pathlib.Path(args.dir) if args.dir else ROOT / "site_dist"
    if args.dir and not (directory / "index.html").is_file():
        sys.exit("{} has no index.html".format(directory))
    if not (directory / "index.html").is_file():
        directory = None
    dev = Dev(directory)
    dev.start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(dev))
    print("{} on http://localhost:{}   (codes: /__dev/codes)".format(
        "pages and API" if directory else "API only", args.port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
