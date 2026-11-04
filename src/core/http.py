"""HTTP API (payload v2) helpers: request parsing, responses, routing."""
import base64
import decimal
import hmac
import json
import logging
import os

from core import config

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 16 * 1024
ORIGIN_HEADER = "X-Origin-Verify"


class ApiError(Exception):
    def __init__(self, status, code, message=None):
        super().__init__(message or code)
        self.status = status
        self.code = code
        self.message = message or code


def _json_default(value):
    if isinstance(value, decimal.Decimal):
        return int(value) if value % 1 == 0 else float(value)
    if isinstance(value, set):
        return sorted(value)
    raise TypeError("not serializable: {!r}".format(type(value)))


def response(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        },
        "body": json.dumps(body, default=_json_default),
    }


def error_response(status, code, message):
    return response(status, {"error": {"code": code, "message": message}})


def get_header(event, name):
    return (event.get("headers") or {}).get(name.lower())


def from_our_site(event):
    """With SITE_ORIGIN set, accept only a request that came from the site's own pages. A browser
    always sends Origin on a POST, Referer is the fallback. (This is a check against other websites
    driving a visitor's browser; it does not stop a script, which can send any header.)"""
    origin = os.environ.get("SITE_ORIGIN", "").rstrip("/")
    if not origin:
        return True
    sent = get_header(event, "origin")
    if sent:
        return sent.rstrip("/") == origin
    referer = get_header(event, "referer") or ""
    return referer == origin or referer.startswith(origin + "/")


def json_body(event):
    raw = event.get("body")
    if raw is None or raw == "":
        return {}
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    if len(raw) > MAX_BODY_BYTES:
        raise ApiError(413, "PAYLOAD_TOO_LARGE", "Request body is too large.")
    try:
        data = json.loads(raw)
    except ValueError:
        raise ApiError(400, "BAD_REQUEST", "Body must be valid JSON.")
    if not isinstance(data, dict):
        raise ApiError(400, "BAD_REQUEST", "Body must be a JSON object.")
    return data


def path_param(event, name):
    value = (event.get("pathParameters") or {}).get(name)
    if not value:
        raise ApiError(400, "BAD_REQUEST", "Missing path parameter {}.".format(name))
    return value


def query_param(event, name, default=None):
    return (event.get("queryStringParameters") or {}).get(name, default)


def origin_allowed(event):
    """True when the request came through our CloudFront distribution.

    CloudFront adds a secret header to every request it forwards, and WAF sits
    on CloudFront, so a request without the header skipped WAF by calling the
    raw API Gateway URL. ORIGIN_SECRET (and ORIGIN_SECRET_PREVIOUS, kept while
    the secret is rotated) turn the check on; with neither set it is off, as in
    dev and tests. Every candidate is compared in constant time."""
    secrets = [s for s in (os.environ.get("ORIGIN_SECRET"), os.environ.get("ORIGIN_SECRET_PREVIOUS")) if s]
    if not secrets:
        return True
    supplied = (get_header(event, ORIGIN_HEADER) or "").encode("utf-8")
    matches = [hmac.compare_digest(supplied, secret.encode("utf-8")) for secret in secrets]
    return any(matches)


def make_handler(routes):
    """Build a Lambda handler that dispatches on the HTTP API routeKey."""

    def handler(event, context):
        config.start_request()
        route_key = event.get("routeKey")
        func = routes.get(route_key)
        if not origin_allowed(event):
            logger.warning("request refused: missing or wrong %s header", ORIGIN_HEADER)
            return error_response(403, "FORBIDDEN", "Forbidden.")
        try:
            if func is None:
                raise ApiError(404, "NOT_FOUND", "Unknown route.")
            result = func(event)
            if isinstance(result, dict):  # a finished response (a redirect, an HTML page)
                return result
            status, body = result
            return response(status, body)
        except ApiError as exc:
            return error_response(exc.status, exc.code, exc.message)
        except Exception:
            # Never echo internals (or request data) back to the caller.
            logger.exception("unhandled error on %s", route_key)
            return error_response(500, "INTERNAL_ERROR", "Internal error.")

    return handler
