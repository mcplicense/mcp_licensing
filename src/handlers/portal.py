"""Self-service sign-up and login (/v1/portal/*), the only public door to Cognito.

    POST /v1/portal/signup   email, password, company_name, accept_terms  -> a code is emailed
    POST /v1/portal/resend   email                                        -> a new code
    POST /v1/portal/confirm  email, code    -> the address is confirmed and the tenant is created
    POST /v1/portal/login    email, password -> an ID token (for /v1/console/*) + a refresh cookie
    POST /v1/portal/refresh  (cookie)        -> a fresh ID token
    POST /v1/portal/logout   (cookie)        -> the refresh token is revoked
    POST /v1/portal/forgot   email           -> a reset code is emailed
    POST /v1/portal/reset    email, code, password

Nothing here reveals whether an address has an account: sign-up, resend and forgot answer
the same way whoever asks. The ID token lives in the page's memory only; the long-lived refresh
token is an HttpOnly cookie the page's scripts cannot read. Every call must come from the site
(Origin) and carry X-Requested-With, which a browser will not send from another website
without a CORS preflight that this API never grants.

A new tenant is created when the address is confirmed: active at once, a generated id,
the person recorded as its owner, and the operator told by email.
"""
import logging
import os
import re

import boto3

from core import clientip, cognito, config, identity, service, store
from core.http import ApiError, from_our_site, get_header, json_body, make_handler, response

logger = logging.getLogger()

COOKIE = "mcp_rt"
COOKIE_PATH = "/v1/portal/"
REFRESH_SECONDS = 12 * 3600  # keep equal to RefreshTokenValidity in template.yml
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "mcp-portal"
CODE_RE = re.compile(r"^\d{6}$")

_sns_client = {"obj": None}


def _sns():
    if _sns_client["obj"] is None:
        _sns_client["obj"] = boto3.client("sns")
    return _sns_client["obj"]


# ---------------------------------------------------------------------- guards

def _guard(event):
    """Only the site's own pages may call these, and only deliberately (not by a plain link or form)."""
    if not from_our_site(event) or get_header(event, CSRF_HEADER) != CSRF_VALUE:
        raise ApiError(403, "FORBIDDEN", "Forbidden.")


def _minutes(seconds):
    return max(1, (seconds + 59) // 60)


def _limit_visitor(scope, event, attempts_setting, lock_setting):
    allowed, retry = store.take_attempt(scope, clientip.rate_key(event),
                                        config.get_int(attempts_setting), config.get_int(lock_setting))
    if not allowed:
        logger.warning("portal %s refused: visitor locked out", scope)
        raise ApiError(429, "TOO_MANY", "Too many attempts from your network. Please try again in about {} minutes."
                       .format(_minutes(retry)))


def _limit_address(scope, email):
    allowed, _ = store.take_window_slot(scope, identity.email_hash(email), config.get_int("signup_email_per_hour"), 3600)
    if not allowed:
        raise ApiError(429, "TOO_MANY", "Too many emails were sent to this address recently. Please wait an hour.")


def _email(body):
    email = identity.clean_email(body.get("email"))
    if email is None:
        raise ApiError(400, "BAD_REQUEST", "Enter a valid email address.")
    return email


def _code(body):
    code = str(body.get("code", "")).strip()
    if not CODE_RE.match(code):
        raise ApiError(400, "BAD_CODE", "Enter the 6-digit code from the email.")
    return code


def _json(status, body, cookies=None):
    result = response(status, body)
    if cookies:
        result["cookies"] = cookies
    return result


def _session_cookie(sub, refresh_token):
    return "{}={}~{}; Max-Age={}; Path={}; HttpOnly; Secure; SameSite=Strict".format(
        COOKIE, sub, refresh_token, REFRESH_SECONDS, COOKIE_PATH)


def _clear_cookie():
    return "{}=; Max-Age=0; Path={}; HttpOnly; Secure; SameSite=Strict".format(COOKIE, COOKIE_PATH)


def _read_cookie(event):
    """(sub, refresh_token) from the session cookie, or None."""
    for cookie in event.get("cookies") or []:
        name, _, value = cookie.partition("=")
        if name.strip() == COOKIE and "~" in value:
            sub, _, token = value.partition("~")
            if sub and token:
                return sub, token
    return None


# ------------------------------------------------------------------ the tenant

def _notify_operator(tenant, event):
    topic = os.environ.get("NOTIFY_TOPIC_ARN")
    country = get_header(event, "cloudfront-viewer-country") or ""
    country = country if re.fullmatch(r"[A-Z]{2}", country) else "unknown"
    try:
        if not topic:
            return
        _sns().publish(
            TopicArn=topic, Subject="MCP Licensing: new tenant {}".format(tenant["tenant_id"].upper()),
            Message="A new provider signed up.\n\nTenant:  {}\nCompany: {}\nEmail:   {}\nCountry: {}\nTime:    {}\n\n"
                    "To ban: POST /v1/super/tenants/{}/ban".format(
                        tenant["tenant_id"].upper(), tenant["company_name"], tenant["email"], country,
                        store.now_iso(), tenant["tenant_id"]))
    except Exception:
        logger.exception("could not notify the operator of a new tenant")


def _provision(email, event):
    """The tenant id of this confirmed person, creating the tenant the first time."""
    user = cognito.get_user(email)
    if user is None:
        raise ApiError(502, "UPSTREAM_ERROR", "The sign-in service had a problem. Please try again shortly.")
    if user.get("custom:tenant_id"):
        return user["custom:tenant_id"]
    tenant = service.provision_tenant(email, user.get("custom:company") or "Unnamed", user.get("_sub"))
    cognito.set_tenant(email, tenant["tenant_id"])
    _notify_operator(tenant, event)
    logger.info("tenant created for a new sign-up")
    return tenant["tenant_id"]


# -------------------------------------------------------------------- sign-up

def signup(event):
    _guard(event)
    body = json_body(event)
    email = _email(body)
    company = identity.clean_company(body.get("company_name"))
    if company is None:
        raise ApiError(400, "BAD_REQUEST", "Enter your company or project name (2 to 100 characters).")
    if body.get("accept_terms") is not True:
        raise ApiError(400, "BAD_REQUEST", "Please accept the terms and the privacy policy.")
    password = body.get("password")
    problem = identity.password_problem(password, email)
    if problem:
        raise ApiError(400, "WEAK_PASSWORD", problem)

    _limit_visitor("signup", event, "signup_ip_attempts", "signup_ip_lock_seconds")
    if str(body.get("website") or "").strip():  # a bot filled in the hidden field: look like success
        logger.warning("sign-up: honeypot filled")
        return _json(200, {"status": "code_sent"})
    _limit_address("signup-email", email)
    sent_today, _ = store.take_window_slot("signup-day", "all", config.get_int("signup_daily_cap"), 86400)
    if not sent_today:
        raise ApiError(429, "TOO_MANY", "Sign-ups are very busy right now. Please try again tomorrow.")
    if store.get_banned(identity.email_hash(email)):
        raise ApiError(403, "NOT_ALLOWED", "This email address cannot be used to sign up. Contact support if you think this is a mistake.")

    try:
        cognito.sign_up(email, password, company)
    except cognito.Exists:
        cognito.resend_code(email)  # a person who lost the first code can simply sign up again
    return _json(200, {"status": "code_sent"})


def resend(event):
    _guard(event)
    email = _email(json_body(event))
    _limit_visitor("resend", event, "signup_ip_attempts", "signup_ip_lock_seconds")
    _limit_address("signup-email", email)
    cognito.resend_code(email)
    return _json(200, {"status": "code_sent"})


def confirm(event):
    _guard(event)
    body = json_body(event)
    email, code = _email(body), _code(body)
    _limit_address("confirm-email", email)
    try:
        cognito.confirm_sign_up(email, code)
    except ApiError as exc:
        if exc.code == "BAD_LOGIN":  # Cognito's answer for an address that is already confirmed
            raise ApiError(400, "BAD_CODE", "That code is not valid. If you already confirmed this address, log in.")
        raise
    _provision(email, event)
    return _json(200, {"status": "confirmed"})


# ----------------------------------------------------------------- the session

def _session_response(tokens, email):
    """The ID token for the page and, when there is one, the refresh cookie."""
    claims = cognito.token_claims(tokens["IdToken"])
    body = {"id_token": tokens["IdToken"], "expires_in": int(tokens.get("ExpiresIn", 900)),
            "email": claims.get("email", email), "tenant_id": claims.get("custom:tenant_id")}
    cookies = None
    if tokens.get("RefreshToken"):
        cookies = [_session_cookie(claims.get("sub", ""), tokens["RefreshToken"])]
    return _json(200, body, cookies)


def login(event):
    _guard(event)
    body = json_body(event)
    email = _email(body)
    password = body.get("password")
    if not isinstance(password, str) or not password or len(password) > identity.MAX_PASSWORD:
        raise ApiError(400, "BAD_REQUEST", "Enter your password.")
    _limit_visitor("login", event, "login_ip_attempts", "login_ip_lock_seconds")

    tokens = cognito.login(email, password)
    claims = cognito.token_claims(tokens["IdToken"])
    if not claims.get("custom:tenant_id"):  # confirmed but the tenant was never created: finish the job
        _provision(email, event)
        refreshed = cognito.refresh(tokens["RefreshToken"], claims.get("sub", ""))
        refreshed["RefreshToken"] = tokens["RefreshToken"]
        tokens = refreshed
    return _session_response(tokens, email)


def refresh(event):
    _guard(event)
    session = _read_cookie(event)
    if session is None:
        return _json(401, {"error": {"code": "NO_SESSION", "message": "Please sign in."}})
    sub, token = session
    try:
        tokens = cognito.refresh(token, sub)
    except ApiError as exc:
        if exc.code != "BAD_LOGIN":  # rate limited or a service problem: keep the cookie, try again later
            raise
        return _json(401, {"error": {"code": "NO_SESSION", "message": "Please sign in."}}, [_clear_cookie()])
    return _session_response(tokens, "")


def logout(event):
    _guard(event)
    session = _read_cookie(event)
    if session is not None:
        cognito.revoke(session[1])
    return _json(200, {"status": "signed_out"}, [_clear_cookie()])


# ------------------------------------------------------------- password reset

def forgot(event):
    _guard(event)
    email = _email(json_body(event))
    _limit_visitor("forgot", event, "signup_ip_attempts", "signup_ip_lock_seconds")
    _limit_address("signup-email", email)
    cognito.forgot_password(email)
    return _json(200, {"status": "code_sent"})


def reset(event):
    _guard(event)
    body = json_body(event)
    email, code = _email(body), _code(body)
    password = body.get("password")
    problem = identity.password_problem(password, email)
    if problem:
        raise ApiError(400, "WEAK_PASSWORD", problem)
    _limit_address("confirm-email", email)
    cognito.confirm_forgot_password(email, code, password)
    return _json(200, {"status": "password_changed"})


handler = make_handler({
    "POST /v1/portal/signup": signup,
    "POST /v1/portal/resend": resend,
    "POST /v1/portal/confirm": confirm,
    "POST /v1/portal/login": login,
    "POST /v1/portal/refresh": refresh,
    "POST /v1/portal/logout": logout,
    "POST /v1/portal/forgot": forgot,
    "POST /v1/portal/reset": reset,
})
