"""Amazon Cognito, behind our own endpoints.

Browsers never call Cognito: the app client has a secret, and only the portal
Lambda holds it. This module is the only place that talks to Cognito, and it
turns Cognito's exceptions into our own ApiError codes with plain messages.

The pool signs people in with their email address. A tenant's id is stored in
the user attribute custom:tenant_id, which the app client cannot write (only
this code can, through the admin API), and it travels in the ID token.
"""
import base64
import hashlib
import hmac
import logging
import os

import boto3
from botocore.exceptions import ClientError

from core.http import ApiError

logger = logging.getLogger(__name__)

_client = {"obj": None}


def reset():
    _client["obj"] = None


def _cognito():
    if _client["obj"] is None:
        _client["obj"] = boto3.client("cognito-idp")
    return _client["obj"]


def _client_id():
    return os.environ["USER_POOL_CLIENT_ID"]


def _pool_id():
    return os.environ["USER_POOL_ID"]


def secret_hash(username):
    """Cognito requires this proof of the client secret with every call."""
    digest = hmac.new(os.environ["USER_POOL_CLIENT_SECRET"].encode("utf-8"),
                      (username + _client_id()).encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


# What Cognito says -> (status, our code, what the person sees). Anything not listed is a 502:
# we never show a visitor Cognito's own wording.
_ERRORS = {
    "InvalidPasswordException": (400, "WEAK_PASSWORD", "That password is not accepted. Use at least 12 characters with a capital letter, a lower-case letter and a number."),
    "InvalidParameterException": (400, "BAD_REQUEST", "Please check what you entered and try again."),
    "CodeMismatchException": (400, "BAD_CODE", "That code is not right. Check it and try again."),
    "ExpiredCodeException": (400, "CODE_EXPIRED", "That code has expired. Request a new one."),
    "NotAuthorizedException": (401, "BAD_LOGIN", "Incorrect email or password."),
    "UserNotConfirmedException": (403, "NOT_CONFIRMED", "This email address has not been confirmed yet."),
    "PasswordResetRequiredException": (403, "RESET_REQUIRED", "Please reset your password."),
    "LimitExceededException": (429, "TOO_MANY", "Too many attempts. Please wait a while and try again."),
    "TooManyRequestsException": (429, "TOO_MANY", "Too many attempts. Please wait a while and try again."),
    "TooManyFailedAttemptsException": (429, "TOO_MANY", "Too many attempts. Please wait a while and try again."),
}
_EXISTS = "UsernameExistsException"
_NOT_FOUND = "UserNotFoundException"


class Exists(Exception):
    """sign_up found a user with this address already."""


def _call(operation, **kwargs):
    try:
        return getattr(_cognito(), operation)(**kwargs)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == _EXISTS:
            raise Exists()
        if code in _ERRORS:
            status, our_code, message = _ERRORS[code]
            raise ApiError(status, our_code, message)
        logger.exception("cognito %s failed: %s", operation, code)
        raise ApiError(502, "UPSTREAM_ERROR", "The sign-in service had a problem. Please try again shortly.")


def sign_up(email, password, company):
    """Create an unconfirmed user and have Cognito email the code. Raises Exists."""
    _call("sign_up", ClientId=_client_id(), SecretHash=secret_hash(email), Username=email, Password=password,
          UserAttributes=[{"Name": "email", "Value": email}, {"Name": "custom:company", "Value": company}])


def resend_code(email):
    try:
        _call("resend_confirmation_code", ClientId=_client_id(), SecretHash=secret_hash(email), Username=email)
    except ApiError as exc:
        if exc.code not in ("BAD_REQUEST",):  # already confirmed or unknown: nothing to say
            raise


def confirm_sign_up(email, code):
    _call("confirm_sign_up", ClientId=_client_id(), SecretHash=secret_hash(email), Username=email,
          ConfirmationCode=code)


def login(email, password):
    """Returns Cognito's AuthenticationResult (IdToken, AccessToken, RefreshToken, ExpiresIn)."""
    result = _call("initiate_auth", ClientId=_client_id(), AuthFlow="USER_PASSWORD_AUTH",
                   AuthParameters={"USERNAME": email, "PASSWORD": password, "SECRET_HASH": secret_hash(email)})
    if "AuthenticationResult" not in result:  # a challenge (MFA, new password): not offered yet
        raise ApiError(400, "UNSUPPORTED", "This account needs a sign-in step that is not available yet. Contact support.")
    return result["AuthenticationResult"]


def refresh(refresh_token, username):
    """A fresh ID token from a refresh token. The secret hash for this flow is computed from the
    user's real Cognito username (their sub, because the pool signs people in by email), not from
    the email they typed."""
    result = _call("initiate_auth", ClientId=_client_id(), AuthFlow="REFRESH_TOKEN_AUTH",
                   AuthParameters={"REFRESH_TOKEN": refresh_token, "SECRET_HASH": secret_hash(username)})
    return result["AuthenticationResult"]


def token_claims(token):
    """The claims of a JWT we have just received from Cognito over TLS, WITHOUT checking its
    signature (we only read them; API Gateway verifies tokens that come back to us). Returns {}
    for anything that is not a JWT."""
    import json
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError, AttributeError, TypeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def revoke(refresh_token):
    try:
        _call("revoke_token", ClientId=_client_id(), ClientSecret=os.environ["USER_POOL_CLIENT_SECRET"],
              Token=refresh_token)
    except ApiError:
        logger.warning("could not revoke a refresh token")  # the cookie is cleared regardless


def forgot_password(email):
    try:
        _call("forgot_password", ClientId=_client_id(), SecretHash=secret_hash(email), Username=email)
    except ApiError as exc:
        if exc.code not in ("BAD_REQUEST", "NOT_CONFIRMED"):  # an unknown address looks the same as a known one
            raise


def confirm_forgot_password(email, code, new_password):
    _call("confirm_forgot_password", ClientId=_client_id(), SecretHash=secret_hash(email), Username=email,
          ConfirmationCode=code, Password=new_password)


# ---- admin calls (IAM-authorised; the app client cannot make these) ----

def get_user(email):
    """{attribute: value} for a user, or None when there is no such user."""
    try:
        result = _cognito().admin_get_user(UserPoolId=_pool_id(), Username=email)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == _NOT_FOUND:
            return None
        raise
    attributes = {a["Name"]: a["Value"] for a in result.get("UserAttributes", [])}
    attributes["_enabled"] = result.get("Enabled", True)
    attributes["_sub"] = attributes.get("sub")
    return attributes


def set_tenant(email, tenant_id):
    _cognito().admin_update_user_attributes(
        UserPoolId=_pool_id(), Username=email, UserAttributes=[{"Name": "custom:tenant_id", "Value": tenant_id}])


def disable_user(email):
    _cognito().admin_disable_user(UserPoolId=_pool_id(), Username=email)
    _cognito().admin_user_global_sign_out(UserPoolId=_pool_id(), Username=email)


def enable_user(email):
    _cognito().admin_enable_user(UserPoolId=_pool_id(), Username=email)
