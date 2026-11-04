"""Admin API key authentication, done inside the Lambda.

Header: X-Tenant-Api-Key: mcpk_<key_id>.<secret>
Roles:  tenant_admin  -> /v1/admin/*  (tenant comes from the key record; refused
                         while the platform has the tenant disabled)
        super_admin   -> /v1/super/*
"""
import logging
import os
from collections import namedtuple
from datetime import datetime, timedelta, timezone

from core import keys, store
from core.http import ApiError, get_header

logger = logging.getLogger(__name__)

HEADER = "X-Tenant-Api-Key"
ROLE_TENANT_ADMIN = "tenant_admin"
ROLE_SUPER_ADMIN = "super_admin"
LAST_USED_REFRESH = timedelta(minutes=10)

Principal = namedtuple("Principal", "role tenant_id key_id")


def _unauthorized():
    return ApiError(401, "UNAUTHORIZED", "Missing or invalid {}.".format(HEADER))


def authenticate(event, required_role):
    raw = get_header(event, HEADER)
    key_id = keys.parse_api_key(raw)
    if key_id is None:
        raise _unauthorized()

    record = store.get_api_key(key_id)
    if record is None or record.get("status") != "ACTIVE":
        raise _unauthorized()
    if not keys.hashes_match(record["key_hash"], raw):
        raise _unauthorized()

    expires_at = record.get("expires_at")
    if expires_at and expires_at < store.now_iso():
        raise _unauthorized()

    if record["role"] != required_role:
        raise ApiError(403, "FORBIDDEN", "This key cannot access this route.")

    if required_role == ROLE_TENANT_ADMIN:
        # A tenant the platform has disabled (banned) loses its admin access
        # too, not only license verification. A tenant that merely suspended
        # itself keeps it: it needs it to resume.
        tenant = store.get_tenant(record.get("tenant_id"))
        if tenant is None or tenant.get("disabled_by_platform"):
            raise ApiError(403, "TENANT_DISABLED", "This tenant is disabled.")

    _touch_last_used(record)
    return Principal(record["role"], record.get("tenant_id"), key_id)


def authenticate_console(event):
    """A person signed in on the website. API Gateway has already verified the ID token's
    signature, issuer and audience before this runs; the claims below arrive in requestContext,
    which a caller cannot forge. The tenant comes only from the custom:tenant_id claim, which the
    portal sets and the user cannot change."""
    claims = (((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {}).get("claims") or {}
    expected_audience = os.environ.get("USER_POOL_CLIENT_ID")
    if claims.get("token_use") != "id" or (expected_audience and claims.get("aud") != expected_audience):
        raise ApiError(401, "UNAUTHORIZED", "Please sign in again.")
    tenant_id = claims.get("custom:tenant_id")
    if not keys.is_valid_tenant_id(tenant_id) or str(claims.get("email_verified")).lower() != "true":
        raise ApiError(403, "NO_TENANT", "Your account is not ready yet. Please sign in again.")
    tenant = store.get_tenant(tenant_id)
    if tenant is None or tenant.get("disabled_by_platform"):
        raise ApiError(403, "TENANT_DISABLED", "This tenant is disabled.")
    return Principal(ROLE_TENANT_ADMIN, tenant_id, "user:" + str(claims.get("sub", ""))[:8])


def _touch_last_used(record):
    last = record.get("last_used_at")
    if last:
        try:
            age = datetime.now(timezone.utc) - datetime.strptime(
                last, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            if age < LAST_USED_REFRESH:
                return
        except ValueError:
            pass
    try:
        store.update_api_key(record["key_id"], {"last_used_at": store.now_iso()})
    except Exception:
        logger.warning("could not update last_used_at", exc_info=True)


def actor_label(principal):
    return "{}:{}".format(principal.role, principal.key_id)
