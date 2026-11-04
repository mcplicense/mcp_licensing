"""Runtime configuration.

Table names come from Lambda environment variables set by the template.
Everything else a person may want to tune lives in SSM Parameter Store
(standard tier, free) under one prefix per stage:

    /mcp/<stage>/<name>                         platform default
    /mcp/<stage>/tenants/<tenant_id>/<name>     override for one tenant

Only the limit_* settings can be overridden per tenant. An override is
looked up first, then the platform value, then the default built in below, so a
missing or unreadable parameter never takes the service down.

Freshness: CONFIG_CACHE_SECONDS says how long a warm container may reuse what
it read. 0 means "read again on every invocation" (still at most once per
invocation, and only when a setting is actually needed): the management
functions use it so a change in SSM applies to the very next request. The
verify function caches for a minute because it can run 100 times a second and
SSM's default limit is about 40 reads a second.
"""
import logging
import os
import re
import time

import boto3

logger = logging.getLogger(__name__)

DEFAULT_CACHE_SECONDS = 60
MAX_TENANTS_CACHED = 500
TENANT_PATH_RE = re.compile(r"^[a-z0-9-]{3,12}$")

DEFAULTS = {
    "default_seats_max": "1",
    "default_license_days": "365",
    "default_lease_duration_sec": "86400",
    "client_cache_ttl_seconds": "300",
    "limit_licenses_per_tenant": "50",
    "limit_seats_per_license": "10",
    "limit_seats_per_tenant": "200",
    "limit_api_keys_per_tenant": "5",
    "limit_verify_per_min": "100",
    "contact_ip_attempts": "3",
    "contact_ip_lock_seconds": "1800",
    "contact_daily_cap": "100",
    "signup_ip_attempts": "3",
    "signup_ip_lock_seconds": "1800",
    "signup_email_per_hour": "3",
    "signup_daily_cap": "200",
    "login_ip_attempts": "20",
    "login_ip_lock_seconds": "900",
    "log_level": "INFO",
}
TENANT_OVERRIDABLE = tuple(name for name in DEFAULTS if name.startswith("limit_"))

_cache = {"values": None, "loaded_at": 0.0}
_tenant_cache = {}


def table_name(env_var):
    return os.environ[env_var]


def cache_seconds():
    try:
        return int(os.environ.get("CONFIG_CACHE_SECONDS", DEFAULT_CACHE_SECONDS))
    except ValueError:
        return DEFAULT_CACHE_SECONDS


def _read_path(path):
    """Direct children of an SSM path as {name: value}. Raises on failure."""
    values = {}
    paginator = boto3.client("ssm").get_paginator("get_parameters_by_path")
    for page in paginator.paginate(Path=path):
        for param in page["Parameters"]:
            values[param["Name"].rsplit("/", 1)[-1]] = param["Value"]
    return values


def _load_platform():
    prefix = os.environ.get("SSM_PREFIX")
    values = dict(DEFAULTS)
    if not prefix:
        return values
    try:
        values.update(_read_path(prefix))
    except Exception:
        # Fall back to defaults rather than fail every request.
        logger.exception("could not read SSM parameters under %s", prefix)
    return values


def _fresh(loaded_at):
    return time.time() - loaded_at <= cache_seconds()


def get_settings():
    if _cache["values"] is None or not _fresh(_cache["loaded_at"]):
        _cache["values"] = _load_platform()
        _cache["loaded_at"] = time.time()
        logging.getLogger().setLevel(_cache["values"]["log_level"].upper())
    return _cache["values"]


def tenant_overrides(tenant_id):
    """The limit_* overrides set for this tenant ({} when there are none)."""
    prefix = os.environ.get("SSM_PREFIX")
    if not prefix or not TENANT_PATH_RE.match(tenant_id or ""):
        return {}
    cached = _tenant_cache.get(tenant_id)
    if cached and _fresh(cached[0]):
        return cached[1]
    try:
        values = {k: v for k, v in _read_path("{}/tenants/{}".format(prefix, tenant_id)).items()
                  if k in TENANT_OVERRIDABLE}
    except Exception:
        logger.exception("could not read overrides for tenant %s", tenant_id)
        values = {}
    if len(_tenant_cache) >= MAX_TENANTS_CACHED:
        _tenant_cache.clear()
    _tenant_cache[tenant_id] = (time.time(), values)
    return values


def get_int(name, tenant_id=None):
    """A setting as an integer; for a limit_* setting pass the tenant to honour
    that tenant's override."""
    if tenant_id and name in TENANT_OVERRIDABLE:
        try:
            return int(tenant_overrides(tenant_id)[name])
        except (KeyError, ValueError):
            pass
    try:
        return int(get_settings()[name])
    except (KeyError, ValueError):
        return int(DEFAULTS[name])


def start_request():
    """Call at the start of every invocation. With CONFIG_CACHE_SECONDS=0 this
    drops what the previous invocation read, so settings are read again."""
    if cache_seconds() <= 0:
        reset_cache()


def reset_cache():
    _cache["values"] = None
    _cache["loaded_at"] = 0.0
    _tenant_cache.clear()
