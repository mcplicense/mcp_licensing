"""DynamoDB access. Every function takes the tenant explicitly: all tenant
data lives under a tenant_id partition key, so there is no way to read another
tenant's rows without naming that tenant."""
import base64
import json
import logging
import random
import time
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from core import config
from core.http import ApiError

logger = logging.getLogger(__name__)

_resource = {"obj": None}
_tables = {}


def reset():
    _resource["obj"] = None
    _tables.clear()


def _table(env_var):
    if env_var not in _tables:
        if _resource["obj"] is None:
            _resource["obj"] = boto3.resource("dynamodb")
        _tables[env_var] = _resource["obj"].Table(config.table_name(env_var))
    return _tables[env_var]


def _client():
    if _resource["obj"] is None:
        _resource["obj"] = boto3.resource("dynamodb")
    return _resource["obj"].meta.client


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_epoch():
    """Seconds since the epoch. Seat leases are compared in epoch seconds."""
    return int(time.time())


TRANSACT_ATTEMPTS = 6
_RETRYABLE = {"TransactionConflict", "ThrottlingError", "ProvisionedThroughputExceeded"}
_RETRYABLE_EXC = {"TransactionConflictException", "TransactionInProgressException"}


def _transact(items):
    """Run a TransactWriteItems call.

    Returns None on success, or the per-item cancellation codes (for example
    ["ConditionalCheckFailed", "None"]) when a condition failed. Contention
    with another transaction on the same item is retried with jitter; if it
    never clears, raise 503 so the caller can retry later (clients treat a
    5xx like a network failure and keep running on their offline grace)."""
    for attempt in range(TRANSACT_ATTEMPTS):
        try:
            _client().transact_write_items(TransactItems=items)
            return None
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "TransactionCanceledException":
                codes = [r.get("Code") for r in exc.response.get("CancellationReasons", [])]
                if not any(c in _RETRYABLE for c in codes):
                    return codes
            elif code not in _RETRYABLE_EXC:
                raise
        time.sleep(random.uniform(0.01, 0.05) * (attempt + 1))
    raise ApiError(503, "BUSY", "Please retry shortly.")


def encode_token(last_key):
    if not last_key:
        return None
    return base64.urlsafe_b64encode(json.dumps(last_key).encode()).decode()


def decode_token(token):
    if not token:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(token.encode()).decode())
    except Exception:
        raise ApiError(400, "BAD_REQUEST", "Invalid next_token.")


def _is_condition_failure(exc):
    return exc.response["Error"]["Code"] == "ConditionalCheckFailedException"


def _update(table, key, updates, condition=None, values=None, names=None):
    """SET the given attributes; a value of None REMOVEs the attribute. Fails
    with ConditionalCheckFailed when the item does not exist (unless a
    different condition is given)."""
    expr_names = dict(names or {})
    expr_values = dict(values or {})
    sets, removes = [], []
    for i, (attr, value) in enumerate(updates.items()):
        expr_names["#u{}".format(i)] = attr
        if value is None:
            removes.append("#u{}".format(i))
            continue
        expr_values[":u{}".format(i)] = value
        sets.append("#u{} = :u{}".format(i, i))
    expression = ""
    if sets:
        expression += "SET " + ", ".join(sets)
    if removes:
        expression += " REMOVE " + ", ".join(removes)
    kwargs = {
        "Key": key,
        "UpdateExpression": expression.strip(),
        "ExpressionAttributeNames": expr_names,
        "ReturnValues": "ALL_NEW",
    }
    if expr_values:
        kwargs["ExpressionAttributeValues"] = expr_values
    kwargs["ConditionExpression"] = condition or "attribute_exists({})".format(
        next(iter(key))
    )
    return table.update_item(**kwargs)["Attributes"]


# ------------------------------------------------------------------ tenants

def get_tenant(tenant_id):
    return _table("TENANT_TABLE").get_item(Key={"tenant_id": tenant_id}).get("Item")


def create_tenant(item):
    try:
        _table("TENANT_TABLE").put_item(
            Item=item, ConditionExpression="attribute_not_exists(tenant_id)"
        )
    except ClientError as exc:
        if _is_condition_failure(exc):
            raise ApiError(409, "TENANT_EXISTS", "Tenant already exists.")
        raise


def update_tenant(tenant_id, updates):
    try:
        return _update(_table("TENANT_TABLE"), {"tenant_id": tenant_id}, updates)
    except ClientError as exc:
        if _is_condition_failure(exc):
            raise ApiError(404, "TENANT_NOT_FOUND", "Tenant not found.")
        raise


def scan_tenants(limit, start_key):
    kwargs = {"Limit": limit}
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key
    resp = _table("TENANT_TABLE").scan(**kwargs)
    return resp["Items"], resp.get("LastEvaluatedKey")


# ----------------------------------------------------------------- licenses

def create_license(item):
    _table("LICENSE_TABLE").put_item(
        Item=item, ConditionExpression="attribute_not_exists(license_id)"
    )


def get_license(tenant_id, license_id, consistent=False):
    return (
        _table("LICENSE_TABLE")
        .get_item(Key={"tenant_id": tenant_id, "license_id": license_id},
                  ConsistentRead=consistent)
        .get("Item")
    )


def find_license_by_key_hash(tenant_id, key_hash):
    resp = _table("LICENSE_TABLE").query(
        IndexName="key_hash_index",
        KeyConditionExpression=Key("tenant_id").eq(tenant_id) & Key("key_hash").eq(key_hash),
        Limit=1,
    )
    items = resp["Items"]
    return items[0] if items else None


def license_quota_rows(tenant_id):
    """Every license of the tenant with only the fields the limits need."""
    items = []
    kwargs = {
        "KeyConditionExpression": Key("tenant_id").eq(tenant_id),
        "ProjectionExpression": "license_id, seats_max, #st",
        "ExpressionAttributeNames": {"#st": "status"},
        "ConsistentRead": True,
    }
    table = _table("LICENSE_TABLE")
    while True:
        resp = table.query(**kwargs)
        items.extend(resp["Items"])
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def list_licenses(tenant_id, limit, start_key):
    kwargs = {"KeyConditionExpression": Key("tenant_id").eq(tenant_id), "Limit": limit}
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key
    resp = _table("LICENSE_TABLE").query(**kwargs)
    return resp["Items"], resp.get("LastEvaluatedKey")


def update_license(tenant_id, license_id, updates):
    try:
        return _update(
            _table("LICENSE_TABLE"),
            {"tenant_id": tenant_id, "license_id": license_id},
            updates,
        )
    except ClientError as exc:
        if _is_condition_failure(exc):
            raise ApiError(404, "LICENSE_NOT_FOUND", "License not found.")
        raise


# -------------------------------------------------------------------- seats

def seat_id(license_id, device_id):
    return "{}#{}".format(license_id, device_id)


def get_seat(tenant_id, license_id, device_id):
    return (
        _table("SEAT_TABLE")
        .get_item(Key={"tenant_id": tenant_id, "seat_id": seat_id(license_id, device_id)})
        .get("Item")
    )


SEAT_CREATED = "CREATED"
SEAT_EXISTS = "EXISTS"
SEAT_FULL = "FULL"


def _new_seat_item(tenant_id, license_id, device_id, when, lease_expires_at):
    return {
        "tenant_id": tenant_id,
        "seat_id": seat_id(license_id, device_id),
        "license_id": license_id,
        "device_id": device_id,
        "first_seen_at": when,
        "last_seen_at": when,
        "lease_expires_at": lease_expires_at,  # epoch seconds
    }


def register_seat(tenant_id, license_id, device_id, when, lease_expires_at):
    """Atomically claim a seat for a new device.

    One transaction does both writes or neither: put the seat only if it does
    not exist, and increment seats_used only while seats_used < seats_max. The
    limit is checked by DynamoDB against the stored value at commit time, so
    concurrent callers can never exceed seats_max, and the counter can not
    drift from the seat rows. seats_used counts seat rows, including rows
    whose lease has expired but that nobody has reclaimed yet.

    Returns SEAT_CREATED, SEAT_EXISTS (this device already holds a seat) or
    SEAT_FULL."""
    codes = _transact([
        {"Put": {
            "TableName": config.table_name("SEAT_TABLE"),
            "Item": _new_seat_item(tenant_id, license_id, device_id, when, lease_expires_at),
            "ConditionExpression": "attribute_not_exists(seat_id)",
        }},
        {"Update": {
            "TableName": config.table_name("LICENSE_TABLE"),
            "Key": {"tenant_id": tenant_id, "license_id": license_id},
            "UpdateExpression": "ADD seats_used :one",
            "ConditionExpression": "attribute_exists(license_id) AND seats_used < seats_max",
            "ExpressionAttributeValues": {":one": 1},
        }},
    ])
    if codes is None:
        return SEAT_CREATED
    if codes[0] == "ConditionalCheckFailed":
        return SEAT_EXISTS  # wins over FULL: the device already has its seat
    if codes[1] == "ConditionalCheckFailed":
        return SEAT_FULL
    raise ApiError(500, "INTERNAL_ERROR", "Internal error.")


def renew_seat(tenant_id, license_id, device_id, when, lease_expires_at):
    """Extend the lease of a seat the device already holds. Returns False when
    the seat no longer exists (released or reclaimed in the meantime), so a
    deleted seat is never resurrected without its counter."""
    try:
        _table("SEAT_TABLE").update_item(
            Key={"tenant_id": tenant_id, "seat_id": seat_id(license_id, device_id)},
            UpdateExpression="SET last_seen_at = :t, lease_expires_at = :l",
            ConditionExpression="attribute_exists(seat_id)",
            ExpressionAttributeValues={":t": when, ":l": lease_expires_at},
        )
        return True
    except ClientError as exc:
        if _is_condition_failure(exc):
            return False
        raise


def find_expired_seats(tenant_id, license_id, now_epoch_value):
    """Seats of this license whose lease has run out, oldest lease first."""
    kwargs = {
        "KeyConditionExpression": Key("tenant_id").eq(tenant_id)
        & Key("seat_id").begins_with(license_id + "#"),
        "FilterExpression": "lease_expires_at < :now",
        "ExpressionAttributeValues": {":now": now_epoch_value},
        "ConsistentRead": True,
    }
    items = []
    table = _table("SEAT_TABLE")
    while True:
        resp = table.query(**kwargs)
        items.extend(resp["Items"])
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return sorted(items, key=lambda s: int(s["lease_expires_at"]))


def reclaim_seat(tenant_id, license_id, expired_seat, device_id, when, lease_expires_at,
                 now_epoch_value):
    """Give an expired seat to a new device in one transaction.

    The old seat is deleted only if its lease is still the expired value we
    read (so a device that renewed in the meantime keeps it), and the new seat
    is put only if the device has none. seats_used is unchanged: one row out,
    one row in. Returns SEAT_CREATED, SEAT_EXISTS, or None when someone else
    got the expired seat first."""
    codes = _transact([
        {"Delete": {
            "TableName": config.table_name("SEAT_TABLE"),
            "Key": {"tenant_id": tenant_id, "seat_id": expired_seat["seat_id"]},
            "ConditionExpression": "lease_expires_at = :seen AND lease_expires_at < :now",
            "ExpressionAttributeValues": {
                ":seen": expired_seat["lease_expires_at"], ":now": now_epoch_value},
        }},
        {"Put": {
            "TableName": config.table_name("SEAT_TABLE"),
            "Item": _new_seat_item(tenant_id, license_id, device_id, when, lease_expires_at),
            "ConditionExpression": "attribute_not_exists(seat_id)",
        }},
    ])
    if codes is None:
        return SEAT_CREATED
    if codes[1] == "ConditionalCheckFailed":
        return SEAT_EXISTS
    if codes[0] == "ConditionalCheckFailed":
        return None
    raise ApiError(500, "INTERNAL_ERROR", "Internal error.")


def list_seats(tenant_id, license_id):
    items = []
    kwargs = {
        "KeyConditionExpression": Key("tenant_id").eq(tenant_id)
        & Key("seat_id").begins_with(license_id + "#")
    }
    table = _table("SEAT_TABLE")
    while True:
        resp = table.query(**kwargs)
        items.extend(resp["Items"])
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def release_seat(tenant_id, license_id, device_id):
    """Atomically delete a seat and decrement seats_used. Returns True when a
    seat was removed, False when the device held none."""
    seat_key = {"tenant_id": tenant_id, "seat_id": seat_id(license_id, device_id)}
    codes = _transact([
        {"Delete": {
            "TableName": config.table_name("SEAT_TABLE"),
            "Key": seat_key,
            "ConditionExpression": "attribute_exists(seat_id)",
        }},
        {"Update": {
            "TableName": config.table_name("LICENSE_TABLE"),
            "Key": {"tenant_id": tenant_id, "license_id": license_id},
            "UpdateExpression": "ADD seats_used :minus_one",
            "ConditionExpression": "seats_used > :zero",
            "ExpressionAttributeValues": {":minus_one": -1, ":zero": 0},
        }},
    ])
    if codes is None:
        return True
    if codes[0] == "ConditionalCheckFailed":
        return False
    # Counter already at 0 although the seat exists (not reachable now that
    # both writes are transactional, but never leave a seat undeletable).
    resp = _table("SEAT_TABLE").delete_item(Key=seat_key, ReturnValues="ALL_OLD")
    return "Attributes" in resp


# ------------------------------------------------------------ banned emails

def get_banned(email_hash):
    return _table("BANNED_TABLE").get_item(Key={"email_hash": email_hash}).get("Item")


def put_banned(item):
    _table("BANNED_TABLE").put_item(Item=item)


def delete_banned(email_hash):
    _table("BANNED_TABLE").delete_item(Key={"email_hash": email_hash})


# -------------------------------------------------------------- rate limits

RATE_WINDOW_SEC = 60


def _count_in_window(prefix, limit, window_sec):
    """Count one request in the current fixed window of window_sec seconds.

    Returns (allowed, retry_after_seconds). One conditional UpdateItem both
    checks and increments, so concurrent requests can never push the count
    past the limit; a request refused for being over the limit is not counted.
    Items expire through DynamoDB TTL shortly after their window ends.

    A counter protects the service, it is not a security check, so a DynamoDB
    failure here lets the request through (and is logged) rather than taking
    the endpoint down with it."""
    now = now_epoch()
    window = now // window_sec
    retry_after = (window + 1) * window_sec - now
    try:
        _table("RATE_TABLE").update_item(
            Key={"bucket": "{}#{}".format(prefix, window)},
            UpdateExpression="ADD request_count :one SET expires_at = :expires",
            ConditionExpression="attribute_not_exists(request_count) OR request_count < :limit",
            ExpressionAttributeValues={
                ":one": 1,
                ":limit": limit,
                ":expires": (window + 1) * window_sec + 300,
            },
        )
        return True, 0
    except ClientError as exc:
        if _is_condition_failure(exc):
            return False, retry_after
        logger.exception("rate limit counter failed; allowing the request")
        return True, 0


def take_rate_slot(tenant_id, limit):
    """Count one verify request against the tenant's limit for the current minute."""
    return _count_in_window(tenant_id, limit, RATE_WINDOW_SEC)


def take_window_slot(scope, key, limit, window_sec):
    """Count one request for (scope, key) in the current window, for example a
    daily cap on a whole endpoint. Returns (allowed, retry_after_seconds)."""
    return _count_in_window("window#{}#{}".format(scope, key), limit, window_sec)


def take_attempt(scope, key, max_attempts, lock_sec):
    """Allow max_attempts per visitor, then lock them out for lock_sec seconds.

    The first max_attempts calls pass; the next one starts a lock that lasts
    lock_sec from that moment, and everything during the lock is refused. The
    count restarts once lock_sec has passed since the visitor's last attempt,
    so a person who comes back later starts fresh. Returns (allowed,
    retry_after_seconds); retry_after is how long a refused visitor must wait.

    Every step is a conditional write, so simultaneous requests cannot slip an
    extra attempt through. Like the other counters this fails open."""
    now = now_epoch()
    table = _table("RATE_TABLE")
    attempts_key = {"bucket": "attempts#{}#{}".format(scope, key)}
    lock_key = {"bucket": "lock#{}#{}".format(scope, key)}
    try:
        lock = table.get_item(Key=lock_key, ConsistentRead=True).get("Item")
        if lock and int(lock["locked_until"]) > now:
            return False, int(lock["locked_until"]) - now

        window_end = now + lock_sec
        try:  # an attempt inside the current run
            table.update_item(
                Key=attempts_key,
                UpdateExpression="SET attempts = if_not_exists(attempts, :zero) + :one, expires_at = :end",
                ConditionExpression="attribute_not_exists(attempts) OR (attempts < :max AND expires_at > :now)",
                ExpressionAttributeValues={":zero": 0, ":one": 1, ":max": max_attempts,
                                           ":end": window_end, ":now": now},
            )
            return True, 0
        except ClientError as exc:
            if not _is_condition_failure(exc):
                raise
        try:  # the last run is over: this is the first attempt of a new one
            table.update_item(
                Key=attempts_key,
                UpdateExpression="SET attempts = :one, expires_at = :end",
                ConditionExpression="expires_at <= :now",
                ExpressionAttributeValues={":one": 1, ":end": window_end, ":now": now},
            )
            return True, 0
        except ClientError as exc:
            if not _is_condition_failure(exc):
                raise
        # Over the limit inside the run: lock.
        table.put_item(Item=dict(lock_key, locked_until=now + lock_sec, expires_at=now + lock_sec + 3600))
        return False, lock_sec
    except ClientError:
        logger.exception("attempt limiter failed; allowing the request")
        return True, 0


# ----------------------------------------------------------------- api keys

def put_api_key(item):
    _table("API_KEY_TABLE").put_item(
        Item=item, ConditionExpression="attribute_not_exists(key_id)"
    )


def get_api_key(key_id):
    return _table("API_KEY_TABLE").get_item(Key={"key_id": key_id}).get("Item")


def list_api_keys(tenant_id):
    items = []
    kwargs = {
        "IndexName": "tenant_id_index",
        "KeyConditionExpression": Key("tenant_id").eq(tenant_id),
    }
    table = _table("API_KEY_TABLE")
    while True:
        resp = table.query(**kwargs)
        items.extend(resp["Items"])
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def update_api_key(key_id, updates):
    try:
        return _update(_table("API_KEY_TABLE"), {"key_id": key_id}, updates)
    except ClientError as exc:
        if _is_condition_failure(exc):
            raise ApiError(404, "API_KEY_NOT_FOUND", "API key not found.")
        raise


# -------------------------------------------------------------------- audit

def put_audit(partition, event_id, item):
    record = {"tenant_id": partition, "event_id": event_id}
    record.update(item)
    _table("AUDIT_TABLE").put_item(Item=record)


def list_audit(partition, limit, start_key):
    kwargs = {
        "KeyConditionExpression": Key("tenant_id").eq(partition),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key
    resp = _table("AUDIT_TABLE").query(**kwargs)
    return resp["Items"], resp.get("LastEvaluatedKey")


# ------------------------------------------------------------------ control

def get_control(control_key):
    return _table("CONTROL_TABLE").get_item(Key={"control_key": control_key}).get("Item")


def put_control(item):
    _table("CONTROL_TABLE").put_item(Item=item)
