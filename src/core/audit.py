"""Audit trail. PLATFORM is the partition for events that are not tenant scoped."""
import secrets

from core import store

PLATFORM = "PLATFORM"


def record(partition, principal, event_type, details=None):
    """Write one audit event. principal is an auth.Principal."""
    now = store.now_iso()
    store.put_audit(
        partition,
        "{}#{}".format(now, secrets.token_hex(4)),
        {
            "timestamp": now,
            "event_type": event_type,
            "actor_role": principal.role,
            "actor_key_id": principal.key_id,
            "details": details or {},
        },
    )


def public_view(item):
    """What a tenant admin sees. Platform actors are shown as 'platform'
    without their key id."""
    actor = "platform" if item.get("actor_role") == "super_admin" else item.get("actor_key_id")
    return {
        "timestamp": item["timestamp"],
        "event_type": item["event_type"],
        "actor": actor,
        "details": item.get("details", {}),
    }
