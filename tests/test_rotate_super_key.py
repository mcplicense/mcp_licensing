"""scripts/rotate_super_key.py: old super keys die at once, the new one works, tenant keys are untouched."""
import importlib.util
import pathlib

from core import keys, store
from helpers import call, create_tenant

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_script():
    spec = importlib.util.spec_from_file_location("rotate_super_key", ROOT / "scripts" / "rotate_super_key.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def add_super_key(label):
    key_id, full_key, key_hash = keys.generate_api_key()
    store._table("API_KEY_TABLE").put_item(Item={
        "key_id": key_id, "key_hash": key_hash, "role": "super_admin", "status": "ACTIVE", "label": label,
        "created_at": store.now_iso()})
    return full_key


def test_every_old_super_key_is_refused_and_the_new_one_works(super_key):
    second = add_super_key("second")
    assert call("GET /v1/super/kill-switch", key=super_key)[0] == 200
    new_key, revoked = load_script().rotate(store._table("API_KEY_TABLE"))
    assert len(revoked) == 2
    assert call("GET /v1/super/kill-switch", key=super_key)[0] == 401
    assert call("GET /v1/super/kill-switch", key=second)[0] == 401
    assert call("GET /v1/super/kill-switch", key=new_key)[0] == 200


def test_tenant_admin_keys_are_not_touched(super_key):
    tenant = create_tenant(super_key)
    status, data = call("POST /v1/super/tenants/{tenant_id}/api-keys", {"label": "t"}, key=super_key,
                        params={"tenant_id": tenant["tenant_id"]})
    assert status == 201, data
    admin_key = data["api_key"]
    load_script().rotate(store._table("API_KEY_TABLE"))
    assert call("GET /v1/admin/tenant", key=admin_key)[0] == 200


def test_rotating_twice_leaves_exactly_one_active_super_key(super_key):
    module = load_script()
    table = store._table("API_KEY_TABLE")
    module.rotate(table)
    module.rotate(table)
    active = [i for i in table.scan()["Items"] if i["role"] == "super_admin" and i["status"] == "ACTIVE"]
    assert len(active) == 1


def test_a_revoked_key_records_when_it_was_revoked(super_key):
    module = load_script()
    table = store._table("API_KEY_TABLE")
    _, revoked = module.rotate(table)
    row = table.get_item(Key={"key_id": revoked[0]})["Item"]
    assert row["status"] == "REVOKED" and row["revoked_at"].endswith("Z")
