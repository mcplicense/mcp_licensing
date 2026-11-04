import os
import pathlib
import sys

import boto3
import pytest
import yaml
from moto import mock_aws

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "client"))
sys.path.insert(0, str(ROOT / "tests"))

from core import config, keys, store  # noqa: E402


class _TemplateLoader(yaml.SafeLoader):
    """Reads CloudFormation YAML; intrinsic tags collapse to their plain value."""


def _intrinsic(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return loader.construct_mapping(node, deep=True)


_TemplateLoader.add_multi_constructor("!", _intrinsic)


def load_template(name="template.yml"):
    with open(ROOT / name, "r", encoding="utf-8") as handle:
        return yaml.load(handle, Loader=_TemplateLoader)


def _create_tables_from_template(template):
    """Create the tables exactly as the template declares them, so tests can
    not drift from the infrastructure."""
    client = boto3.client("dynamodb")
    env_to_logical = {}
    env = template["Globals"]["Function"]["Environment"]["Variables"]
    for name, logical in env.items():
        if name.endswith("_TABLE"):
            env_to_logical[name] = logical
    for logical_id, resource in template["Resources"].items():
        if resource["Type"] != "AWS::DynamoDB::Table":
            continue
        props = resource["Properties"]
        kwargs = {
            "TableName": props["TableName"],
            "BillingMode": props["BillingMode"],
            "AttributeDefinitions": props["AttributeDefinitions"],
            "KeySchema": props["KeySchema"],
        }
        if "GlobalSecondaryIndexes" in props:
            kwargs["GlobalSecondaryIndexes"] = props["GlobalSecondaryIndexes"]
        client.create_table(**kwargs)
        for env_name, logical in env_to_logical.items():
            if logical == logical_id:
                os.environ[env_name] = props["TableName"]


@pytest.fixture(autouse=True)
def serialized_dynamodb(monkeypatch):
    """Make each moto DynamoDB request atomic.

    Real DynamoDB executes every request, transactions included, as one
    serializable unit. moto has no locking, so concurrent threads can interleave
    inside a single TransactWriteItems and give false failures. Serialising
    requests models DynamoDB faithfully; separate requests (such as a read
    followed by a transaction) can still interleave, which is what the
    concurrency tests exercise.

    The same goes for boto3 itself: one resource client has ONE condition
    builder whose placeholder counters are reset at the start of every request,
    so two threads building a Key(...) & Key(...) query at once can hand out the
    same placeholder twice and send a query without its partition key (a
    ValidationException, seen in roughly 1 in 40 runs of the 25-thread seat
    test). A Lambda environment handles one request at a time, so production
    never does this; the tests' threads must not either."""
    import threading
    from boto3.dynamodb.transform import TransformationInjector
    from moto.dynamodb.responses import DynamoHandler

    lock = threading.RLock()
    original = DynamoHandler.call_action

    def locked(self, *args, **kwargs):
        with lock:
            return original(self, *args, **kwargs)

    monkeypatch.setattr(DynamoHandler, "call_action", locked)

    build_lock = threading.RLock()
    original_inject = TransformationInjector.inject_condition_expressions

    def locked_inject(self, *args, **kwargs):
        with build_lock:
            return original_inject(self, *args, **kwargs)

    monkeypatch.setattr(TransformationInjector, "inject_condition_expressions", locked_inject)


@pytest.fixture(autouse=True)
def aws(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("SSM_PREFIX", raising=False)
    with mock_aws():
        _create_tables_from_template(load_template())
        store.reset()
        config.reset_cache()
        yield


@pytest.fixture
def super_key():
    key_id, full_key, key_hash = keys.generate_api_key()
    store._table("API_KEY_TABLE").put_item(Item={
        "key_id": key_id, "key_hash": key_hash, "role": "super_admin",
        "status": "ACTIVE", "label": "test", "created_at": store.now_iso(),
    })
    return full_key
