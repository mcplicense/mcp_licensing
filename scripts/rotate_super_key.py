"""Revoke every active super_admin key and create a new one. Use it when a super key may have leaked, or was lost.

    python scripts/rotate_super_key.py --region us-east-1

The new key is printed once; only its hash is stored. The old keys stop working at once (a revoked key is
refused on its next request). Use the AWS credentials that can write to the mcp_api_key table.
"""
import argparse
import os
import sys
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Attr

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from core import keys  # noqa: E402


def rotate(table, label="super admin"):
    """Revoke the active super_admin keys, create one and return (new key, [revoked key ids])."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    revoked = []
    scan = {"FilterExpression": Attr("role").eq("super_admin") & Attr("status").eq("ACTIVE")}
    while True:
        page = table.scan(**scan)
        for item in page["Items"]:
            table.update_item(
                Key={"key_id": item["key_id"]},
                UpdateExpression="SET #s = :revoked, revoked_at = :now",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":revoked": "REVOKED", ":now": now},
            )
            revoked.append(item["key_id"])
        if "LastEvaluatedKey" not in page:
            break
        scan["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    key_id, full_key, key_hash = keys.generate_api_key()
    table.put_item(
        Item={"key_id": key_id, "key_hash": key_hash, "role": "super_admin", "status": "ACTIVE", "label": label,
              "created_at": now},
        ConditionExpression="attribute_not_exists(key_id)",
    )
    return full_key, revoked


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--region", required=True)
    parser.add_argument("--table", default="mcp_api_key")
    parser.add_argument("--label", default="super admin")
    args = parser.parse_args(argv)
    table = boto3.resource("dynamodb", region_name=args.region).Table(args.table)
    full_key, revoked = rotate(table, args.label)
    print("revoked {} super_admin key(s): {}".format(len(revoked), ", ".join(revoked) or "none"))
    print("new super_admin key. Store it now; it cannot be shown again:")
    print(full_key)


if __name__ == "__main__":
    main()
