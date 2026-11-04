"""Create the first super_admin API key. Run once per stage/region with AWS
credentials that can write to the mcp_api_key table.

    python scripts/bootstrap_super_key.py --region us-west-2 --label "owner"

The key is printed once. Only its hash is stored.
"""
import argparse
import os
import sys
from datetime import datetime, timezone

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from core import keys  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--region", required=True)
    parser.add_argument("--table", default="mcp_api_key")
    parser.add_argument("--label", default="super admin")
    args = parser.parse_args()

    key_id, full_key, key_hash = keys.generate_api_key()
    table = boto3.resource("dynamodb", region_name=args.region).Table(args.table)
    table.put_item(
        Item={
            "key_id": key_id,
            "key_hash": key_hash,
            "role": "super_admin",
            "status": "ACTIVE",
            "label": args.label,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        ConditionExpression="attribute_not_exists(key_id)",
    )
    print("super_admin key created. Store it now; it cannot be shown again:")
    print(full_key)


if __name__ == "__main__":
    main()
