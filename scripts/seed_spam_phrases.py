"""Put the spam phrases in git (scripts/data/spam_phrases.json) into the mcp_spam_phrase table.

    python scripts/seed_spam_phrases.py --region us-east-1                  # create missing rows only
    python scripts/seed_spam_phrases.py --region us-east-1 --merge          # also add missing phrases to existing rows
    python scripts/seed_spam_phrases.py --region us-east-1 --file mine.json # rows from another JSON list
    python scripts/seed_spam_phrases.py --region us-east-1 --dry-run

A row is {"scope": "contact", "name": "seo", "phrases": "seo, backlink*, ...", "enabled": true, "note": "..."}.
Without --merge an existing row (same scope and name) is kept exactly as it is. With --merge its phrases are
extended by the ones in the file that it lacks; nothing is ever removed, and `enabled` and `note` stay as they are,
so running this again never undoes an edit. To record the live table in git after editing it by hand, run
`python scripts/spam_phrases.py export`.
"""
import argparse
import json
import os
import pathlib
import sys

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from core import spam  # noqa: E402

DATA_FILE = pathlib.Path(__file__).resolve().parent / "data" / "spam_phrases.json"


def load_rows(path=DATA_FILE):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


STARTER_ROWS = load_rows()


def check_rows(rows):
    """Raise ValueError unless every row has a scope and name and at least one usable phrase."""
    for row in rows:
        if not row.get("scope") or not row.get("name"):
            raise ValueError("every row needs a scope and a name: {}".format(row))
        good, _ = spam.parse_phrases(row.get("phrases"))
        if not good:
            raise ValueError("row {!r} has no usable phrase".format(row["name"]))


def seed(table, rows):
    """Write the rows that do not exist yet; return (created names, kept names)."""
    check_rows(rows)
    created, kept = [], []
    for row in rows:
        try:
            table.put_item(Item=row, ConditionExpression="attribute_not_exists(#n)",
                           ExpressionAttributeNames={"#n": "name"})
            created.append(row["name"])
        except ClientError as error:
            if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            kept.append(row["name"])
    return created, kept


def merge(table, rows):
    """Create missing rows and add the phrases an existing row lacks. Returns (created names, {name: phrases
    added}). Never removes a phrase and never changes `enabled` or `note` of an existing row."""
    check_rows(rows)
    created, extended = [], {}
    for row in rows:
        key = {"scope": row["scope"], "name": row["name"]}
        existing = table.get_item(Key=key).get("Item")
        if existing is None:
            table.put_item(Item=row)
            created.append(row["name"])
            continue
        have, _ = spam.parse_phrases(existing.get("phrases"))
        wanted, _ = spam.parse_phrases(row.get("phrases"))
        missing = [phrase for phrase in wanted if phrase not in have]
        if missing:
            text = str(existing.get("phrases") or "").rstrip().rstrip(",")
            table.update_item(Key=key, UpdateExpression="SET phrases = :p",
                              ExpressionAttributeValues={":p": (text + ", " if text else "") + ", ".join(missing)})
            extended[row["name"]] = missing
    return created, extended


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--table", default="mcp_spam_phrase")
    parser.add_argument("--file", help="a JSON list of rows to use instead of scripts/data/spam_phrases.json")
    parser.add_argument("--merge", action="store_true", help="also add missing phrases to existing rows")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    rows = load_rows(args.file) if args.file else STARTER_ROWS
    check_rows(rows)
    if args.dry_run:
        for row in rows:
            print("would {} {}/{}: {}".format("merge" if args.merge else "add", row["scope"], row["name"],
                                              row["phrases"][:70]))
        return
    table = boto3.resource("dynamodb", region_name=args.region).Table(args.table)
    if args.merge:
        created, extended = merge(table, rows)
        print("created:", ", ".join(created) or "none")
        for name, phrases in extended.items():
            print("added to {}: {}".format(name, ", ".join(phrases)))
        if not created and not extended:
            print("nothing to add: the table already has every phrase in the file")
    else:
        created, kept = seed(table, rows)
        print("created:", ", ".join(created) or "none", "| kept as they were:", ", ".join(kept) or "none")


if __name__ == "__main__":
    main()
