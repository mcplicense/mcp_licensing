"""Put the starter spam phrases into the mcp_spam_phrase table.

    python scripts/seed_spam_phrases.py --region us-east-1                 # the starter rows
    python scripts/seed_spam_phrases.py --region us-east-1 --file mine.json  # rows from a JSON list instead
    python scripts/seed_spam_phrases.py --region us-east-1 --dry-run

A row is {"scope": "contact", "name": "seo", "phrases": "seo, backlink*, ...", "enabled": true, "note": "..."}.
Existing rows (same scope and name) are kept as they are, so running this again never undoes an edit.
Edit the table afterwards in the DynamoDB console, or with scripts/spam_phrases.py.
"""
import argparse
import json
import os
import sys

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from core import spam  # noqa: E402

STARTER_ROWS = [
    {"scope": "contact", "name": "seo", "enabled": True, "note": "SEO and search-ranking pitches",
     "phrases": "seo, search engine*, search ranking*, google ranking*, first page of google, backlink*, "
                "link building, guest post*, website traffic, site traffic, web traffic, organic traffic, "
                "target keyword*"},
    {"scope": "contact", "name": "marketing", "enabled": True, "note": "marketing and lead-generation pitches",
     "phrases": "digital marketing, marketing services, social media marketing, social media management, "
                "lead generation, cold email*, email list*, online presence, online visibility, online performance"},
    {"scope": "contact", "name": "boost", "enabled": True, "note": "'boost / increase your sales' style pitches",
     "phrases": "increase sales, increase your sales, increase traffic, increase your traffic, increase revenue, "
                "increase your revenue, increase conversions, increase your conversions, boost sales, "
                "boost your sales, boost traffic, boost your traffic, boost ranking*, boost your ranking*, "
                "boost your website, boost your business, boost your online, boost online"},
    {"scope": "contact", "name": "development", "enabled": True, "note": "agency and outsourcing offers",
     "phrases": "web design, web development, app development, outsourc*"},
    {"scope": "contact", "name": "scams", "enabled": True, "note": "money, crypto and pharmacy spam",
     "phrases": "bitcoin, cryptocurrency, crypto, casino, forex, viagra, payday loan*, make money, work from home"},
]


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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--table", default="mcp_spam_phrase")
    parser.add_argument("--file", help="a JSON list of rows to use instead of the starter rows")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    rows = STARTER_ROWS
    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            rows = json.load(handle)
    check_rows(rows)
    if args.dry_run:
        for row in rows:
            print("would add {}/{}: {}".format(row["scope"], row["name"], row["phrases"][:70]))
        return
    table = boto3.resource("dynamodb", region_name=args.region).Table(args.table)
    created, kept = seed(table, rows)
    print("created:", ", ".join(created) or "none", "| kept as they were:", ", ".join(kept) or "none")


if __name__ == "__main__":
    main()
