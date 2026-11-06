"""Edit and try the contact form's spam phrases (the mcp_spam_phrase table).

    python scripts/spam_phrases.py list
    python scripts/spam_phrases.py add "seo audit" "free quote"          # into the row named "custom"
    python scripts/spam_phrases.py add "domain renewal" --group scams    # into another row
    python scripts/spam_phrases.py remove "free quote"
    python scripts/spam_phrases.py test "Hello, we offer SEO audits for your site"
    python scripts/spam_phrases.py export        # write the live table to scripts/data/spam_phrases.json (commit it)

Phrases are plain text, matched whole-word and case-insensitively; a trailing * matches word endings
("outsourc*"). `add` refuses a phrase that would block one of the legitimate messages in
scripts/legit_messages.txt (use --force only if you are sure). You can also edit the table by hand in the
DynamoDB console: one row per group, `phrases` separated by commas or lines, `enabled` false to switch a row off.
Uses the default AWS profile.
"""
import argparse
import json
import os
import pathlib
import sys

import boto3
from boto3.dynamodb.conditions import Key

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from core import spam  # noqa: E402

SCOPE = "contact"
CORPUS = pathlib.Path(__file__).resolve().parent / "legit_messages.txt"
DATA_FILE = pathlib.Path(__file__).resolve().parent / "data" / "spam_phrases.json"


def legit_messages():
    return [line.strip() for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]


def rows(table):
    page = table.query(KeyConditionExpression=Key("scope").eq(SCOPE))
    return sorted(page["Items"], key=lambda row: row["name"])


def blocked_by(phrase):
    """The legitimate messages this phrase would drop."""
    return [message for message in legit_messages() if spam.reason("", message, [phrase]) not in (None, "link")]


def add(table, phrases, group="custom", force=False):
    """Add phrases to the row `group`; returns the phrases added. Raises ValueError for a bad or risky phrase."""
    clean = []
    for raw in phrases:
        phrase, problem = spam.check_phrase(raw)
        if not phrase:
            raise ValueError("{!r}: {}".format(raw, problem))
        hit = blocked_by(phrase)
        if hit and not force:
            raise ValueError("{!r} would block a legitimate message ({!r}...). Use a more specific phrase, "
                             "or --force.".format(raw, hit[0][:50]))
        clean.append(phrase)
    existing = table.get_item(Key={"scope": SCOPE, "name": group}).get("Item") or {
        "scope": SCOPE, "name": group, "enabled": True, "note": "added with scripts/spam_phrases.py", "phrases": ""}
    current, _ = spam.parse_phrases(existing.get("phrases"))
    merged = current + [phrase for phrase in clean if phrase not in current]
    existing["phrases"] = ", ".join(merged)
    existing["enabled"] = True
    table.put_item(Item=existing)
    return [phrase for phrase in clean if phrase not in current]


def remove(table, phrase):
    """Remove a phrase from every row that has it; returns the names of the rows changed."""
    target, _ = spam.check_phrase(phrase)
    changed = []
    for row in rows(table):
        current, _ = spam.parse_phrases(row.get("phrases"))
        kept = [p for p in current if p != target]
        if len(kept) == len(current):
            continue
        if kept:
            table.update_item(Key={"scope": SCOPE, "name": row["name"]}, UpdateExpression="SET phrases = :p",
                              ExpressionAttributeValues={":p": ", ".join(kept)})
        else:
            table.delete_item(Key={"scope": SCOPE, "name": row["name"]})
        changed.append(row["name"])
    return changed


def export(table):
    """The rows of the table as plain dicts, in the order and shape of scripts/data/spam_phrases.json."""
    out = []
    for row in rows(table):
        phrases = row.get("phrases")
        if isinstance(phrases, (set, frozenset, list, tuple)):
            phrases = ", ".join(sorted(str(p) for p in phrases))
        item = {"scope": row["scope"], "name": row["name"], "enabled": row.get("enabled") is not False}
        if row.get("note"):
            item["note"] = str(row["note"])
        item["phrases"] = str(phrases or "")
        out.append(item)
    return out


def verdict(table, message):
    phrases, _ = spam.phrases_from_rows(rows(table))
    return spam.reason("", message, phrases or None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--table", default="mcp_spam_phrase")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    add_parser = commands.add_parser("add")
    add_parser.add_argument("phrases", nargs="+")
    add_parser.add_argument("--group", default="custom")
    add_parser.add_argument("--force", action="store_true")
    commands.add_parser("remove").add_argument("phrase")
    commands.add_parser("test").add_argument("message")
    export_parser = commands.add_parser("export")
    export_parser.add_argument("--file", default=str(DATA_FILE),
                               help="where to write the rows (default: scripts/data/spam_phrases.json)")
    args = parser.parse_args(argv)

    table = boto3.resource("dynamodb", region_name=args.region).Table(args.table)
    if args.command == "list":
        found = rows(table)
        usable, skipped = spam.phrases_from_rows(found)
        for row in found:
            state = "on " if row.get("enabled") is not False else "OFF"
            print("[{}] {:<14} {}".format(state, row["name"], row.get("phrases")))
        print("{} rows, {} usable phrases, {} entries skipped".format(len(found), len(usable), skipped))
    elif args.command == "add":
        try:
            added = add(table, args.phrases, args.group, args.force)
        except ValueError as error:
            sys.exit("not added: {}".format(error))
        print("added to {}: {}".format(args.group, ", ".join(added) or "nothing new"))
    elif args.command == "remove":
        changed = remove(table, args.phrase)
        print("removed from: {}".format(", ".join(changed) if changed else "no row (not found)"))
    elif args.command == "export":
        found = export(table)
        with open(args.file, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(found, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        print("wrote {} rows to {}; commit it to keep git in step with the table".format(len(found), args.file))
    else:
        why = verdict(table, args.message)
        print("SPAM ({})".format(why) if why else "looks like a person: delivered")


if __name__ == "__main__":
    main()
