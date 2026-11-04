"""Emergency stop for the public service: switch the public-facing Lambdas off, and back on.

    python scripts/emergency.py status
    python scripts/emergency.py stop --level signups     # sign-up, login, contact form
    python scripts/emergency.py stop --level console     # ... and the tenant console and admin API
    python scripts/emergency.py stop --level all         # ... and the license check itself
    python scripts/emergency.py resume                   # everything back on

It sets each function's reserved concurrency to 0, which refuses every invocation within seconds and is
undone by removing the setting. Nothing is deleted. The platform function (/v1/super/*) is never stopped, so
you can still ban a tenant or flip the kill switch while the rest is off.

Stopping the license check (`all`) makes clients see a server error, which the client helper treats as "could
not check": tools keep running on their last answer until its lease ends. To refuse every license instead, use
the global kill switch (PUT /v1/super/kill-switch). Use the default AWS profile unless you pass --profile.
"""
import argparse
import sys

import boto3
from botocore.exceptions import ClientError

LEVELS = {
    "signups": ["portal", "contact"],
    "console": ["portal", "contact", "admin"],
    "all": ["portal", "contact", "admin", "mcp"],
}
NEVER_STOPPED = ["super"]
EVERYTHING = LEVELS["all"] + NEVER_STOPPED


def function_name(stage, short):
    return "mcp-licensing-{}-{}".format(stage, short)


def status(client, stage):
    """Return [(short name, state)] where state is 'running', 'STOPPED' or a limit like 'limited to 5'."""
    rows = []
    for short in EVERYTHING:
        try:
            reserved = client.get_function_concurrency(FunctionName=function_name(stage, short)).get(
                "ReservedConcurrentExecutions")
        except ClientError as error:
            rows.append((short, "ERROR " + error.response["Error"]["Code"]))
            continue
        if reserved is None:
            rows.append((short, "running"))
        elif reserved == 0:
            rows.append((short, "STOPPED"))
        else:
            rows.append((short, "limited to {}".format(reserved)))
    return rows


def stop(client, stage, level, dry_run=False):
    return _apply(client, stage, LEVELS[level], "stop", dry_run)


def resume(client, stage, dry_run=False):
    return _apply(client, stage, EVERYTHING, "resume", dry_run)


def _apply(client, stage, shorts, action, dry_run):
    """Return [(short name, result)]; a result starting with 'ERROR' means that function was not changed."""
    rows = []
    for short in shorts:
        name = function_name(stage, short)
        if dry_run:
            rows.append((short, "would " + action))
            continue
        try:
            if action == "stop":
                client.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=0)
                rows.append((short, "stopped"))
            else:
                client.delete_function_concurrency(FunctionName=name)
                rows.append((short, "running"))
        except ClientError as error:
            rows.append((short, "ERROR " + error.response["Error"]["Code"]))
    return rows


def main(argv=None, client=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("action", choices=["status", "stop", "resume"])
    parser.add_argument("--level", choices=sorted(LEVELS), help="what to stop (required for stop)")
    parser.add_argument("--stage", default="prod")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--profile", default=None, help="AWS profile (default: the default profile)")
    parser.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    args = parser.parse_args(argv)
    if args.action == "stop" and not args.level:
        parser.error("stop needs --level signups, console or all")

    client = client or boto3.Session(profile_name=args.profile, region_name=args.region).client("lambda")
    if args.action == "status":
        rows = status(client, args.stage)
    elif args.action == "stop":
        rows = stop(client, args.stage, args.level, args.dry_run)
    else:
        rows = resume(client, args.stage, args.dry_run)

    for short, state in rows:
        print("{:<9}{}".format(short, state))
    failed = [short for short, state in rows if state.startswith("ERROR")]
    if args.action == "stop" and not args.dry_run and not failed:
        print("\nStopped. The platform function stays up so you can still ban tenants or use the kill switch."
              "\nTo bring everything back: python scripts/emergency.py resume")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
