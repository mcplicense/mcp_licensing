"""Create the SSM settings under /mcp/<stage>/ that do not exist yet.

    python scripts/seed_config.py --stage prod --region us-east-1
    python scripts/seed_config.py --stage prod --region us-east-1 --tenant sfs limit_seats_per_license=100

The first form creates every platform setting that is missing, using the
values built into src/core/config.py, and NEVER overwrites one that exists, so
it is safe to run again after a release adds a setting. The second form sets
limit_* overrides for one tenant (this one does overwrite: it is you saying
what you want).

Change a value afterwards with the console or the CLI:

    aws ssm put-parameter --name /mcp/prod/limit_seats_per_license --value 20 \\
        --type String --overwrite

The Lambdas pick the change up on their next request (management functions) or
within a minute (verify).
"""
import argparse
import os
import sys

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from core import config, keys  # noqa: E402

DESCRIPTIONS = {
    "default_seats_max": "Seats granted to a new license when none is requested.",
    "default_license_days": "Validity of a new license when no expires_at is requested.",
    "default_lease_duration_sec": "Seat lease length in seconds (86400 = 24h). Tenants and licenses may override it.",
    "client_cache_ttl_seconds": "How long a client may reuse a successful verify result.",
    "limit_licenses_per_tenant": "Active licenses one tenant may have. Overridable per tenant.",
    "limit_seats_per_license": "Seats one license may have. Overridable per tenant.",
    "limit_seats_per_tenant": "Seats across all of a tenant's active licenses. Overridable per tenant.",
    "limit_api_keys_per_tenant": "Active admin API keys one tenant may have. Overridable per tenant.",
    "limit_verify_per_min": "Verify requests per tenant per minute; over it answers 429. Overridable per tenant.",
    "contact_ip_attempts": "Contact form messages one visitor (IPv4 address or IPv6 /64) may send before being locked out.",
    "contact_ip_lock_seconds": "How long a visitor who used up their contact form attempts is locked out (1800 = 30 minutes).",
    "contact_daily_cap": "Contact form messages accepted per day in total, whoever sends them.",
    "signup_ip_attempts": "Sign-up, resend and password-reset requests one visitor may make before being locked out.",
    "signup_ip_lock_seconds": "How long that lock lasts (1800 = 30 minutes).",
    "signup_email_per_hour": "Emails (codes) sent to one address per hour by sign-up, resend and password reset.",
    "signup_daily_cap": "Sign-up requests accepted per day in total, whoever makes them.",
    "login_ip_attempts": "Login attempts one visitor may make before being locked out.",
    "login_ip_lock_seconds": "How long a login lock lasts (900 = 15 minutes).",
    "log_level": "Lambda log level: DEBUG, INFO, WARNING or ERROR.",
}


def put(ssm, name, value, description, overwrite):
    try:
        ssm.put_parameter(Name=name, Value=str(value), Type="String", Description=description,
                          Overwrite=overwrite)
        return "set" if overwrite else "created"
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ParameterAlreadyExists":
            return "kept"
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stage", required=True, choices=["dev", "prod"])
    parser.add_argument("--region", required=True)
    parser.add_argument("--tenant", help="set limit_* overrides for this tenant instead")
    parser.add_argument("overrides", nargs="*", help="name=value, with --tenant")
    args = parser.parse_args()

    ssm = boto3.client("ssm", region_name=args.region)
    prefix = "/mcp/" + args.stage

    if args.tenant:
        if not keys.is_valid_tenant_id(args.tenant):
            parser.error("not a valid tenant id: " + args.tenant)
        if not args.overrides:
            parser.error("give at least one name=value")
        for item in args.overrides:
            name, _, value = item.partition("=")
            if name not in config.TENANT_OVERRIDABLE or not value.strip().lstrip("-").isdigit():
                parser.error("{!r}: name must be one of {} and the value a whole number".format(
                    item, ", ".join(config.TENANT_OVERRIDABLE)))
            path = "{}/tenants/{}/{}".format(prefix, args.tenant, name)
            print("{:8} {} = {}".format(put(ssm, path, value.strip(), DESCRIPTIONS[name], True), path, value))
        return

    for name, value in config.DEFAULTS.items():
        path = "{}/{}".format(prefix, name)
        print("{:8} {} = {}".format(put(ssm, path, value, DESCRIPTIONS[name], False), path, value))


if __name__ == "__main__":
    main()
