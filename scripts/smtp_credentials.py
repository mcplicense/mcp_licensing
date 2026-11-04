"""Create the SMTP credentials that let your inbox "Send mail as" support@<domain>.

    python scripts/smtp_credentials.py --domain mcplicense.net --region us-east-1
    python scripts/smtp_credentials.py --domain mcplicense.net --region us-east-1 --check

Without --check it creates (or reuses) the IAM user mcp-licensing-smtp, whose only
permission is to send mail from support@<domain>, makes an access key for it and
prints the SMTP host, port, user name and password ONCE. Nothing is written to
disk. Put them in your mail client's "Send mail as" settings (in Gmail: Settings,
Accounts, "Send mail as", "Add another email address", then SMTP server
email-smtp.<region>.amazonaws.com, port 587, TLS). Replies then come from
support@<domain> and never show your own address.

With --check it only tests, without sending anything, that SES accepts a login
with the credentials you give it (--user and the password read from the
SMTP_PASSWORD environment variable).

An IAM user holds at most two access keys. To rotate: run this again (a second
key), switch your mail client to it, then delete the old key in the IAM console.
"""
import argparse
import base64
import hashlib
import hmac
import os
import smtplib
import sys

import boto3
from botocore.exceptions import ClientError

USER_NAME = "mcp-licensing-smtp"
# The constants of the SES SMTP password derivation (version 4 of the algorithm).
_DATE, _SERVICE, _MESSAGE, _TERMINAL, _VERSION = "11111111", "ses", "SendRawEmail", "aws4_request", 0x04


def _sign(key, message):
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def smtp_password(secret_access_key, region):
    """The SMTP password SES derives from an IAM secret access key and a region."""
    signature = _sign(("AWS4" + secret_access_key).encode("utf-8"), _DATE)
    for part in (region, _SERVICE, _TERMINAL, _MESSAGE):
        signature = _sign(signature, part)
    return base64.b64encode(bytes([_VERSION]) + signature).decode("utf-8")


def policy_document(domain, region, account_id):
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "ses:SendRawEmail",
            "Resource": "arn:aws:ses:{}:{}:identity/{}".format(region, account_id, domain),
            "Condition": {"StringEquals": {"ses:FromAddress": "support@" + domain}},
        }],
    }


def create(domain, region):
    import json
    iam = boto3.client("iam")
    account_id = boto3.client("sts").get_caller_identity()["Account"]
    try:
        iam.create_user(UserName=USER_NAME)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
    iam.put_user_policy(UserName=USER_NAME, PolicyName="send-as-support",
                        PolicyDocument=json.dumps(policy_document(domain, region, account_id)))
    key = iam.create_access_key(UserName=USER_NAME)["AccessKey"]
    return key["AccessKeyId"], smtp_password(key["SecretAccessKey"], region)


def check(region, user, password):
    host = "email-smtp.{}.amazonaws.com".format(region)
    with smtplib.SMTP(host, 587, timeout=20) as server:
        server.starttls()
        server.login(user, password)  # raises SMTPAuthenticationError when SES refuses the login
    return host


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--domain", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--check", action="store_true", help="test a login instead of creating credentials")
    parser.add_argument("--user", help="with --check: the SMTP user name")
    args = parser.parse_args()

    if args.check:
        password = os.environ.get("SMTP_PASSWORD")
        if not args.user or not password:
            parser.error("--check needs --user and the SMTP_PASSWORD environment variable")
        print("login accepted by", check(args.region, args.user, password))
        return

    user, password = create(args.domain, args.region)
    print("Send mail as support@{}:".format(args.domain))
    print("  SMTP server:  email-smtp.{}.amazonaws.com".format(args.region))
    print("  Port:         587 (TLS)")
    print("  Username:     " + user)
    print("  Password:     " + password)
    print("Shown once; it is not stored anywhere. Delete old keys of {} in IAM after switching.".format(USER_NAME))


if __name__ == "__main__":
    sys.exit(main())
