"""Forward mail that SES receives for the domain to one inbox.

An SES receipt rule first saves the raw message in S3, then invokes this
function with the receipt details. The function reads the message back, rewrites
the headers so SES will send it, and sends it on:

  * From becomes "<original sender> via MCP Licensing" <support@domain>, because
    SES only sends as an address of a verified identity. The domain's DKIM then
    signs it, so Gmail sees mail that is properly authenticated.
  * Reply-To is the original sender, so replying (or "Reply" in Gmail) goes to
    them. Everything else, including attachments, is kept as it was.
  * The original DKIM signature and Return-Path no longer apply and are dropped.
  * A message that fails SES's virus scan is dropped; one that fails the spam
    scan is forwarded with "[Spam?]" in front of the subject.
  * A message already forwarded by this function is never forwarded again, so
    two forwarders pointing at each other cannot loop.
  * A message too large for SES to send is replaced by a short notice that says
    where the original is kept.

Nothing here is specific to a person: the destination is the FORWARD_TO
environment variable, set at deploy time.
"""
import email
import email.message
import email.policy
import logging
import os
import re
from email.headerregistry import Address

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FORWARDED_HEADER = "X-MCP-Forwarded"
MAX_FORWARD_BYTES = 9 * 1024 * 1024  # SES sends at most 10 MB
DROPPED_HEADERS = ("DKIM-Signature", "DomainKey-Signature", "Return-Path", "Sender", "Message-ID",
                   "Authentication-Results", "Received-SPF", "ARC-Seal", "ARC-Message-Signature",
                   "ARC-Authentication-Results")

_clients = {}


def _client(name):
    if name not in _clients:
        _clients[name] = boto3.client(name)
    return _clients[name]


def _settings():
    return {"bucket": os.environ["BUCKET"], "prefix": os.environ.get("PREFIX", "inbound/"),
            "forward_to": os.environ["FORWARD_TO"], "from_address": os.environ["FROM_ADDRESS"]}


def _verdict(receipt, name):
    return (receipt.get(name) or {}).get("status", "")


def _label(original_from, fallback):
    """A display name for the From line: the sender's name or address, made safe."""
    name = original_from.display_name if original_from is not None and original_from.display_name else ""
    if not name:
        name = original_from.addr_spec if original_from is not None else fallback
    name = re.sub(r"[\x00-\x1f\x7f\"<>\\]", "", name).strip()[:80] or "someone"
    return "{} via MCP Licensing".format(name)


def _original_from(msg, envelope_sender):
    try:
        header = msg["From"]
        if header is not None and header.addresses:
            return header.addresses[0]
    except Exception:
        logger.warning("could not read the From header")
    return None


def build_forward(raw, receipt, envelope_sender, settings):
    """The message to send, or None when it must not be forwarded."""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    if msg[FORWARDED_HEADER]:
        logger.warning("dropping a message that was already forwarded")
        return None

    original_from = _original_from(msg, envelope_sender)
    reply_to = msg["Reply-To"]
    reply_address = str(reply_to) if reply_to else (str(msg["From"]) if msg["From"] else envelope_sender)
    subject = str(msg["Subject"]) if msg["Subject"] is not None else "(no subject)"
    if _verdict(receipt, "spamVerdict") == "FAIL":
        subject = "[Spam?] " + subject

    for name in DROPPED_HEADERS + ("From", "Reply-To", "Subject"):
        del msg[name]
    msg["From"] = str(Address(display_name=_label(original_from, envelope_sender),
                              addr_spec=settings["from_address"]))
    msg["Reply-To"] = reply_address
    msg["Subject"] = subject
    msg[FORWARDED_HEADER] = "1"
    msg["X-Original-Sender"] = envelope_sender
    if "To" not in msg:
        msg["To"] = settings["from_address"]
    return msg


def _notice(subject, envelope_sender, s3_location, settings):
    msg = email.message.EmailMessage(policy=email.policy.default)
    msg["From"] = str(Address(display_name="MCP Licensing mail", addr_spec=settings["from_address"]))
    msg["To"] = settings["from_address"]
    msg["Subject"] = "A message was too large to forward: " + subject
    msg[FORWARDED_HEADER] = "1"
    msg.set_content(
        "A message from {} was too large to forward by email.\n\nIt is kept at {} "
        "(retained for 30 days).\n".format(envelope_sender, s3_location))
    return msg


def forward(ses_record, settings=None):
    settings = settings or _settings()
    mail, receipt = ses_record["mail"], ses_record.get("receipt", {})
    message_id = mail["messageId"]
    sender = mail.get("source", "unknown")

    if _verdict(receipt, "virusVerdict") == "FAIL":
        logger.warning("dropping message %s: failed the virus scan", message_id)
        return "dropped-virus"

    key = settings["prefix"] + message_id
    location = "s3://{}/{}".format(settings["bucket"], key)
    raw = _client("s3").get_object(Bucket=settings["bucket"], Key=key)["Body"].read()

    if len(raw) > MAX_FORWARD_BYTES:
        subject = (mail.get("commonHeaders") or {}).get("subject", "(no subject)")
        msg = _notice(subject, sender, location, settings)
        outcome = "notice"
    else:
        msg = build_forward(raw, receipt, sender, settings)
        if msg is None:
            return "dropped-loop"
        outcome = "forwarded"

    _client("ses").send_raw_email(Source=settings["from_address"], Destinations=[settings["forward_to"]],
                                  RawMessage={"Data": msg.as_bytes()})
    logger.info("message %s %s", message_id, outcome)  # no addresses or subject in the logs
    return outcome


def handler(event, context):
    return [forward(record["ses"]) for record in event["Records"]]
