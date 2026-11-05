"""POST /v1/site/contact - the website's contact form.

The site has no JavaScript, so this is a plain HTML form post. A valid message
is emailed to the owner through an SNS topic and the visitor is redirected to a
thank-you page; a problem is answered with a small HTML page. Nothing is stored:
the message goes to the owner's inbox and the logs record only that one was sent.

Abuse protection, cheapest first: the request must come from the site (Origin
or Referer), a hidden field that only a bot fills in, a per-visitor attempt
limit (3, then a 30-minute lock), a spam filter (a link, or a phrase from the
mcp_spam_phrase table, see core/spam.py: such a message is dropped silently and
still counts as an attempt),
a daily cap on the whole form, and size limits.
WAF rate-limits the path in front of all this. Neither the recipient's address
nor any other detail of the owner appears here: the subscription lives on the
SNS topic.
"""
import base64
import html
import logging
import os
import re
import urllib.parse

import boto3

from core import clientip, config, spam, store
from core.http import from_our_site, make_handler

logger = logging.getLogger()

TOPICS = {
    "support": "Support",
    "limit": "Raise a limit",
    "privacy": "Privacy request",
    "security": "Security issue",
    "other": "Other",
}
MAX_BODY_BYTES = 8 * 1024
MAX_NAME = 100
MAX_EMAIL = 200
MIN_MESSAGE = 10
MAX_MESSAGE = 2000
HONEYPOT = "website"
SPAM_SCOPE = "contact"
THANKS = "/contact/thanks/"
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # everything but tab and newline

_sns_client = {"obj": None}


def _sns():
    if _sns_client["obj"] is None:
        _sns_client["obj"] = boto3.client("sns")
    return _sns_client["obj"]


# ------------------------------------------------------------------ responses

def _page(status, heading, text):
    body = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex"><title>{h} - MCP Licensing</title>'
        '<link rel="stylesheet" href="/style.css"></head><body>'
        '<main class="page"><div class="wrap narrow"><h1>{h}</h1><p>{t}</p>'
        '<p><a href="/contact/">Back to the contact form</a></p></div></main></body></html>'
    ).format(h=html.escape(heading), t=html.escape(text))
    return {"statusCode": status,
            "headers": {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"},
            "body": body}


def _redirect(location):
    return {"statusCode": 303, "headers": {"Location": location, "Cache-Control": "no-store"}, "body": ""}


# ------------------------------------------------------------------ the form

def _header(event, name):
    return (event.get("headers") or {}).get(name.lower())


def _fields(event):
    """The form as a dict of single strings, or None when it is not a form post."""
    content_type = (_header(event, "content-type") or "").split(";")[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        return None
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8", "replace")
    if len(raw.encode("utf-8")) > MAX_BODY_BYTES:
        raise OverflowError
    parsed = urllib.parse.parse_qs(raw, keep_blank_values=True, max_num_fields=20)
    return {key: values[0] for key, values in parsed.items()}


def _clean(value, limit, keep_newlines=False):
    value = CONTROL_RE.sub("", (value or "").replace("\r\n", "\n").replace("\r", "\n"))
    if not keep_newlines:
        value = " ".join(value.split())
    return value.strip()[:limit] if limit else value.strip()


def _message_text(topic, name, email, message, country):
    return (
        "A message from the MCP Licensing contact form\n\n"
        "Topic:   {topic}\nName:    {name}\nEmail:   {email}\nCountry: {country}\nTime:    {when}\n\n"
        "{message}\n\n--\nReply to the sender's address above. The form does not store messages."
    ).format(topic=TOPICS[topic], name=name or "(not given)", email=email, country=country,
             when=store.now_iso(), message=message)


def _spam_phrases():
    """The usable phrases of the 'contact' rows of the spam table, or None (the built-in list applies) when
    it cannot be read or holds nothing usable."""
    try:
        phrases, skipped = spam.phrases_from_rows(store.spam_rows(SPAM_SCOPE))
    except Exception:
        logger.exception("contact form: could not read the spam phrases; using the built-in list")
        return None
    if skipped:
        logger.warning("contact form: %d spam phrase entries were skipped as unusable", skipped)
    return phrases or None


def submit(event):
    try:
        form = _fields(event)
    except OverflowError:
        return _page(413, "Message too long", "That message is too large to send. Please shorten it.")
    if form is None:
        return _page(415, "Cannot send", "Please use the contact form on the website.")
    if not from_our_site(event):
        logger.warning("contact form refused: wrong origin")
        return _page(403, "Cannot send", "Please use the contact form on the website.")

    topic = form.get("topic", "")
    name = _clean(form.get("name"), MAX_NAME)
    email = _clean(form.get("email"), MAX_EMAIL)
    message = _clean(form.get("message"), 0, keep_newlines=True)

    if topic not in TOPICS:
        return _page(400, "Check your message", "Please choose a topic.")
    if not EMAIL_RE.match(email):
        return _page(400, "Check your message", "Please enter a valid email address so we can reply.")
    if not MIN_MESSAGE <= len(message) <= MAX_MESSAGE:
        return _page(400, "Check your message",
                     "Your message must be between {} and {} characters.".format(MIN_MESSAGE, MAX_MESSAGE))

    visitor = clientip.rate_key(event)
    allowed, retry_after = store.take_attempt(
        "contact", visitor, config.get_int("contact_ip_attempts"), config.get_int("contact_ip_lock_seconds"))
    if not allowed:
        logger.warning("contact form refused: visitor locked out")
        return _page(429, "Too many messages",
                     "Too many messages were sent from your network. Please try again in about {} minutes."
                     .format(max(1, (retry_after + 59) // 60)))

    if _clean(form.get(HONEYPOT), 50):  # a bot filled in the hidden field: look like success
        logger.warning("contact form: honeypot filled")
        return _redirect(THANKS)

    if config.get_int("contact_spam_filter"):  # 0 switches the filter off (SSM) if it ever drops a real message
        why = spam.reason(name, message, _spam_phrases())
        if why:
            logger.warning("contact form: filtered as spam (%s)", why)
            return _redirect(THANKS)

    sent_today, _ = store.take_window_slot("contact-day", "all", config.get_int("contact_daily_cap"), 86400)
    if not sent_today:
        logger.warning("contact form refused: daily cap reached")
        return _page(429, "Please try again later",
                     "We are receiving a lot of messages right now. Please try again tomorrow.")

    topic_arn = os.environ.get("CONTACT_TOPIC_ARN")
    country = _header(event, "cloudfront-viewer-country") or ""
    country = country if re.fullmatch(r"[A-Z]{2}", country) else "unknown"
    try:
        if not topic_arn:
            raise RuntimeError("CONTACT_TOPIC_ARN is not set")
        _sns().publish(TopicArn=topic_arn, Subject="MCP Licensing contact: {}".format(TOPICS[topic]),
                       Message=_message_text(topic, name, email, message, country))
    except Exception:
        logger.exception("contact form: could not deliver a message")
        return _page(503, "Could not send", "Your message could not be sent right now. Please try again later.")

    logger.info("contact form: message delivered topic=%s", topic)
    return _redirect(THANKS)


handler = make_handler({"POST /v1/site/contact": submit})
