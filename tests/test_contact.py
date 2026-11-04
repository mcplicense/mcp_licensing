"""The website's contact form: POST /v1/site/contact."""
import base64
import json
import time
import urllib.parse

import boto3
import pytest

from core import config, store
from handlers import contact

TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:mcp-licensing-test-contact"
SITE = "https://mcplicense.net"
IP = "203.0.113.9"


class FakeSns:
    def __init__(self):
        self.published = []
        self.fail = False

    def publish(self, **kwargs):
        if self.fail:
            raise RuntimeError("SNS is down")
        self.published.append(kwargs)


@pytest.fixture(autouse=True)
def sns(monkeypatch):
    fake = FakeSns()
    monkeypatch.setitem(contact._sns_client, "obj", fake)
    monkeypatch.setenv("CONTACT_TOPIC_ARN", TOPIC_ARN)
    monkeypatch.delenv("SITE_ORIGIN", raising=False)
    monkeypatch.delenv("ORIGIN_SECRET", raising=False)
    return fake


@pytest.fixture
def clock(monkeypatch):
    state = {"t": (int(time.time()) // 86400) * 86400 + 100}
    monkeypatch.setattr(store, "now_epoch", lambda: state["t"])
    return state


def good(**overrides):
    form = {"topic": "support", "name": "Jane Doe", "email": "jane@example.com",
            "message": "Hello, I would like to know how seats work.", "website": ""}
    form.update(overrides)
    return form


def post(form, ip=IP, headers=None, raw=None, content_type="application/x-www-form-urlencoded",
         base64_body=False):
    body = raw if raw is not None else urllib.parse.urlencode(form)
    if base64_body:
        body = base64.b64encode(body.encode()).decode()
    all_headers = {"content-type": content_type, "cloudfront-viewer-address": "{}:4430".format(ip),
                   "cloudfront-viewer-country": "IN"}
    all_headers.update(headers or {})
    event = {"routeKey": "POST /v1/site/contact", "headers": all_headers, "body": body,
             "isBase64Encoded": base64_body}
    return contact.handler(event, None)


def is_thanks(response):
    return response["statusCode"] == 303 and response["headers"]["Location"] == "/contact/thanks/"


# --------------------------------------------------------------- the message

def test_a_valid_message_is_emailed_and_the_visitor_is_thanked(sns):
    response = post(good())
    assert is_thanks(response)
    (sent,) = sns.published
    assert sent["TopicArn"] == TOPIC_ARN
    assert sent["Subject"] == "MCP Licensing contact: Support"
    for expected in ("jane@example.com", "Jane Doe", "Hello, I would like to know how seats work.",
                     "Topic:   Support", "Country: IN"):
        assert expected in sent["Message"]
    assert IP not in sent["Message"]  # the visitor's address is used for limits, not passed on


def test_the_subject_comes_only_from_the_fixed_list(sns):
    for topic, label in contact.TOPICS.items():
        post(good(topic=topic), ip="198.51.100.{}".format(len(sns.published) + 1))
    assert [m["Subject"] for m in sns.published] == [
        "MCP Licensing contact: " + label for label in contact.TOPICS.values()]
    assert all("\n" not in m["Subject"] and len(m["Subject"]) <= 100 for m in sns.published)


def test_control_characters_and_line_breaks_cannot_forge_fields(sns):
    post(good(name="Eve\r\nTopic:   Security issue\x00", message="Hi there, friend.\x07\x1b[31m red"))
    message = sns.published[0]["Message"]
    assert "\r" not in message and "\x00" not in message and "\x07" not in message and "\x1b" not in message
    # no line of its own starts a second field: the injected text was folded into the name line
    assert [line for line in message.split("\n") if line.startswith("Topic:")] == ["Topic:   Support"]
    assert "Name:    Eve Topic: Security issue" in message


def test_the_message_may_have_several_lines(sns):
    post(good(message="Line one is here.\r\n\r\nLine three is here."))
    assert "Line one is here.\n\nLine three is here." in sns.published[0]["Message"]


def test_the_name_is_optional(sns):
    post(good(name=""))
    assert "Name:    (not given)" in sns.published[0]["Message"]


def test_a_base64_body_is_accepted(sns):
    assert is_thanks(post(good(), base64_body=True))
    assert len(sns.published) == 1


# ---------------------------------------------------------------- validation

@pytest.mark.parametrize("override,fragment", [
    ({"topic": ""}, "choose a topic"),
    ({"topic": "free-money"}, "choose a topic"),
    ({"email": ""}, "valid email"),
    ({"email": "not-an-email"}, "valid email"),
    ({"email": "a@b"}, "valid email"),
    ({"email": "jane@example.com\r\nBcc: x@example.com"}, "valid email"),
    ({"email": "<script>@example.com"}, "valid email"),
    ({"message": "short"}, "between 10 and 2000"),
    ({"message": "x" * 2001}, "between 10 and 2000"),
])
def test_invalid_input_gets_a_clear_page_and_sends_nothing(sns, override, fragment):
    response = post(good(**override))
    assert response["statusCode"] == 400
    assert response["headers"]["Content-Type"].startswith("text/html")
    assert fragment in response["body"]
    assert sns.published == []


def test_a_typo_does_not_use_up_the_visitors_attempts(sns):
    for _ in range(5):
        assert post(good(email="oops"))["statusCode"] == 400
    assert all(is_thanks(post(good())) for _ in range(3))


def test_error_pages_never_echo_what_the_visitor_typed():
    response = post(good(email="<img src=x onerror=alert(1)>", message="<b>secret-marker</b> padding"))
    assert "secret-marker" not in response["body"] and "onerror" not in response["body"]
    assert "<script" not in response["body"].lower()


def test_only_a_form_post_is_accepted(sns):
    assert post(None, raw=json.dumps(good()), content_type="application/json")["statusCode"] == 415
    assert post(None, raw=urllib.parse.urlencode(good()), content_type="text/plain")["statusCode"] == 415
    assert post(None, raw="topic=support&message=" + "x" * 9000)["statusCode"] == 413
    assert sns.published == []


def test_the_content_type_may_carry_a_charset(sns):
    assert is_thanks(post(good(), content_type="application/x-www-form-urlencoded; charset=UTF-8"))


# ------------------------------------------------------------------ the bots

def test_a_filled_hidden_field_looks_like_success_but_sends_nothing(sns):
    assert is_thanks(post(good(website="http://spam.example")))
    assert sns.published == []


def test_a_bot_that_fills_the_hidden_field_still_uses_up_its_attempts(sns):
    for _ in range(3):
        post(good(website="x"))
    assert post(good())["statusCode"] == 429


def test_the_site_origin_is_enforced_when_configured(sns, monkeypatch):
    monkeypatch.setenv("SITE_ORIGIN", SITE)
    assert is_thanks(post(good(), headers={"origin": SITE}))
    assert is_thanks(post(good(), headers={"referer": SITE + "/contact/"}, ip="198.51.100.1"))
    for headers in ({"origin": "https://evil.example"}, {"referer": "https://evil.example/contact/"},
                    {"referer": SITE + ".evil.example/"}, {}):
        assert post(good(), headers=headers, ip="198.51.100.2")["statusCode"] == 403
    assert len(sns.published) == 2


def test_the_origin_is_not_checked_when_not_configured(sns):
    assert is_thanks(post(good(), headers={"origin": "https://anything.example"}))


def test_the_origin_secret_check_still_applies(sns, monkeypatch):
    monkeypatch.setenv("ORIGIN_SECRET", "s" * 40)
    response = post(good())
    assert response["statusCode"] == 403 and json.loads(response["body"])["error"]["code"] == "FORBIDDEN"
    assert is_thanks(post(good(), headers={"x-origin-verify": "s" * 40}))


# ------------------------------------------------------- 3 attempts, 30 minutes

def test_three_messages_then_a_30_minute_lock(sns, clock):
    assert all(is_thanks(post(good())) for _ in range(3))
    locked = post(good())
    assert locked["statusCode"] == 429 and "30 minutes" in locked["body"]
    assert len(sns.published) == 3
    clock["t"] += 1799
    assert post(good())["statusCode"] == 429
    clock["t"] += 1
    assert is_thanks(post(good()))


def test_another_visitor_is_not_affected(sns, clock):
    for _ in range(4):
        post(good(), ip="198.51.100.1")
    assert is_thanks(post(good(), ip="198.51.100.2"))


def test_an_ipv6_visitor_cannot_dodge_the_lock_by_changing_address(sns, clock):
    def v6(last):
        return post(good(), headers={"cloudfront-viewer-address": "[2001:db8:1:2::{}]:4430".format(last)})
    assert all(is_thanks(v6(n)) for n in (1, 2, 3))
    assert v6(4)["statusCode"] == 429


def test_the_numbers_come_from_ssm(sns, clock, monkeypatch):
    monkeypatch.setenv("SSM_PREFIX", "/mcp/test")
    ssm = boto3.client("ssm")
    ssm.put_parameter(Name="/mcp/test/contact_ip_attempts", Value="1", Type="String")
    ssm.put_parameter(Name="/mcp/test/contact_ip_lock_seconds", Value="600", Type="String")
    config.reset_cache()
    assert is_thanks(post(good()))
    assert post(good())["statusCode"] == 429
    clock["t"] += 600
    assert is_thanks(post(good()))


def test_a_daily_cap_covers_the_whole_form(sns, clock, monkeypatch):
    monkeypatch.setenv("SSM_PREFIX", "/mcp/test")
    boto3.client("ssm").put_parameter(Name="/mcp/test/contact_daily_cap", Value="2", Type="String")
    config.reset_cache()
    assert is_thanks(post(good(), ip="198.51.100.1"))
    assert is_thanks(post(good(), ip="198.51.100.2"))
    capped = post(good(), ip="198.51.100.3")
    assert capped["statusCode"] == 429 and "tomorrow" in capped["body"]
    assert len(sns.published) == 2
    clock["t"] += 86400
    assert is_thanks(post(good(), ip="198.51.100.4"))


def test_a_request_with_no_usable_address_shares_one_strict_bucket(sns, clock):
    assert all(is_thanks(post(good(), headers={"cloudfront-viewer-address": ""})) for _ in range(3))
    assert post(good(), headers={"cloudfront-viewer-address": ""})["statusCode"] == 429


# ------------------------------------------------------------------- delivery

def test_a_delivery_failure_tells_the_visitor_to_try_later(sns):
    sns.fail = True
    response = post(good())
    assert response["statusCode"] == 503 and "try again later" in response["body"]
    assert "SNS is down" not in response["body"]


def test_a_missing_topic_is_a_delivery_failure_not_a_crash(sns, monkeypatch):
    monkeypatch.delenv("CONTACT_TOPIC_ARN")
    assert post(good())["statusCode"] == 503


def test_the_logs_do_not_contain_the_message(sns, caplog):
    caplog.set_level("INFO")
    post(good(message="a private message with a marker word: zebra-marker-42"))
    assert "zebra-marker-42" not in caplog.text and "jane@example.com" not in caplog.text
