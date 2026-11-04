"""The inbound mail forwarder: mail received for the domain reaches one inbox."""
import email
import email.policy
import importlib.util
import pathlib
from email.message import EmailMessage

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FORWARD_TO = "owner@example.net"
FROM_ADDRESS = "support@mcplicense.net"
SETTINGS = {"bucket": "inbound-bucket", "prefix": "inbound/", "forward_to": FORWARD_TO,
            "from_address": FROM_ADDRESS}


@pytest.fixture(scope="module")
def forwarder_module():
    spec = importlib.util.spec_from_file_location("forwarder", ROOT / "mail" / "forwarder.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.reads = []

    def get_object(self, Bucket, Key):
        self.reads.append((Bucket, Key))
        body = self.objects[(Bucket, Key)]
        return {"Body": type("Body", (), {"read": lambda self_: body})()}


class FakeSes:
    def __init__(self):
        self.sent = []

    def send_raw_email(self, **kwargs):
        self.sent.append(kwargs)


@pytest.fixture
def mail(forwarder_module, monkeypatch):
    s3, ses = FakeS3(), FakeSes()
    monkeypatch.setitem(forwarder_module._clients, "s3", s3)
    monkeypatch.setitem(forwarder_module._clients, "ses", ses)
    for name, value in (("BUCKET", "inbound-bucket"), ("FORWARD_TO", FORWARD_TO), ("FROM_ADDRESS", FROM_ADDRESS)):
        monkeypatch.setenv(name, value)

    class Harness:
        module = forwarder_module

        def receive(self, raw, message_id="abc123", spam="PASS", virus="PASS", source="jane@example.org"):
            s3.objects[("inbound-bucket", "inbound/" + message_id)] = raw
            record = {"ses": {"mail": {"messageId": message_id, "source": source,
                                       "commonHeaders": {"subject": "Hello"}},
                              "receipt": {"spamVerdict": {"status": spam}, "virusVerdict": {"status": virus}}}}
            return forwarder_module.handler({"Records": [record]}, None)

        @property
        def sent(self):
            return ses.sent

        @property
        def reads(self):
            return s3.reads

        def forwarded(self):
            (call,) = ses.sent
            return call, email.message_from_bytes(call["RawMessage"]["Data"], policy=email.policy.default)

    return Harness()


def message(subject="Hello", sender="Jane Doe <jane@example.org>", body="Can you help with seats?", **headers):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "support@mcplicense.net"
    if subject is not None:
        msg["Subject"] = subject
    msg["Message-ID"] = "<original@example.org>"
    msg["DKIM-Signature"] = "v=1; a=rsa-sha256; d=example.org; s=x; b=abc"
    msg["Return-Path"] = "<bounces@example.org>"
    for name, value in headers.items():
        msg[name.replace("_", "-")] = value
    msg.set_content(body)
    return msg


# ------------------------------------------------------------------ forwarding

def test_a_message_reaches_the_inbox_from_the_domain_address(mail):
    assert mail.receive(message().as_bytes()) == ["forwarded"]
    call, forwarded = mail.forwarded()
    assert call["Source"] == FROM_ADDRESS and call["Destinations"] == [FORWARD_TO]
    assert forwarded["From"].addresses[0].addr_spec == FROM_ADDRESS
    assert forwarded["From"].addresses[0].display_name == "Jane Doe via MCP Licensing"
    assert forwarded["Subject"] == "Hello"
    assert forwarded["To"] == "support@mcplicense.net"
    assert "Can you help with seats?" in forwarded.get_content()


def test_replying_goes_to_the_original_sender(mail):
    mail.receive(message().as_bytes())
    _, forwarded = mail.forwarded()
    assert forwarded["Reply-To"].addresses[0].addr_spec == "jane@example.org"
    assert forwarded["Reply-To"].addresses[0].display_name == "Jane Doe"


def test_an_original_reply_to_is_kept(mail):
    mail.receive(message(Reply_To="Sales Desk <sales@example.org>").as_bytes())
    _, forwarded = mail.forwarded()
    assert forwarded["Reply-To"].addresses[0].addr_spec == "sales@example.org"


def test_authentication_headers_that_no_longer_apply_are_dropped(mail):
    mail.receive(message().as_bytes())
    _, forwarded = mail.forwarded()
    for header in ("DKIM-Signature", "Return-Path", "Message-ID", "Sender"):
        assert forwarded[header] is None, header
    assert forwarded["X-MCP-Forwarded"] == "1"
    assert forwarded["X-Original-Sender"] == "jane@example.org"


def test_attachments_and_html_survive(mail):
    msg = message(body="plain text version")
    msg.add_alternative("<p>html <b>version</b></p>", subtype="html")
    msg.add_attachment(b"%PDF-1.4 fake pdf bytes", maintype="application", subtype="pdf", filename="invoice.pdf")
    mail.receive(msg.as_bytes())
    _, forwarded = mail.forwarded()
    attachments = list(forwarded.iter_attachments())
    assert [a.get_filename() for a in attachments] == ["invoice.pdf"]
    assert attachments[0].get_content() == b"%PDF-1.4 fake pdf bytes"
    assert "html <b>version</b>" in forwarded.get_body(("html",)).get_content()
    assert "plain text version" in forwarded.get_body(("plain",)).get_content()


def test_non_ascii_names_and_subjects_round_trip(mail):
    mail.receive(message(subject="Fragen zur Lizenz über 5 Plätze", sender="José Álvarez <jose@example.es>").as_bytes())
    _, forwarded = mail.forwarded()
    assert forwarded["Subject"] == "Fragen zur Lizenz über 5 Plätze"
    assert forwarded["From"].addresses[0].display_name == "José Álvarez via MCP Licensing"


def test_a_message_without_a_subject_or_from_still_arrives(mail):
    msg = EmailMessage()
    msg["To"] = "support@mcplicense.net"
    msg.set_content("just a body")
    mail.receive(msg.as_bytes(), source="bounce@example.org")
    _, forwarded = mail.forwarded()
    assert forwarded["Subject"] == "(no subject)"
    assert forwarded["From"].addresses[0].display_name == "bounce@example.org via MCP Licensing"
    assert forwarded["Reply-To"] == "bounce@example.org"


def test_a_garbled_message_does_not_crash_the_forwarder(mail):
    assert mail.receive(b"\x00\xff\xfe not an email at all \r\n\r\n??") == ["forwarded"]
    assert len(mail.sent) == 1


def test_a_hostile_sender_name_cannot_inject_headers(mail):
    raw = (b'From: "Eve\\" <evil@x.example>\r\n Bcc: victim@example.com" <eve@example.org>\r\n'
           b"To: support@mcplicense.net\r\nSubject: hi\r\n\r\nbody text here\r\n")
    mail.receive(raw)
    call, forwarded = mail.forwarded()
    assert "bcc" not in [name.lower() for name in forwarded.keys()]
    assert call["Destinations"] == [FORWARD_TO]
    display = forwarded["From"].addresses[0].display_name
    assert "<" not in display and ">" not in display and "\n" not in display and '"' not in display
    assert forwarded["From"].addresses[0].addr_spec == FROM_ADDRESS


# ------------------------------------------------------------- spam and safety

def test_spam_is_forwarded_but_marked(mail):
    mail.receive(message().as_bytes(), spam="FAIL")
    _, forwarded = mail.forwarded()
    assert forwarded["Subject"] == "[Spam?] Hello"


@pytest.mark.parametrize("verdict", ["PASS", "GRAY", "PROCESSING_FAILED", ""])
def test_other_spam_verdicts_leave_the_subject_alone(mail, verdict):
    mail.receive(message().as_bytes(), spam=verdict)
    _, forwarded = mail.forwarded()
    assert forwarded["Subject"] == "Hello"


def test_a_message_with_a_virus_is_dropped_unread(mail):
    assert mail.receive(message().as_bytes(), virus="FAIL") == ["dropped-virus"]
    assert mail.sent == [] and mail.reads == []


def test_a_message_that_was_already_forwarded_is_never_forwarded_again(mail):
    assert mail.receive(message(X_MCP_Forwarded="1").as_bytes()) == ["dropped-loop"]
    assert mail.sent == []


def test_an_oversized_message_is_replaced_by_a_notice_that_says_where_it_is(mail):
    big = message(body="x" * 100).as_bytes() + b"A" * (mail.module.MAX_FORWARD_BYTES + 1)
    assert mail.receive(big, message_id="big1") == ["notice"]
    call, notice = mail.forwarded()
    assert notice["Subject"] == "A message was too large to forward: Hello"
    assert "s3://inbound-bucket/inbound/big1" in notice.get_content()
    assert len(call["RawMessage"]["Data"]) < 5000  # the big message itself is not sent


def test_the_logs_do_not_contain_addresses_or_subjects(mail, caplog):
    caplog.set_level("INFO")
    mail.receive(message(subject="a secret subject line").as_bytes())
    assert "jane@example.org" not in caplog.text and "secret subject" not in caplog.text
    assert "abc123 forwarded" in caplog.text


def test_several_records_in_one_event_are_all_forwarded(mail):
    mail.receive(message().as_bytes(), message_id="one")
    mail.receive(message(subject="Second").as_bytes(), message_id="two")
    assert len(mail.sent) == 2
