"""scripts/smtp_credentials.py: SMTP credentials for sending as support@<domain>."""
import base64
import importlib.util
import json
import pathlib

import boto3
import pytest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "smtp_credentials.py"


@pytest.fixture(scope="module")
def smtp():
    spec = importlib.util.spec_from_file_location("smtp_credentials", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(smtp, monkeypatch, *argv):
    monkeypatch.setattr("sys.argv", ["smtp_credentials.py", *argv])
    smtp.main()


def test_the_password_derivation_has_the_documented_shape(smtp):
    password = smtp.smtp_password("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1")
    raw = base64.b64decode(password)
    assert len(raw) == 33 and raw[0] == 0x04  # a version byte, then an HMAC-SHA256
    assert password == smtp.smtp_password("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1")


def test_the_password_depends_on_the_secret_and_the_region(smtp):
    base = smtp.smtp_password("secret-one", "us-east-1")
    assert smtp.smtp_password("secret-two", "us-east-1") != base
    assert smtp.smtp_password("secret-one", "us-west-2") != base


def test_the_policy_allows_one_action_from_one_address_on_one_identity(smtp):
    policy = smtp.policy_document("mcplicense.net", "us-east-1", "123456789012")
    (statement,) = policy["Statement"]
    assert statement["Action"] == "ses:SendRawEmail" and statement["Effect"] == "Allow"
    assert statement["Resource"] == "arn:aws:ses:us-east-1:123456789012:identity/mcplicense.net"
    assert statement["Condition"] == {"StringEquals": {"ses:FromAddress": "support@mcplicense.net"}}


def test_it_creates_a_restricted_user_and_prints_the_credentials_once(smtp, monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    run(smtp, monkeypatch, "--domain", "mcplicense.net", "--region", "us-east-1")
    out = capsys.readouterr().out
    iam = boto3.client("iam")

    (key,) = iam.list_access_keys(UserName=smtp.USER_NAME)["AccessKeyMetadata"]
    assert "Username:     " + key["AccessKeyId"] in out
    assert "email-smtp.us-east-1.amazonaws.com" in out and "587" in out
    assert "Password:     " in out

    stored = iam.get_user_policy(UserName=smtp.USER_NAME, PolicyName="send-as-support")["PolicyDocument"]
    assert json.dumps(stored).count("ses:SendRawEmail") == 1
    assert list(tmp_path.iterdir()) == []  # nothing written to disk


def test_running_it_again_adds_a_second_key_for_rotation(smtp, monkeypatch, capsys):
    for _ in range(2):
        run(smtp, monkeypatch, "--domain", "mcplicense.net", "--region", "us-east-1")
    keys = boto3.client("iam").list_access_keys(UserName=smtp.USER_NAME)["AccessKeyMetadata"]
    assert len(keys) == 2
    assert capsys.readouterr().out.count("Password:") == 2


def test_check_needs_credentials(smtp, monkeypatch):
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    with pytest.raises(SystemExit):
        run(smtp, monkeypatch, "--domain", "mcplicense.net", "--region", "us-east-1", "--check")


def test_check_logs_in_without_sending_anything(smtp, monkeypatch, capsys):
    calls = []

    class FakeServer:
        def __init__(self, host, port, timeout):
            calls.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self):
            calls.append(("starttls",))

        def login(self, user, password):
            calls.append(("login", user, password))

        def sendmail(self, *args, **kwargs):
            raise AssertionError("--check must not send mail")

    monkeypatch.setattr(smtp.smtplib, "SMTP", FakeServer)
    monkeypatch.setenv("SMTP_PASSWORD", "pw")
    run(smtp, monkeypatch, "--domain", "mcplicense.net", "--region", "us-east-1", "--check", "--user", "AKIAEXAMPLE")
    assert calls == [("connect", "email-smtp.us-east-1.amazonaws.com", 587), ("starttls",),
                     ("login", "AKIAEXAMPLE", "pw")]
    assert "login accepted" in capsys.readouterr().out
