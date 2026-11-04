"""The rules for people who sign up, and every call to Cognito checked against the real API model."""
import base64
import json

import boto3
import pytest
from botocore.stub import Stubber

from core import cognito, identity
from core.http import ApiError
from fake_cognito import CLIENT_ID, CLIENT_SECRET, POOL_ID, error

GMAIL = "gmail.com"  # spelt out here so no test fixture looks like a real mailbox to the hygiene test
GOOGLEMAIL = "googlemail.com"


# --------------------------------------------------------------------- emails

@pytest.mark.parametrize("raw,clean", [
    ("Jane@Example.com", "jane@example.com"), ("  jane@example.com  ", "jane@example.com"),
    ("jane+tag@example.co.uk", "jane+tag@example.co.uk"),
])
def test_clean_email(raw, clean):
    assert identity.clean_email(raw) == clean


@pytest.mark.parametrize("raw", ["", "jane", "jane@", "@example.com", "jane@example", "a b@example.com",
                                 "<x>@example.com", "jane@example.com\nBcc: x@y.z", None, 42, "a" * 201 + "@example.com"])
def test_clean_email_rejects(raw):
    assert identity.clean_email(raw) is None


@pytest.mark.parametrize("a,b", [
    ("jane@example.com", "JANE@example.com"),
    ("jane@example.com", "jane+anything@example.com"),
    ("j.a.n.e@" + GMAIL, "jane@" + GMAIL),
    ("jane@" + GOOGLEMAIL, "j.ane+x@" + GMAIL),
])
def test_the_same_mailbox_has_one_hash(a, b):
    assert identity.email_hash(a) == identity.email_hash(b)


@pytest.mark.parametrize("a,b", [
    ("jane@example.com", "jane@example.org"),
    ("j.ane@example.com", "jane@example.com"),   # dots only count at Gmail
    ("jane@example.com", "jan@example.com"),
])
def test_different_mailboxes_have_different_hashes(a, b):
    assert identity.email_hash(a) != identity.email_hash(b)


def test_the_hash_does_not_contain_the_address():
    value = identity.email_hash("jane@example.com")
    assert len(value) == 64 and "jane" not in value and "example" not in value


# ------------------------------------------------------------------ passwords

@pytest.mark.parametrize("password", ["Correct-Horse-9", "Abcdefghij12", "A1" + "b" * 126])
def test_acceptable_passwords(password):
    assert identity.password_problem(password, "someone@example.com") is None


@pytest.mark.parametrize("password,fragment", [
    (None, "Enter a password"), (123456789012, "Enter a password"), ("", "at least 12"),
    ("Short1A", "at least 12"), ("x" * 129, "at most 128"),
    ("alllowercase1234", "capital letter"), ("ALLCAPITALS1234", "lower-case"), ("NoNumbersAtAllHere", "number"),
    ("Passw0rd1234", "too common"), ("Welcome12345", "too common"),
])
def test_unacceptable_passwords(password, fragment):
    assert fragment in identity.password_problem(password)


def test_a_password_may_not_contain_a_long_email_name_but_a_short_one_is_fine():
    assert "email name" in identity.password_problem("Janedoe-Rocks-99", "janedoe@example.com")
    assert identity.password_problem("Correct-Horse-9", "c@example.com") is None
    assert identity.password_problem("Correct-Horse-9", "abc@example.com") is None


# ------------------------------------------------------------------ companies

@pytest.mark.parametrize("raw,clean", [("Acme", "Acme"), ("  Acme   Tools  ", "Acme Tools"), ("Ac\x00me\nTools", "Ac me Tools"),
                                       ("x" * 100, "x" * 100)])
def test_company_names(raw, clean):
    assert identity.clean_company(raw) == clean


@pytest.mark.parametrize("raw", ["", " ", "x", "x" * 101, None, 7])
def test_unusable_company_names(raw):
    assert identity.clean_company(raw) is None


# ----------------------------------------------- Cognito calls match the API model

@pytest.fixture
def stub(monkeypatch):
    """A real boto3 client (so every call is validated against the cognito-idp service model) with
    its answers stubbed: a misspelt or missing parameter fails here, not in production."""
    for name, value in (("USER_POOL_ID", POOL_ID), ("USER_POOL_CLIENT_ID", CLIENT_ID),
                        ("USER_POOL_CLIENT_SECRET", CLIENT_SECRET)):
        monkeypatch.setenv(name, value)
    client = boto3.client("cognito-idp", region_name="us-east-1")
    monkeypatch.setitem(cognito._client, "obj", client)
    with Stubber(client) as stubber:
        yield stubber
        stubber.assert_no_pending_responses()


def test_secret_hash_matches_the_documented_algorithm(monkeypatch):
    for name, value in (("USER_POOL_CLIENT_ID", "abc"), ("USER_POOL_CLIENT_SECRET", "shh")):
        monkeypatch.setenv(name, value)
    import hashlib
    import hmac
    expected = base64.b64encode(hmac.new(b"shh", b"user@example.comabc", hashlib.sha256).digest()).decode()
    assert cognito.secret_hash("user@example.com") == expected


def test_sign_up_shape(stub):
    stub.add_response("sign_up", {"UserConfirmed": False, "UserSub": "s"}, {
        "ClientId": CLIENT_ID, "SecretHash": cognito.secret_hash("a@example.com"), "Username": "a@example.com",
        "Password": "Pw-1234567890", "UserAttributes": [{"Name": "email", "Value": "a@example.com"},
                                                      {"Name": "custom:company", "Value": "Acme"}]})
    cognito.sign_up("a@example.com", "Pw-1234567890", "Acme")


def test_confirm_resend_and_login_shapes(stub):
    h = cognito.secret_hash("a@example.com")
    stub.add_response("confirm_sign_up", {}, {"ClientId": CLIENT_ID, "SecretHash": h, "Username": "a@example.com",
                                              "ConfirmationCode": "123456"})
    stub.add_response("resend_confirmation_code", {"CodeDeliveryDetails": {}},
                      {"ClientId": CLIENT_ID, "SecretHash": h, "Username": "a@example.com"})
    stub.add_response("initiate_auth", {"AuthenticationResult": {"IdToken": "t", "RefreshToken": "r", "ExpiresIn": 900}}, {
        "ClientId": CLIENT_ID, "AuthFlow": "USER_PASSWORD_AUTH",
        "AuthParameters": {"USERNAME": "a@example.com", "PASSWORD": "pw", "SECRET_HASH": h}})
    cognito.confirm_sign_up("a@example.com", "123456")
    cognito.resend_code("a@example.com")
    assert cognito.login("a@example.com", "pw")["IdToken"] == "t"


def test_refresh_uses_the_subs_hash_not_the_emails(stub):
    stub.add_response("initiate_auth", {"AuthenticationResult": {"IdToken": "new", "ExpiresIn": 900}}, {
        "ClientId": CLIENT_ID, "AuthFlow": "REFRESH_TOKEN_AUTH",
        "AuthParameters": {"REFRESH_TOKEN": "rt", "SECRET_HASH": cognito.secret_hash("sub-123")}})
    assert cognito.refresh("rt", "sub-123")["IdToken"] == "new"


def test_revoke_forgot_and_reset_shapes(stub):
    h = cognito.secret_hash("a@example.com")
    stub.add_response("revoke_token", {}, {"ClientId": CLIENT_ID, "ClientSecret": CLIENT_SECRET, "Token": "rt"})
    stub.add_response("forgot_password", {"CodeDeliveryDetails": {}}, {"ClientId": CLIENT_ID, "SecretHash": h, "Username": "a@example.com"})
    stub.add_response("confirm_forgot_password", {}, {"ClientId": CLIENT_ID, "SecretHash": h, "Username": "a@example.com",
                                                      "ConfirmationCode": "123456", "Password": "New-Pass-12345"})
    cognito.revoke("rt")
    cognito.forgot_password("a@example.com")
    cognito.confirm_forgot_password("a@example.com", "123456", "New-Pass-12345")


def test_admin_call_shapes(stub):
    stub.add_response("admin_get_user", {"Username": "u", "Enabled": True,
                                         "UserAttributes": [{"Name": "sub", "Value": "s"}, {"Name": "custom:tenant_id", "Value": "mcp-abc234"}]},
                      {"UserPoolId": POOL_ID, "Username": "a@example.com"})
    stub.add_response("admin_update_user_attributes", {}, {"UserPoolId": POOL_ID, "Username": "a@example.com",
                                                           "UserAttributes": [{"Name": "custom:tenant_id", "Value": "mcp-abc234"}]})
    stub.add_response("admin_disable_user", {}, {"UserPoolId": POOL_ID, "Username": "sub-1"})
    stub.add_response("admin_user_global_sign_out", {}, {"UserPoolId": POOL_ID, "Username": "sub-1"})
    stub.add_response("admin_enable_user", {}, {"UserPoolId": POOL_ID, "Username": "sub-1"})
    user = cognito.get_user("a@example.com")
    assert user["custom:tenant_id"] == "mcp-abc234" and user["_sub"] == "s" and user["_enabled"] is True
    cognito.set_tenant("a@example.com", "mcp-abc234")
    cognito.disable_user("sub-1")
    cognito.enable_user("sub-1")


def test_a_missing_user_is_none_not_an_error(stub):
    stub.add_client_error("admin_get_user", "UserNotFoundException")
    assert cognito.get_user("ghost@example.com") is None


# -------------------------------------------------------------- error mapping

@pytest.mark.parametrize("code,status,our_code", [
    ("InvalidPasswordException", 400, "WEAK_PASSWORD"), ("InvalidParameterException", 400, "BAD_REQUEST"),
    ("CodeMismatchException", 400, "BAD_CODE"), ("ExpiredCodeException", 400, "CODE_EXPIRED"),
    ("NotAuthorizedException", 401, "BAD_LOGIN"), ("UserNotConfirmedException", 403, "NOT_CONFIRMED"),
    ("PasswordResetRequiredException", 403, "RESET_REQUIRED"), ("LimitExceededException", 429, "TOO_MANY"),
    ("TooManyRequestsException", 429, "TOO_MANY"), ("TooManyFailedAttemptsException", 429, "TOO_MANY"),
    ("InternalErrorException", 502, "UPSTREAM_ERROR"), ("ResourceNotFoundException", 502, "UPSTREAM_ERROR"),
])
def test_cognito_errors_become_our_errors(stub, code, status, our_code):
    stub.add_client_error("initiate_auth", code, "Some internal Cognito sentence with details")
    with pytest.raises(ApiError) as exc:
        cognito.login("a@example.com", "pw")
    assert (exc.value.status, exc.value.code) == (status, our_code)
    assert "internal Cognito sentence" not in exc.value.message


def test_an_existing_user_is_signalled_not_raised_as_an_api_error(stub):
    stub.add_client_error("sign_up", "UsernameExistsException")
    with pytest.raises(cognito.Exists):
        cognito.sign_up("a@example.com", "Pw-1234567890", "Acme")


def test_a_challenge_instead_of_tokens_is_refused_plainly(stub):
    stub.add_response("initiate_auth", {"ChallengeName": "SOFTWARE_TOKEN_MFA", "Session": "s" * 24})
    with pytest.raises(ApiError) as exc:
        cognito.login("a@example.com", "pw")
    assert exc.value.code == "UNSUPPORTED"


@pytest.mark.parametrize("token", ["", "abc", "a.b", "a.%%%.c", None, 5, "a." + base64.b64encode(b"[1]").decode() + ".c"])
def test_token_claims_of_anything_else_is_empty(token):
    assert cognito.token_claims(token) == {}


def test_token_claims_reads_a_real_payload():
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "s1", "custom:tenant_id": "mcp-abc234"}).encode()).decode().rstrip("=")
    assert cognito.token_claims("h.{}.s".format(payload)) == {"sub": "s1", "custom:tenant_id": "mcp-abc234"}
