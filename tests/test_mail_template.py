"""mail.yml: sending identity, DNS, and the inbound rule that forwards mail to one
inbox. These tests pin what makes it safe and correctly authenticated."""
import importlib.util
import pathlib
import re

import pytest

from conftest import load_template

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULE_SET = "mcp-licensing-inbound"


@pytest.fixture(scope="module")
def mail():
    return load_template("mail.yml")


def resources(template, type_name):
    return {k: v for k, v in template["Resources"].items() if v["Type"] == type_name}


def one(template, type_name):
    (found,) = resources(template, type_name).values()
    return found["Properties"]


def records(template):
    return {name: r["Properties"] for name, r in resources(template, "AWS::Route53::RecordSet").items()}


def identities(template):
    return {name: r for name, r in resources(template, "AWS::SES::EmailIdentity").items()}


# -------------------------------------------------------------------- sending

def test_the_domain_signs_its_mail_with_a_2048_bit_dkim_key(mail):
    domain = identities(mail)["Identity"]["Properties"]
    assert domain["EmailIdentity"] == "DomainName"
    assert domain["DkimAttributes"] == {"SigningEnabled": True}
    assert domain["DkimSigningAttributes"]["NextSigningKeyLength"] == "RSA_2048_BIT"


def test_the_three_dkim_records_point_at_the_tokens_ses_issues(mail):
    recs = records(mail)
    for n in (1, 2, 3):
        record = recs["DkimRecord{}".format(n)]
        assert record["Type"] == "CNAME"
        assert record["Name"] == "Identity.DkimDNSTokenName{}".format(n)
        assert record["ResourceRecords"] == ["Identity.DkimDNSTokenValue{}".format(n)]


def test_spf_lines_up_through_a_mail_from_subdomain(mail):
    domain = identities(mail)["Identity"]["Properties"]
    assert domain["MailFromAttributes"]["MailFromDomain"] == "mail.${DomainName}"
    recs = records(mail)
    assert recs["MailFromMx"]["Name"] == "mail.${DomainName}" and recs["MailFromMx"]["Type"] == "MX"
    assert recs["MailFromMx"]["ResourceRecords"] == ["10 feedback-smtp.${AWS::Region}.amazonses.com"]
    for name in ("MailFromSpf", "DomainSpf"):
        assert recs[name]["Type"] == "TXT"
        assert recs[name]["ResourceRecords"] == ['"v=spf1 include:amazonses.com ~all"']


def test_dmarc_quarantines_unauthenticated_mail_and_publishes_no_address(mail):
    dmarc = records(mail)["Dmarc"]
    assert dmarc["Name"] == "_dmarc.${DomainName}" and dmarc["Type"] == "TXT"
    (value,) = dmarc["ResourceRecords"]
    assert "p=quarantine" in value and "pct=100" in value
    assert "rua=" not in value and "ruf=" not in value and "@" not in value  # no mailbox is advertised


# ------------------------------------------------------------------- receiving

def test_inbound_mail_is_routed_to_ses_in_this_region(mail):
    mx = records(mail)["InboundMx"]
    assert mx["Name"] == "DomainName" and mx["Type"] == "MX"
    assert mx["ResourceRecords"] == ["10 inbound-smtp.${AWS::Region}.amazonaws.com"]


def test_the_inbound_bucket_is_private_encrypted_and_short_lived(mail):
    ((name, bucket),) = resources(mail, "AWS::S3::Bucket").items()
    props = bucket["Properties"]
    assert props["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": True, "BlockPublicPolicy": True,
        "IgnorePublicAcls": True, "RestrictPublicBuckets": True}
    assert props["BucketEncryption"]["ServerSideEncryptionConfiguration"][0][
        "ServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"
    (rule,) = props["LifecycleConfiguration"]["Rules"]
    assert rule["ExpirationInDays"] == 30 and rule["Status"] == "Enabled"
    assert bucket["DeletionPolicy"] == "Retain"


def test_ses_may_only_store_messages_from_our_own_rule_set(mail):
    policy = one(mail, "AWS::S3::BucketPolicy")["PolicyDocument"]
    (allow,) = [s for s in policy["Statement"] if s["Effect"] == "Allow"]
    assert allow["Principal"] == {"Service": "ses.amazonaws.com"}
    assert allow["Action"] == "s3:PutObject"
    assert allow["Resource"] == "${InboundBucket.Arn}/inbound/*"
    assert allow["Condition"]["StringEquals"] == {"aws:SourceAccount": "AWS::AccountId"}
    assert allow["Condition"]["StringLike"]["aws:SourceArn"].endswith(
        "receipt-rule-set/{}:receipt-rule/*".format(RULE_SET))
    assert any(s["Effect"] == "Deny" and s["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
               for s in policy["Statement"])


def test_only_the_three_role_addresses_are_accepted_and_scanned(mail):
    rule = one(mail, "AWS::SES::ReceiptRule")["Rule"]
    assert rule["Recipients"] == ["support@${DomainName}", "abuse@${DomainName}", "postmaster@${DomainName}"]
    assert rule["ScanEnabled"] is True and rule["Enabled"] is True
    s3_action, lambda_action = rule["Actions"]  # store first, so a message is never lost if the Lambda fails
    assert s3_action["S3Action"]["ObjectKeyPrefix"] == "inbound/"
    assert lambda_action["LambdaAction"]["InvocationType"] == "Event"


def test_the_rule_set_name_is_the_same_everywhere_it_appears(mail):
    assert one(mail, "AWS::SES::ReceiptRuleSet")["RuleSetName"] == RULE_SET
    text = (ROOT / "mail.yml").read_text(encoding="utf-8")
    assert text.count("receipt-rule-set/" + RULE_SET) == 2  # bucket policy and invoke permission
    assert text.count("set-active-receipt-rule-set --rule-set-name " + RULE_SET) == 1
    rule_name = one(mail, "AWS::SES::ReceiptRule")["Rule"]["Name"]
    permission = one(mail, "AWS::Lambda::Permission")
    assert permission["SourceArn"].endswith("receipt-rule-set/{}:receipt-rule/{}".format(RULE_SET, rule_name))


def test_only_ses_in_this_account_may_invoke_the_forwarder(mail):
    permission = one(mail, "AWS::Lambda::Permission")
    assert permission["Principal"] == "ses.amazonaws.com"
    assert permission["SourceAccount"] == "AWS::AccountId"
    assert permission["Action"] == "lambda:InvokeFunction"


# ------------------------------------------------------------------ the function

def function(mail):
    return one(mail, "AWS::Serverless::Function")


def test_the_forwarder_can_read_only_inbound_mail_and_send_only_as_the_support_address(mail):
    statements = function(mail)["Policies"][0]["Statement"]
    read = next(s for s in statements if s["Action"] == "s3:GetObject")
    assert read["Resource"] == "${InboundBucket.Arn}/inbound/*"
    send = next(s for s in statements if s["Action"] == "ses:SendRawEmail")
    # sandbox SES authorises SendRawEmail on the sender's identity AND the recipient's: leaving the
    # inbox out made every forward fail with AccessDenied (found by the live test, which moto cannot do)
    assert [r.rsplit(":identity/", 1)[1] for r in send["Resource"]] == ["${DomainName}", "${ForwardTo}"]
    assert send["Condition"] == {"StringEquals": {"ses:FromAddress": "support@${DomainName}"}}
    assert len(statements) == 2  # nothing else


def test_the_forwarders_environment_matches_what_its_code_reads(mail):
    env = function(mail)["Environment"]["Variables"]
    assert env["FROM_ADDRESS"] == "support@${DomainName}"
    assert env["PREFIX"] == "inbound/" and env["FORWARD_TO"] == "ForwardTo" and env["BUCKET"] == "InboundBucket"
    source = (ROOT / "mail" / "forwarder.py").read_text(encoding="utf-8")
    read_by_code = set(re.findall(r'os\.environ(?:\.get)?[\[(]"([A-Z_]+)"', source))
    assert read_by_code == set(env)


def test_the_handler_and_code_location_exist(mail):
    props = function(mail)
    assert props["CodeUri"] == "mail/" and props["Handler"] == "forwarder.handler"
    spec = importlib.util.spec_from_file_location("forwarder", ROOT / "mail" / "forwarder.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert callable(module.handler)


def test_the_destination_is_given_at_deploy_time_and_never_stored_in_the_repo(mail):
    assert "Default" not in mail["Parameters"]["ForwardTo"]
    text = (ROOT / "mail.yml").read_text(encoding="utf-8")
    assert not re.search(r"[\w.+-]+@(?!\$\{)[\w-]+\.[a-z]{2,}", text), "an email address is written into mail.yml"


def test_a_forwarder_failure_raises_an_alarm(mail):
    alarm = one(mail, "AWS::CloudWatch::Alarm")
    assert alarm["MetricName"] == "Errors" and alarm["Namespace"] == "AWS/Lambda"
    assert alarm["AlarmActions"] == ["AlarmTopic"]
    assert one(mail, "AWS::SNS::Subscription")["Endpoint"] == "ForwardTo"


def test_the_sandbox_verification_is_optional_after_production_access(mail):
    assert mail["Parameters"]["VerifyForwardTo"]["AllowedValues"] == ["true", "false"]
    forward_identity = identities(mail)["ForwardToIdentity"]
    assert forward_identity["Condition"] == "VerifyForward"
    assert forward_identity["Properties"]["EmailIdentity"] == "ForwardTo"
