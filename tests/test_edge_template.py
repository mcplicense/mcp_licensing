"""edge.yml puts CloudFront and WAF in front of the API. These tests pin the
properties that make that protection real, so an edit cannot quietly weaken it."""
import pytest

from conftest import load_template
from core.http import ORIGIN_HEADER

ZONE_OF_CLOUDFRONT = "Z2FDTNDATAQYW2"
CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
ALL_VIEWER_EXCEPT_HOST = "b689b0a8-53d0-40ab-baf2-68738e2966ac"


@pytest.fixture(scope="module")
def edge():
    return load_template("edge.yml")


@pytest.fixture(scope="module")
def app():
    return load_template("template.yml")


def _resources(template, type_name):
    return {k: v["Properties"] for k, v in template["Resources"].items() if v["Type"] == type_name}


def _acl(edge):
    (acl,) = _resources(edge, "AWS::WAFv2::WebACL").values()
    return acl


def _rules(edge):
    return {rule["Name"]: rule for rule in _acl(edge)["Rules"]}


def _distribution(edge):
    (dist,) = _resources(edge, "AWS::CloudFront::Distribution").values()
    return dist["DistributionConfig"]


# ----------------------------------------------------------------------- WAF

def test_web_acl_is_cloudfront_scoped_and_allows_by_default(edge):
    acl = _acl(edge)
    assert acl["Scope"] == "CLOUDFRONT"
    assert acl["DefaultAction"] == {"Allow": {}}


def test_rate_rules_limit_per_ip_over_five_minutes(edge):
    rules = _rules(edge)
    expected = {"rate-verify": "VerifyRateLimit", "rate-admin": "AdminRateLimit",
                "rate-super": "SuperRateLimit", "rate-overall": "OverallRateLimit",
                "rate-site": "SiteRateLimit"}
    for name, param in expected.items():
        rate = rules[name]["Statement"]["RateBasedStatement"]
        assert rate["AggregateKeyType"] == "IP"
        assert rate["EvaluationWindowSec"] == 300
        assert rate["Limit"] == param


def test_default_limits(edge):
    params = edge["Parameters"]
    assert params["VerifyRateLimit"]["Default"] == 600
    assert params["AdminRateLimit"]["Default"] == 100
    assert params["SuperRateLimit"]["Default"] == 50
    assert params["OverallRateLimit"]["Default"] == 2000
    assert params["SiteRateLimit"]["Default"] == 600
    for name in ("VerifyRateLimit", "AdminRateLimit", "SuperRateLimit", "OverallRateLimit", "SiteRateLimit"):
        assert params[name]["MinValue"] >= 10  # WAF's own minimum


def test_each_path_rule_only_counts_its_own_prefix(edge):
    rules = _rules(edge)
    for name, prefix in {"rate-verify": "/v1/mcp/", "rate-admin": "/v1/admin/",
                         "rate-super": "/v1/super/"}.items():
        match = rules[name]["Statement"]["RateBasedStatement"]["ScopeDownStatement"]["ByteMatchStatement"]
        assert match["SearchString"] == prefix
        assert match["PositionalConstraint"] == "STARTS_WITH"
        assert match["FieldToMatch"] == {"UriPath": {}}


def test_the_api_and_the_website_have_separate_per_ip_budgets(edge):
    """The website shares this web ACL, so rate-overall counts /v1/ only and
    rate-site counts everything else: browsing the docs cannot use up the
    budget that an office's MCP tools need."""
    rules = _rules(edge)
    overall = rules["rate-overall"]["Statement"]["RateBasedStatement"]["ScopeDownStatement"]["ByteMatchStatement"]
    assert overall["SearchString"] == "/v1/" and overall["PositionalConstraint"] == "STARTS_WITH"
    site = rules["rate-site"]["Statement"]["RateBasedStatement"]["ScopeDownStatement"]["NotStatement"]
    inner = site["Statement"]["ByteMatchStatement"]
    assert inner["SearchString"] == "/v1/" and inner["PositionalConstraint"] == "STARTS_WITH"


def test_rate_rules_block_with_429_not_403(edge):
    """The client helper treats a plain 403 as a license decision, so a shared
    office address that hits a limit must get a 429 instead."""
    acl = _acl(edge)
    for name, rule in _rules(edge).items():
        if not name.startswith("rate-"):
            continue
        response = rule["Action"]["Block"]["CustomResponse"]
        assert response["ResponseCode"] == 429
        assert response["CustomResponseBodyKey"] in acl["CustomResponseBodies"]


def test_managed_rule_groups_start_in_count_mode(edge):
    assert edge["Parameters"]["ManagedRulesMode"]["Default"] == "Count"
    assert edge["Parameters"]["ManagedRulesMode"]["AllowedValues"] == ["Count", "Block"]
    managed = {n: r for n, r in _rules(edge).items() if "ManagedRuleGroupStatement" in r["Statement"]}
    assert sorted(r["Statement"]["ManagedRuleGroupStatement"]["Name"] for r in managed.values()) == [
        "AWSManagedRulesAmazonIpReputationList",
        "AWSManagedRulesCommonRuleSet",
        "AWSManagedRulesKnownBadInputsRuleSet",
    ]
    for rule in managed.values():
        # collapsed !If: [condition, value when Block, value when Count]
        assert rule["OverrideAction"] == ["ManagedBlocks", {"None": {}}, {"Count": {}}]


def test_rule_priorities_are_unique(edge):
    priorities = [r["Priority"] for r in _acl(edge)["Rules"]]
    assert len(priorities) == len(set(priorities))


def test_waf_log_hides_credentials(edge):
    (logging,) = _resources(edge, "AWS::WAFv2::LoggingConfiguration").values()
    redacted = {f["SingleHeader"]["Name"] for f in logging["RedactedFields"]}
    assert redacted == {"x-tenant-api-key", ORIGIN_HEADER.lower()}
    (group,) = _resources(edge, "AWS::Logs::LogGroup").values()
    assert group["LogGroupName"].startswith("aws-waf-logs-")  # WAF only writes to groups with this prefix


# ---------------------------------------------------------------- CloudFront

def test_distribution_is_protected_by_the_web_acl(edge):
    assert _distribution(edge)["WebACLId"] == "WebAcl.Arn"


def test_distribution_sends_the_origin_secret_the_lambda_checks(edge):
    (origin,) = _distribution(edge)["Origins"]
    (header,) = origin["OriginCustomHeaders"]
    assert header["HeaderName"] == ORIGIN_HEADER
    assert header["HeaderValue"] == "OriginSecret"


def test_traffic_is_https_only_on_both_legs(edge):
    dist = _distribution(edge)
    assert dist["DefaultCacheBehavior"]["ViewerProtocolPolicy"] == "https-only"
    (origin,) = dist["Origins"]
    assert origin["CustomOriginConfig"]["OriginProtocolPolicy"] == "https-only"
    assert dist["ViewerCertificate"]["MinimumProtocolVersion"].startswith("TLSv1.2")
    assert dist["ViewerCertificate"]["SslSupportMethod"] == "sni-only"


def test_nothing_is_cached_and_the_api_key_header_is_forwarded(edge):
    behavior = _distribution(edge)["DefaultCacheBehavior"]
    assert behavior["CachePolicyId"] == CACHING_DISABLED
    assert behavior["OriginRequestPolicyId"] == ALL_VIEWER_EXCEPT_HOST
    assert {"GET", "POST", "PUT", "PATCH", "DELETE"} <= set(behavior["AllowedMethods"])


def test_origin_is_the_api_stage(edge):
    (origin,) = _distribution(edge)["Origins"]
    assert origin["DomainName"] == "${ApiId}.execute-api.${ApiRegion}.amazonaws.com"
    assert origin["OriginPath"] == "/${Stage}"


# ------------------------------------------------------------ DNS and TLS

def test_certificate_is_validated_through_dns_in_the_hosted_zone(edge):
    (cert,) = _resources(edge, "AWS::CertificateManager::Certificate").values()
    assert cert["ValidationMethod"] == "DNS"
    assert cert["DomainValidationOptions"] == [{"DomainName": "DomainName", "HostedZoneId": "HostedZoneId"}]


def test_dns_points_both_ipv4_and_ipv6_at_cloudfront(edge):
    records = _resources(edge, "AWS::Route53::RecordSet").values()
    assert sorted(r["Type"] for r in records) == ["A", "AAAA"]
    for record in records:
        assert record["Name"] == "DomainName"
        assert record["AliasTarget"]["HostedZoneId"] == ZONE_OF_CLOUDFRONT
        assert record["AliasTarget"]["DNSName"] == "Distribution.DomainName"


def test_domain_is_a_parameter_not_hardcoded(edge):
    assert "Default" not in edge["Parameters"]["DomainName"]
    assert "Default" not in edge["Parameters"]["HostedZoneId"]


# --------------------------------------------------------------------- secret

def test_origin_secret_is_hidden_and_long_in_both_templates(edge, app):
    assert edge["Parameters"]["OriginSecret"]["NoEcho"] is True
    assert edge["Parameters"]["OriginSecret"]["MinLength"] >= 32
    assert "Default" not in edge["Parameters"]["OriginSecret"]
    for name in ("OriginSecret", "OriginSecretPrevious"):
        assert app["Parameters"][name]["NoEcho"] is True


def test_the_api_stack_cannot_be_deployed_to_prod_without_the_secret(app):
    rule = app["Rules"]["ProdNeedsOriginSecret"]
    assert rule["RuleCondition"] == ["Stage", "prod"]               # !Equals [!Ref Stage, prod]
    (assertion,) = rule["Assertions"]
    assert assertion["Assert"] == [["OriginSecret", ""]]            # !Not [!Equals [!Ref OriginSecret, '']]


def test_lambdas_receive_the_secrets_as_environment(app):
    env = app["Globals"]["Function"]["Environment"]["Variables"]
    assert env["ORIGIN_SECRET"] == "OriginSecret"
    assert env["ORIGIN_SECRET_PREVIOUS"] == "OriginSecretPrevious"


# --------------------------------------------------------------------- alarms

def test_alarms_exist_and_notify(edge):
    alarms = _resources(edge, "AWS::CloudWatch::Alarm")
    assert {a["MetricName"] for a in alarms.values()} == {"Requests", "5xxErrorRate"}
    for alarm in alarms.values():
        assert alarm["AlarmActions"] == ["AlarmTopic"]
        assert alarm["Namespace"] == "AWS/CloudFront"


def test_the_contact_form_has_its_own_per_ip_backstop(edge):
    """WAF cannot count to 3 and lock for 30 minutes (its minimum is 10, its longest window 10
    minutes), so it is only a backstop here: the Lambda enforces the real rule."""
    rule = _rules(edge)["rate-contact"]
    rate = rule["Statement"]["RateBasedStatement"]
    assert rate["Limit"] == "ContactRateLimit" and rate["AggregateKeyType"] == "IP"
    assert rate["EvaluationWindowSec"] == 600
    match = rate["ScopeDownStatement"]["ByteMatchStatement"]
    assert match["SearchString"] == "/v1/site/contact" and match["PositionalConstraint"] == "EXACTLY"
    params = edge["Parameters"]["ContactRateLimit"]
    assert params["Default"] == 10 and params["MinValue"] >= 10
    assert rule["Action"]["Block"]["CustomResponse"]["ResponseCode"] == 429


def test_sign_up_and_the_console_have_their_own_per_ip_backstops(edge):
    """WAF's minimum limit is 10 and its longest window 10 minutes, so it only backstops the exact limits
    (3 sign-ups then a 30-minute lock, per-address caps, per-tenant rates) that the Lambdas enforce."""
    rules = _rules(edge)
    for name, prefix, param, default in (("rate-portal", "/v1/portal/", "PortalRateLimit", 60),
                                         ("rate-console", "/v1/console/", "ConsoleRateLimit", 600)):
        rate = rules[name]["Statement"]["RateBasedStatement"]
        assert rate["Limit"] == param and rate["AggregateKeyType"] == "IP" and rate["EvaluationWindowSec"] == 300
        match = rate["ScopeDownStatement"]["ByteMatchStatement"]
        assert match["SearchString"] == prefix and match["PositionalConstraint"] == "STARTS_WITH"
        assert edge["Parameters"][param]["Default"] == default and edge["Parameters"][param]["MinValue"] >= 10
        assert rules[name]["Action"]["Block"]["CustomResponse"]["ResponseCode"] == 429
