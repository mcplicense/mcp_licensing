"""site.yml serves the website from a private bucket through CloudFront. These
tests pin what keeps it private, encrypted, and under the same WAF as the API."""
import json
import shutil
import subprocess

import pytest

from conftest import load_template

ZONE_OF_CLOUDFRONT = "Z2FDTNDATAQYW2"


@pytest.fixture(scope="module")
def site():
    return load_template("site.yml")


def resources(template, type_name):
    return {k: v for k, v in template["Resources"].items() if v["Type"] == type_name}


def one(template, type_name):
    (found,) = resources(template, type_name).values()
    return found["Properties"]


# ------------------------------------------------------------------- bucket

def test_bucket_is_private_encrypted_and_versioned(site):
    (name, bucket), = resources(site, "AWS::S3::Bucket").items()
    props = bucket["Properties"]
    assert props["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": True, "BlockPublicPolicy": True,
        "IgnorePublicAcls": True, "RestrictPublicBuckets": True}
    assert props["OwnershipControls"]["Rules"] == [{"ObjectOwnership": "BucketOwnerEnforced"}]
    assert props["BucketEncryption"]["ServerSideEncryptionConfiguration"][0][
        "ServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"
    assert props["VersioningConfiguration"] == {"Status": "Enabled"}
    assert "WebsiteConfiguration" not in props and "AccessControl" not in props
    assert bucket["DeletionPolicy"] == "Retain"  # a stack delete must not fail on, or lose, the content


def test_only_this_distribution_may_read_the_bucket(site):
    policy = one(site, "AWS::S3::BucketPolicy")["PolicyDocument"]
    allows = {s["Action"]: s for s in policy["Statement"] if s["Effect"] == "Allow"}
    assert set(allows) == {"s3:GetObject", "s3:ListBucket"}  # read objects, and list so a missing file is a 404
    for allow in allows.values():  # both only for this distribution; never a write, never public
        assert allow["Principal"] == {"Service": "cloudfront.amazonaws.com"}
        assert allow["Condition"] == {"StringEquals": {
            "AWS:SourceArn": "arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:distribution/${Distribution}"}}
    assert allows["s3:GetObject"]["Resource"] == "${SiteBucket.Arn}/*"
    assert allows["s3:ListBucket"]["Resource"] == "SiteBucket.Arn"  # the bucket itself, not its objects


def test_the_bucket_refuses_unencrypted_transport(site):
    policy = one(site, "AWS::S3::BucketPolicy")["PolicyDocument"]
    deny = [s for s in policy["Statement"] if s["Effect"] == "Deny"]
    assert any(s["Condition"] == {"Bool": {"aws:SecureTransport": "false"}} for s in deny)


def test_origin_access_control_signs_every_request(site):
    config = one(site, "AWS::CloudFront::OriginAccessControl")["OriginAccessControlConfig"]
    assert config["OriginAccessControlOriginType"] == "s3"
    assert config["SigningBehavior"] == "always" and config["SigningProtocol"] == "sigv4"


# --------------------------------------------------------------- CloudFront

def distribution(site):
    return one(site, "AWS::CloudFront::Distribution")["DistributionConfig"]


def test_the_website_sits_behind_the_same_web_acl_as_the_api(site):
    assert distribution(site)["WebACLId"] == "WebAclArn"
    assert "Default" not in site["Parameters"]["WebAclArn"]  # it must be passed, from edge.yml


def test_https_only_modern_tls_and_read_only_methods(site):
    dist = distribution(site)
    behavior = dist["DefaultCacheBehavior"]
    assert behavior["ViewerProtocolPolicy"] == "redirect-to-https"
    assert set(behavior["AllowedMethods"]) <= {"GET", "HEAD", "OPTIONS"}
    assert dist["ViewerCertificate"]["MinimumProtocolVersion"].startswith("TLSv1.2")
    assert dist["ViewerCertificate"]["SslSupportMethod"] == "sni-only"
    assert behavior["Compress"] is True


def origins(site):
    return {o["Id"]: o for o in distribution(site)["Origins"]}


def test_the_default_origin_is_the_bucket_through_origin_access_control(site):
    assert distribution(site)["DefaultCacheBehavior"]["TargetOriginId"] == "site"
    origin = origins(site)["site"]
    assert origin["DomainName"] == "SiteBucket.RegionalDomainName"
    assert origin["OriginAccessControlId"] == "OriginAccessControl.Id"
    assert origin["S3OriginConfig"] == {"OriginAccessIdentity": ""}


def behaviors(site):
    return {b["PathPattern"]: b for b in distribution(site)["CacheBehaviors"]}


def test_only_the_websites_own_api_paths_reach_the_api(site):
    """The API is reachable from the website's domain through exactly three path patterns (the contact form,
    sign-up and login, and the signed-in console), so the API-key routes, the verify route and the platform's
    super routes can never be called from here."""
    found = behaviors(site)
    assert set(found) == {"/v1/site/*", "/v1/portal/*", "/v1/console/*"}
    for pattern, behavior in found.items():
        assert behavior["TargetOriginId"] == "api"
        assert behavior["ViewerProtocolPolicy"] == "https-only"          # a redirect would turn a POST into a GET
        assert {"POST", "GET"} <= set(behavior["AllowedMethods"])
        assert behavior["CachePolicyId"] == "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"  # nothing cached
        assert behavior["ResponseHeadersPolicyId"] == "SecurityHeaders"
        assert "FunctionAssociations" not in behavior  # the page-rewrite function must not touch API paths
    for forbidden in ("/v1/admin", "/v1/super", "/v1/mcp", "/v1/*", "/*"):
        assert not [p for p in found if p.startswith(forbidden)], forbidden


def test_the_api_origin_is_https_only_and_carries_the_origin_secret(site):
    origin = origins(site)["api"]
    assert origin["DomainName"] == "${ApiId}.execute-api.${ApiRegion}.amazonaws.com"
    assert origin["OriginPath"] == "/${Stage}"
    assert origin["CustomOriginConfig"]["OriginProtocolPolicy"] == "https-only"
    assert origin["OriginCustomHeaders"] == [{"HeaderName": "X-Origin-Verify", "HeaderValue": "OriginSecret"}]
    params = site["Parameters"]["OriginSecret"]
    assert params["NoEcho"] is True and params["MinLength"] >= 32 and "Default" not in params


def request_policy(site, name):
    return site["Resources"][name]["Properties"]["OriginRequestPolicyConfig"]


def test_each_api_path_gets_only_what_it_needs(site):
    """No policy forwards Host (API Gateway would not recognise it) or the API-key header, and only the
    portal sees a cookie (and only the refresh cookie); only the console sees the ID token."""
    common = {"CloudFront-Viewer-Address", "Content-Type", "Origin", "Referer"}
    expected = {  # behaviour -> (policy, extra headers, cookies, query strings)
        "/v1/site/*": ("ApiOriginRequestPolicy", set(), {"CookieBehavior": "none"}, "none"),
        "/v1/portal/*": ("PortalOriginRequestPolicy", {"X-Requested-With"},
                         {"CookieBehavior": "whitelist", "Cookies": ["mcp_rt"]}, "none"),
        "/v1/console/*": ("ConsoleOriginRequestPolicy", {"X-Requested-With", "Authorization"},
                          {"CookieBehavior": "none"}, "all"),
    }
    for pattern, (name, extra, cookies, query) in expected.items():
        assert behaviors(site)[pattern]["OriginRequestPolicyId"] == name
        config = request_policy(site, name)
        assert config["HeadersConfig"]["HeaderBehavior"] == "whitelist"
        headers = set(config["HeadersConfig"]["Headers"])
        assert common <= headers and extra <= headers, pattern
        assert not headers & {"Host", "X-Tenant-Api-Key", "Cookie"}, pattern
        assert ("Authorization" in headers) == ("Authorization" in extra), pattern
        assert config["CookiesConfig"] == cookies, pattern
        assert config["QueryStringsConfig"] == {"QueryStringBehavior": query}, pattern


def test_both_names_are_served_and_covered_by_the_certificate(site):
    dist = distribution(site)
    assert dist["Aliases"] == ["DomainName", "www.${DomainName}"]
    cert = one(site, "AWS::CertificateManager::Certificate")
    assert cert["DomainName"] == "DomainName"
    assert cert["SubjectAlternativeNames"] == ["www.${DomainName}"]
    assert cert["ValidationMethod"] == "DNS"
    assert [o["DomainName"] for o in cert["DomainValidationOptions"]] == ["DomainName", "www.${DomainName}"]


def test_a_missing_page_gets_the_404_page_with_a_404_status(site):
    errors = {e["ErrorCode"]: e for e in distribution(site)["CustomErrorResponses"]}
    assert errors[404]["ResponseCode"] == 404 and errors[404]["ResponsePagePath"] == "/404.html"


def test_a_403_is_never_replaced_because_the_contact_form_answers_403_itself(site):
    """Custom error responses are per distribution. Mapping 403 (what S3 says about a missing file when it
    may not list the bucket) would also replace the contact Lambda's 403 pages with the site's 404 page."""
    assert 403 not in {e["ErrorCode"] for e in distribution(site)["CustomErrorResponses"]}


def test_dns_covers_both_names_over_ipv4_and_ipv6(site):
    records = [r["Properties"] for r in resources(site, "AWS::Route53::RecordSet").values()]
    assert sorted((r["Name"], r["Type"]) for r in records) == sorted([
        ("DomainName", "A"), ("DomainName", "AAAA"),
        ("www.${DomainName}", "A"), ("www.${DomainName}", "AAAA")])
    for record in records:
        assert record["AliasTarget"]["HostedZoneId"] == ZONE_OF_CLOUDFRONT
        assert record["AliasTarget"]["DNSName"] == "Distribution.DomainName"


# ----------------------------------------------------------- security headers

def headers(site):
    return one(site, "AWS::CloudFront::ResponseHeadersPolicy")["ResponseHeadersPolicyConfig"]


def test_the_content_security_policy_allows_only_scripts_from_this_site(site):
    csp = headers(site)["SecurityHeadersConfig"]["ContentSecurityPolicy"]
    policy = " ".join(csp["ContentSecurityPolicy"].split())
    directives = {d.split(" ", 1)[0]: d.split(" ", 1)[1] if " " in d else "" for d in policy.split("; ")}
    assert csp["Override"] is True
    assert directives["default-src"] == "'none'"
    assert directives["script-src"] == "'self'"      # files from this site: never inline, never another host
    assert directives["connect-src"] == "'self'"     # the pages may call back to this site (the portal and console)
    assert directives["style-src"] == "'self'" and directives["img-src"] == "'self'"
    assert directives["form-action"] == "'self'"
    assert directives["frame-ancestors"] == "'none'" and directives["base-uri"] == "'none'"
    assert not {"font-src", "frame-src", "object-src", "media-src", "worker-src"} & set(directives)  # all 'none' by default
    for weakening in ("unsafe-inline", "unsafe-eval", "unsafe-hashes", "*", "http:", "data:", "blob:", "https:"):
        assert weakening not in policy


def test_the_other_security_headers(site):
    security = headers(site)["SecurityHeadersConfig"]
    assert security["StrictTransportSecurity"]["AccessControlMaxAgeSec"] >= 31536000
    assert security["StrictTransportSecurity"]["IncludeSubdomains"] is True
    assert security["ContentTypeOptions"]["Override"] is True
    assert security["FrameOptions"]["FrameOption"] == "DENY"
    assert security["ReferrerPolicy"]["ReferrerPolicy"] == "strict-origin-when-cross-origin"
    (custom,) = headers(site)["CustomHeadersConfig"]["Items"]
    assert custom["Header"] == "Permissions-Policy" and "camera=()" in custom["Value"]
    assert distribution(site)["DefaultCacheBehavior"]["ResponseHeadersPolicyId"] == "SecurityHeaders"


# ------------------------------------------------- the rewrite function, run

@pytest.mark.skipif(not shutil.which("node"), reason="node is needed to run the CloudFront function")
def test_the_rewrite_function_does_what_the_site_needs(site, tmp_path):
    code = one(site, "AWS::CloudFront::Function")["FunctionCode"].replace("${DomainName}", "mcplicense.net")
    assert "${" not in code
    harness = tmp_path / "run.js"
    harness.write_text(code + """
const cases = [
  ["mcplicense.net", "/"], ["mcplicense.net", "/docs/"], ["mcplicense.net", "/docs"],
  ["mcplicense.net", "/style.css"], ["mcplicense.net", "/downloads/mcp_auth.py"],
  ["www.mcplicense.net", "/docs/"], ["d111111abcdef8.cloudfront.net", "/"], ["MCPLICENSE.NET", "/privacy/"],
];
console.log(JSON.stringify(cases.map(([host, uri]) => {
  const result = handler({ request: { uri, headers: { host: { value: host } } } });
  return result.statusCode ? [result.statusCode, result.headers.location.value] : [result.uri];
})));
""", encoding="utf-8")
    out = subprocess.run(["node", str(harness)], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout) == [
        ["/index.html"],                                  # the home page
        ["/docs/index.html"],                              # a folder serves its index
        [301, "https://mcplicense.net/docs/"],             # /docs gets its trailing slash
        ["/style.css"],                                    # files are untouched
        ["/downloads/mcp_auth.py"],
        [301, "https://mcplicense.net/docs/"],             # www goes to the main host, same path
        [301, "https://mcplicense.net/"],                  # the raw cloudfront.net name too
        ["/privacy/index.html"],                           # host names are case-insensitive
    ]
