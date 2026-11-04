"""The user pool, its client, the token check on the console routes, and who may touch what.

Some pool settings cannot be changed after creation: CloudFormation answers an edit to them by
REPLACING the pool, which deletes every user. These tests pin them, so an edit that would do that
fails here, in a pull request, and not in production."""
import pytest

from conftest import load_template
from handlers import portal


@pytest.fixture(scope="module")
def t():
    return load_template("template.yml")


def resource(t, name):
    return t["Resources"][name]


def props(t, name):
    return t["Resources"][name]["Properties"]


def statements(t, function):
    return props(t, function)["Policies"][0]["Statement"]


def actions(t, function):
    found = []
    for statement in statements(t, function):
        found += [statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]
    return set(found)


# ------------------------------------------------------------------ the pool

def test_the_pool_cannot_be_deleted_or_replaced_by_accident(t):
    pool = resource(t, "UserPool")
    assert pool["DeletionPolicy"] == "Retain" and pool["UpdateReplacePolicy"] == "Retain"
    assert pool["Properties"]["DeletionProtection"] == "ACTIVE"


def test_settings_that_force_a_replacement_are_pinned(t):
    """Changing any of these replaces the pool. If you must, plan a migration; do not just edit."""
    pool = props(t, "UserPool")
    assert pool["UsernameAttributes"] == ["email"]
    assert pool["UsernameConfiguration"] == {"CaseSensitive": False}
    schema = {a["Name"]: a for a in pool["Schema"]}
    assert list(schema) == ["email", "tenant_id", "company"]
    assert schema["email"]["Required"] is True and schema["email"]["AttributeDataType"] == "String"
    for name, longest in (("tenant_id", "32"), ("company", "200")):
        assert schema[name]["AttributeDataType"] == "String" and schema[name]["Mutable"] is True
        assert schema[name]["StringAttributeConstraints"] == {"MinLength": "0", "MaxLength": longest}


def test_people_sign_in_with_a_confirmed_email_and_choose_a_strong_password(t):
    pool = props(t, "UserPool")
    assert pool["AutoVerifiedAttributes"] == ["email"]
    policy = pool["Policies"]["PasswordPolicy"]
    assert policy["MinimumLength"] >= 12
    assert policy["RequireLowercase"] and policy["RequireUppercase"] and policy["RequireNumbers"]
    assert pool["AccountRecoverySetting"]["RecoveryMechanisms"] == [{"Name": "verified_email", "Priority": 1}]


def test_anyone_may_sign_up_but_mfa_is_available(t):
    pool = props(t, "UserPool")
    assert pool["AdminCreateUserConfig"] == {"AllowAdminCreateUserOnly": False}  # self-service
    assert pool["MfaConfiguration"] == "OPTIONAL" and pool["EnabledMfas"] == ["SOFTWARE_TOKEN_MFA"]


def test_the_code_email_carries_the_code_and_a_plain_warning(t):
    template = props(t, "UserPool")["VerificationMessageTemplate"]
    assert template["DefaultEmailOption"] == "CONFIRM_WITH_CODE"
    assert "{####}" in template["EmailMessage"] and "ignore this email" in template["EmailMessage"]


def test_emails_go_out_through_ses_from_the_domain_when_one_is_configured(t):
    email = props(t, "UserPool")["EmailConfiguration"]
    assert email[0] == "UseSesEmail" and email[2] == "AWS::NoValue"  # empty EmailDomain falls back to Cognito's sender
    ses = email[1]
    assert ses["EmailSendingAccount"] == "DEVELOPER"
    assert ses["From"] == "MCP Licensing <no-reply@${EmailDomain}>"
    assert ses["SourceArn"].endswith(":identity/${EmailDomain}")
    assert t["Parameters"]["EmailDomain"]["Default"] == ""


# ----------------------------------------------------------------- the client

def test_only_the_portal_can_use_the_client_because_it_has_a_secret(t):
    client = props(t, "UserPoolClient")
    assert client["GenerateSecret"] is True
    assert set(client["ExplicitAuthFlows"]) == {"ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"}
    assert client["PreventUserExistenceErrors"] == "ENABLED"
    assert client["EnableTokenRevocation"] is True


def test_token_lifetimes_match_what_the_code_assumes(t):
    client = props(t, "UserPoolClient")
    assert (client["AccessTokenValidity"], client["IdTokenValidity"]) == (15, 15)
    assert client["TokenValidityUnits"] == {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "hours"}
    assert client["RefreshTokenValidity"] * 3600 == portal.REFRESH_SECONDS  # the cookie lives as long as the token


def test_a_user_cannot_write_their_own_tenant(t):
    client = props(t, "UserPoolClient")
    assert "custom:tenant_id" in client["ReadAttributes"] and "email_verified" in client["ReadAttributes"]
    assert "custom:tenant_id" not in client["WriteAttributes"]
    assert "email_verified" not in client["WriteAttributes"]  # nobody can mark their own address verified


# ------------------------------------------------------- the token check

def test_console_routes_check_the_id_token_and_nothing_else_does(t):
    authorizer = props(t, "HttpApi")["Auth"]["Authorizers"]["TenantJwt"]
    assert authorizer["IdentitySource"] == "$request.header.Authorization"
    assert authorizer["JwtConfiguration"]["audience"] == ["UserPoolClient"]
    assert authorizer["JwtConfiguration"]["issuer"] == "https://cognito-idp.${AWS::Region}.amazonaws.com/${UserPool}"
    assert "DefaultAuthorizer" not in props(t, "HttpApi")["Auth"]  # so no other route is changed

    with_auth, without = [], []
    for name, res in t["Resources"].items():
        if res["Type"] != "AWS::Serverless::Function":
            continue
        for event_name, event in res["Properties"]["Events"].items():
            ep = event["Properties"]
            (with_auth if "Auth" in ep else without).append((name, ep["Path"], ep.get("Auth")))
    assert with_auth and all(f == "AdminFunction" and path.startswith("/v1/console/") and auth == {"Authorizer": "TenantJwt"}
                             for f, path, auth in with_auth)
    assert not [path for _, path, _ in without if path.startswith("/v1/console/")]  # every console route is protected
    assert len(with_auth) == 15


# ------------------------------------------------------ who may touch what

def test_only_the_portal_holds_the_client_secret(t):
    holders = [n for n, r in t["Resources"].items() if r["Type"] == "AWS::Serverless::Function"
               and "USER_POOL_CLIENT_SECRET" in r["Properties"].get("Environment", {}).get("Variables", {})]
    assert holders == ["PortalFunction"]
    assert "USER_POOL_CLIENT_SECRET" not in t["Globals"]["Function"]["Environment"]["Variables"]
    assert props(t, "PortalFunction")["Environment"]["Variables"]["USER_POOL_CLIENT_SECRET"] == "UserPoolClient.ClientSecret"


def test_the_portal_can_create_a_tenant_and_nothing_more(t):
    assert actions(t, "PortalFunction") == {
        "ssm:GetParametersByPath", "sns:Publish", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
        "cognito-idp:AdminGetUser", "cognito-idp:AdminUpdateUserAttributes"}
    for statement in statements(t, "PortalFunction"):
        assert "*" not in str(statement["Resource"]).replace("/*", "")  # no open-ended resource
    tables = {str(s["Resource"]) for s in statements(t, "PortalFunction") if "dynamodb:PutItem" in s["Action"]}
    assert tables == {"TenantDetailTable.Arn", "RateCounterTable.Arn"}  # it cannot write licenses, keys or audit
    banned = next(s for s in statements(t, "PortalFunction") if s["Resource"] == "BannedEmailTable.Arn")
    assert banned["Action"] == "dynamodb:GetItem"  # it reads the ban list, it cannot edit it


def test_the_portal_routes_are_public_and_exactly_these(t):
    events = props(t, "PortalFunction")["Events"]
    assert {(e["Properties"]["Method"], e["Properties"]["Path"]) for e in events.values()} == {
        ("POST", "/v1/portal/" + name) for name in ("signup", "resend", "confirm", "login", "refresh", "logout", "forgot", "reset")}
    assert all("Auth" not in e["Properties"] for e in events.values())


def test_only_the_platform_function_can_disable_users_and_edit_the_ban_list(t):
    assert {a for a in actions(t, "SuperFunction") if a.startswith("cognito-idp")} == {
        "cognito-idp:AdminDisableUser", "cognito-idp:AdminEnableUser", "cognito-idp:AdminUserGlobalSignOut"}
    for function in ("AdminFunction", "McpFunction", "ContactFunction"):
        assert not {a for a in actions(t, function) if a.startswith("cognito-idp")}, function
        assert all("BannedEmailTable" not in str(s["Resource"]) for s in statements(t, function)), function


def test_the_cognito_permissions_name_this_pool_only(t):
    for function in ("PortalFunction", "SuperFunction"):
        for statement in statements(t, function):
            if any(a.startswith("cognito-idp") for a in ([statement["Action"]] if isinstance(statement["Action"], str)
                                                         else statement["Action"])):
                assert statement["Resource"] == "UserPool.Arn"


def test_the_ban_list_is_kept_and_recoverable(t):
    table = resource(t, "BannedEmailTable")
    assert table["DeletionPolicy"] == "Retain" and table["Properties"]["TableName"] == "mcp_banned_email"
    assert table["Properties"]["PointInTimeRecoverySpecification"]["PointInTimeRecoveryEnabled"] is True
    assert t["Globals"]["Function"]["Environment"]["Variables"]["BANNED_TABLE"] == "BannedEmailTable"


def test_the_functions_learn_the_pool_and_client_ids_but_nothing_secret(t):
    env = t["Globals"]["Function"]["Environment"]["Variables"]
    assert env["USER_POOL_ID"] == "UserPool" and env["USER_POOL_CLIENT_ID"] == "UserPoolClient"
    assert props(t, "PortalFunction")["Environment"]["Variables"]["NOTIFY_TOPIC_ARN"] == "ContactTopic"


def test_the_ids_are_outputs_for_the_site_stack_and_for_you(t):
    assert {"UserPoolId", "UserPoolClientId", "ApiId"} <= set(t["Outputs"])
