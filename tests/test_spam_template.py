"""template.yml: the spam phrase table follows the project's table conventions and only the contact function can
read it (and only read)."""
import pytest

from conftest import load_template


@pytest.fixture(scope="module")
def template():
    return load_template()


def test_the_table_follows_the_conventions(template):
    resource = template["Resources"]["SpamPhraseTable"]
    props = resource["Properties"]
    assert resource["DeletionPolicy"] == "Retain" and resource["UpdateReplacePolicy"] == "Retain"
    assert props["TableName"] == "mcp_spam_phrase" and props["BillingMode"] == "PAY_PER_REQUEST"
    assert props["PointInTimeRecoverySpecification"] == {"PointInTimeRecoveryEnabled": True}
    assert props["KeySchema"] == [{"AttributeName": "scope", "KeyType": "HASH"},
                                  {"AttributeName": "name", "KeyType": "RANGE"}]
    assert {a["AttributeName"]: a["AttributeType"] for a in props["AttributeDefinitions"]} == {"scope": "S", "name": "S"}


def test_the_table_name_reaches_every_function_as_spam_table(template):
    assert template["Globals"]["Function"]["Environment"]["Variables"]["SPAM_TABLE"] == "SpamPhraseTable"


def statements(function):
    return [s for p in function["Properties"].get("Policies", []) for s in p.get("Statement", [])]


def test_only_the_contact_function_may_touch_the_table_and_only_to_query_it(template):
    for name, resource in template["Resources"].items():
        if resource["Type"] != "AWS::Serverless::Function":
            continue
        grants = [s for s in statements(resource) if "SpamPhraseTable" in str(s.get("Resource"))]
        if name == "ContactFunction":
            assert len(grants) == 1 and grants[0]["Action"] == "dynamodb:Query" and grants[0]["Effect"] == "Allow"
        else:
            assert grants == [], name
