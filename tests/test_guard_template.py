"""guard.yml: the spending alerts. Pins that the budget is monthly, in dollars, and emails at the thresholds."""
import pytest

from conftest import load_template


@pytest.fixture(scope="module")
def guard():
    return load_template("guard.yml")


def budget(template):
    (found,) = [r for r in template["Resources"].values() if r["Type"] == "AWS::Budgets::Budget"]
    return found["Properties"]


def test_it_is_a_monthly_cost_budget_in_dollars_with_a_limit_the_deployer_sets(guard):
    properties = budget(guard)["Budget"]
    assert properties["BudgetType"] == "COST" and properties["TimeUnit"] == "MONTHLY"
    assert properties["BudgetLimit"] == {"Amount": "MonthlyBudgetUsd", "Unit": "USD"}  # the loader renders !Ref X as "X"
    assert guard["Parameters"]["MonthlyBudgetUsd"]["MinValue"] == 1


def test_it_warns_at_half_and_four_fifths_of_actual_spend_and_when_the_forecast_passes_the_limit(guard):
    seen = {(n["Notification"]["NotificationType"], n["Notification"]["Threshold"], n["Notification"]["ThresholdType"],
             n["Notification"]["ComparisonOperator"]) for n in budget(guard)["NotificationsWithSubscribers"]}
    assert seen == {("ACTUAL", 50, "PERCENTAGE", "GREATER_THAN"), ("ACTUAL", 80, "PERCENTAGE", "GREATER_THAN"),
                    ("FORECASTED", 100, "PERCENTAGE", "GREATER_THAN")}


def test_every_notification_emails_the_alert_address_and_nobody_else(guard):
    for notification in budget(guard)["NotificationsWithSubscribers"]:
        assert notification["Subscribers"] == [{"SubscriptionType": "EMAIL", "Address": "AlertEmail"}]


def test_no_address_is_baked_into_the_template(guard):
    assert "AlertEmail" in guard["Parameters"] and "Default" not in guard["Parameters"]["AlertEmail"]
