"""scripts/emergency.py: what each level stops, that the platform function is never stopped, and that every
call matches the real Lambda API (a stubbed boto3 client validates the parameters against the service model)."""
import importlib.util
import pathlib

import boto3
import pytest
from botocore.stub import Stubber

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def emergency():
    spec = importlib.util.spec_from_file_location("emergency", ROOT / "scripts" / "emergency.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def lam():
    client = boto3.client("lambda", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    with Stubber(client) as stubber:
        yield client, stubber
        stubber.assert_no_pending_responses()


def expect_stop(stubber, shorts, stage="prod"):
    for short in shorts:
        stubber.add_response("put_function_concurrency", {"ReservedConcurrentExecutions": 0},
                             {"FunctionName": "mcp-licensing-{}-{}".format(stage, short), "ReservedConcurrentExecutions": 0})


@pytest.mark.parametrize("level,shorts", [
    ("signups", ["portal", "contact"]),
    ("console", ["portal", "contact", "admin"]),
    ("all", ["portal", "contact", "admin", "mcp"]),
])
def test_each_level_stops_exactly_its_functions(emergency, lam, level, shorts):
    client, stubber = lam
    expect_stop(stubber, shorts)
    rows = emergency.stop(client, "prod", level)
    assert rows == [(short, "stopped") for short in shorts]


def test_the_platform_function_is_never_stopped_at_any_level(emergency):
    for shorts in emergency.LEVELS.values():
        assert "super" not in shorts
    assert emergency.NEVER_STOPPED == ["super"]


def test_the_levels_grow_from_the_exposed_edge_inwards(emergency):
    assert set(emergency.LEVELS["signups"]) < set(emergency.LEVELS["console"]) < set(emergency.LEVELS["all"])


def test_resume_removes_the_limit_from_every_function_including_the_platform_one(emergency, lam):
    client, stubber = lam
    for short in ["portal", "contact", "admin", "mcp", "super"]:
        stubber.add_response("delete_function_concurrency", {}, {"FunctionName": "mcp-licensing-prod-" + short})
    rows = emergency.resume(client, "prod")
    assert [state for _, state in rows] == ["running"] * 5


def test_a_dry_run_makes_no_calls(emergency, lam):
    client, stubber = lam  # no responses queued: any call would raise
    assert emergency.stop(client, "prod", "all", dry_run=True) == [
        (short, "would stop") for short in ["portal", "contact", "admin", "mcp"]]
    assert emergency.resume(client, "prod", dry_run=True)[0] == ("portal", "would resume")


def test_status_tells_running_stopped_and_limited_apart(emergency, lam):
    client, stubber = lam
    for answer in ({"ReservedConcurrentExecutions": 0}, {}, {"ReservedConcurrentExecutions": 5}, {}, {}):
        stubber.add_response("get_function_concurrency", answer)
    assert emergency.status(client, "prod") == [
        ("portal", "STOPPED"), ("contact", "running"), ("admin", "limited to 5"), ("mcp", "running"), ("super", "running")]


def test_a_missing_function_is_reported_and_the_rest_are_still_stopped(emergency, lam):
    client, stubber = lam
    stubber.add_client_error("put_function_concurrency", "ResourceNotFoundException")
    expect_stop(stubber, ["contact"])
    assert emergency.stop(client, "prod", "signups") == [
        ("portal", "ERROR ResourceNotFoundException"), ("contact", "stopped")]


def test_the_stage_is_part_of_the_function_name(emergency, lam):
    client, stubber = lam
    expect_stop(stubber, ["portal", "contact"], stage="dev")
    emergency.stop(client, "dev", "signups")


def test_the_command_line_exit_codes_and_the_level_is_required(emergency, lam, capsys):
    client, stubber = lam
    with pytest.raises(SystemExit) as exc:
        emergency.main(["stop"], client=client)
    assert exc.value.code == 2
    expect_stop(stubber, ["portal", "contact"])
    assert emergency.main(["stop", "--level", "signups"], client=client) == 0
    out = capsys.readouterr().out
    assert "portal" in out and "resume" in out
    stubber.add_client_error("get_function_concurrency", "AccessDeniedException")
    for _ in range(4):
        stubber.add_response("get_function_concurrency", {})
    assert emergency.main(["status"], client=client) == 1
