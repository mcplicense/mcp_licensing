"""scripts/seed_config.py creates the SSM settings and never overwrites yours."""
import importlib.util
import pathlib

import boto3
import pytest

from core import config

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "seed_config.py"


@pytest.fixture(scope="module")
def seed():
    spec = importlib.util.spec_from_file_location("seed_config", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(seed, monkeypatch, *argv):
    monkeypatch.setattr("sys.argv", ["seed_config.py", *argv])
    seed.main()


def params(prefix="/mcp/prod"):
    ssm = boto3.client("ssm")
    found = {}
    for page in ssm.get_paginator("get_parameters_by_path").paginate(Path=prefix, Recursive=True):
        for p in page["Parameters"]:
            found[p["Name"]] = p["Value"]
    return found


def test_every_setting_has_a_description(seed):
    assert set(seed.DESCRIPTIONS) == set(config.DEFAULTS)


def test_creates_every_default_under_the_stage_prefix(seed, monkeypatch):
    run(seed, monkeypatch, "--stage", "prod", "--region", "us-east-1")
    assert params() == {"/mcp/prod/" + k: v for k, v in config.DEFAULTS.items()}


def test_running_again_never_overwrites_a_value_you_set(seed, monkeypatch, capsys):
    run(seed, monkeypatch, "--stage", "prod", "--region", "us-east-1")
    boto3.client("ssm").put_parameter(Name="/mcp/prod/limit_seats_per_license", Value="25",
                                      Type="String", Overwrite=True)
    capsys.readouterr()
    run(seed, monkeypatch, "--stage", "prod", "--region", "us-east-1")
    assert params()["/mcp/prod/limit_seats_per_license"] == "25"
    assert "created" not in capsys.readouterr().out  # nothing was missing


def test_a_setting_added_by_a_later_release_is_created_on_rerun(seed, monkeypatch):
    run(seed, monkeypatch, "--stage", "prod", "--region", "us-east-1")
    boto3.client("ssm").delete_parameter(Name="/mcp/prod/limit_api_keys_per_tenant")
    run(seed, monkeypatch, "--stage", "prod", "--region", "us-east-1")
    assert params()["/mcp/prod/limit_api_keys_per_tenant"] == config.DEFAULTS["limit_api_keys_per_tenant"]


def test_tenant_overrides(seed, monkeypatch):
    run(seed, monkeypatch, "--stage", "prod", "--region", "us-east-1", "--tenant", "sfs",
        "limit_seats_per_license=100", "limit_verify_per_min=300")
    found = params()
    assert found["/mcp/prod/tenants/sfs/limit_seats_per_license"] == "100"
    assert found["/mcp/prod/tenants/sfs/limit_verify_per_min"] == "300"
    # a change of mind overwrites: this is you saying what you want
    run(seed, monkeypatch, "--stage", "prod", "--region", "us-east-1", "--tenant", "sfs",
        "limit_seats_per_license=50")
    assert params()["/mcp/prod/tenants/sfs/limit_seats_per_license"] == "50"


@pytest.mark.parametrize("argv", [
    ["--tenant", "sfs", "log_level=DEBUG"],                  # not a limit_ setting
    ["--tenant", "sfs", "limit_seats_per_license=lots"],     # not a number
    ["--tenant", "sfs", "limit_seats_per_license"],          # no value
    ["--tenant", "SFS", "limit_seats_per_license=5"],        # not a tenant id
    ["--tenant", "sfs"],                                     # nothing to set
])
def test_bad_overrides_are_refused(seed, monkeypatch, argv):
    with pytest.raises(SystemExit):
        run(seed, monkeypatch, "--stage", "prod", "--region", "us-east-1", *argv)
    assert params() == {}
