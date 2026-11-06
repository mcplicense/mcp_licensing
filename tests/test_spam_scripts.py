"""scripts/seed_spam_phrases.py and scripts/spam_phrases.py against the real table definition (moto)."""
import importlib.util
import pathlib

import pytest

from core import spam, store

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


seed = load_script("seed_spam_phrases")
helper = load_script("spam_phrases")


@pytest.fixture
def table():
    return store._table("SPAM_TABLE")


def names(table):
    return [row["name"] for row in helper.rows(table)]


# ------------------------------------------------------------------------ seed

def test_seed_writes_the_starter_rows_and_never_overwrites(table):
    created, kept = seed.seed(table, seed.STARTER_ROWS)
    assert sorted(created) == sorted(r["name"] for r in seed.STARTER_ROWS) and kept == []
    table.update_item(Key={"scope": "contact", "name": "seo"}, UpdateExpression="SET phrases = :p",
                      ExpressionAttributeValues={":p": "my own list"})
    created, kept = seed.seed(table, seed.STARTER_ROWS)
    assert created == [] and len(kept) == len(seed.STARTER_ROWS)
    assert table.get_item(Key={"scope": "contact", "name": "seo"})["Item"]["phrases"] == "my own list"


def test_seed_refuses_a_row_with_no_usable_phrase_or_no_name(table):
    with pytest.raises(ValueError):
        seed.seed(table, [{"scope": "contact", "name": "bad", "phrases": "a, license"}])
    with pytest.raises(ValueError):
        seed.seed(table, [{"scope": "contact", "phrases": "casino"}])
    assert names(table) == []


def test_the_dry_run_writes_nothing(table, capsys):
    seed.main(["--dry-run"])
    assert "would add contact/seo" in capsys.readouterr().out and names(table) == []


# ---------------------------------------------------------------------- helper

def test_add_creates_the_row_and_the_phrase_takes_effect(table):
    assert helper.add(table, ["Free Quote", "domain renewal"]) == ["free quote", "domain renewal"]
    (row,) = helper.rows(table)
    assert row["name"] == "custom" and row["phrases"] == "free quote, domain renewal" and row["enabled"] is True
    assert helper.verdict(table, "Your domain renewal is due") == "sales phrase: domain renewal"


def test_adding_the_same_phrase_twice_changes_nothing(table):
    helper.add(table, ["free quote"])
    assert helper.add(table, ["free quote"]) == []
    assert helper.rows(table)[0]["phrases"] == "free quote"


def test_add_to_another_group_and_it_switches_a_disabled_row_back_on(table):
    table.put_item(Item={"scope": "contact", "name": "scams", "phrases": "casino", "enabled": False})
    helper.add(table, ["lottery winner"], group="scams")
    row = helper.rows(table)[0]
    assert row["phrases"] == "casino, lottery winner" and row["enabled"] is True


def test_add_refuses_a_phrase_that_would_block_a_legitimate_message(table):
    with pytest.raises(ValueError, match="legitimate message"):
        helper.add(table, ["increase the limit"])
    assert names(table) == []
    assert helper.add(table, ["increase the limit"], force=True) == ["increase the limit"]


@pytest.mark.parametrize("phrase", ["license", "a", "(x|y)", "x" * 70])
def test_add_refuses_an_unusable_phrase(table, phrase):
    with pytest.raises(ValueError):
        helper.add(table, [phrase])
    assert names(table) == []


def test_remove_takes_the_phrase_out_of_every_row_and_deletes_an_emptied_row(table):
    table.put_item(Item={"scope": "contact", "name": "a", "phrases": "free quote, casino", "enabled": True})
    table.put_item(Item={"scope": "contact", "name": "b", "phrases": "free quote", "enabled": True})
    assert sorted(helper.remove(table, "Free Quote")) == ["a", "b"]
    assert names(table) == ["a"] and helper.rows(table)[0]["phrases"] == "casino"
    assert helper.remove(table, "never there") == []


def test_the_verdict_uses_the_table_then_the_fallback(table):
    assert helper.verdict(table, "Our SEO team can help") == "sales phrase: seo"  # empty table: fallback
    helper.add(table, ["gadget offer"])
    assert helper.verdict(table, "Our SEO team can help") is None  # the table list now replaces it
    assert helper.verdict(table, "see https://example.com") == "link"
    assert helper.verdict(table, "Hello, how do seats work?") is None


def test_the_command_line_round_trip(table, capsys):
    helper.main(["add", "gadget offer", "--group", "stuff"])
    helper.main(["list"])
    out = capsys.readouterr().out
    assert "added to stuff: gadget offer" in out and "1 rows, 1 usable phrases, 0 entries skipped" in out
    helper.main(["test", "a gadget offer for you"])
    assert "SPAM (sales phrase: gadget offer)" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        helper.main(["add", "license"])


def test_the_corpus_is_real_and_every_line_passes_the_starter_list():
    messages = helper.legit_messages()
    assert len(messages) >= 25
    phrases, _ = spam.phrases_from_rows(seed.STARTER_ROWS)
    assert all(spam.reason("", m, phrases) is None for m in messages)


# ------------------------------------------------------------ merge and export

def test_merge_creates_missing_rows_and_adds_only_missing_phrases(table):
    table.put_item(Item={"scope": "contact", "name": "seo", "phrases": "seo, my own phrase", "enabled": False,
                         "note": "mine"})
    created, extended = seed.merge(table, seed.STARTER_ROWS)
    assert "seo" not in created and "search_listing" in created
    assert "my own phrase" not in extended["seo"] and "backlink*" in extended["seo"]
    row = table.get_item(Key={"scope": "contact", "name": "seo"})["Item"]
    assert row["phrases"].startswith("seo, my own phrase, ")  # what was there stays, in place
    assert row["enabled"] is False and row["note"] == "mine"   # edits to the flags are respected


def test_merge_twice_changes_nothing_and_never_removes(table):
    seed.merge(table, seed.STARTER_ROWS)
    table.update_item(Key={"scope": "contact", "name": "scams"}, UpdateExpression="SET phrases = :p",
                      ExpressionAttributeValues={":p": "casino"})  # the owner trimmed a row by hand
    created, extended = seed.merge(table, seed.STARTER_ROWS)
    assert created == [] and list(extended) == ["scams"]  # only the trimmed row gets its phrases back
    assert seed.merge(table, seed.STARTER_ROWS) == ([], {})


def test_merge_tolerates_a_string_set_row(table):
    table.put_item(Item={"scope": "contact", "name": "seo", "phrases": {"seo", "my own"}, "enabled": True})
    seed.merge(table, [{"scope": "contact", "name": "seo", "phrases": "seo, backlink*"}])
    good, _ = spam.parse_phrases(table.get_item(Key={"scope": "contact", "name": "seo"})["Item"]["phrases"])
    assert "backlink*" in good


def test_export_round_trips_the_data_file_exactly(table, tmp_path):
    seed.seed(table, seed.STARTER_ROWS)
    out = tmp_path / "rows.json"
    helper.main(["export", "--file", str(out)])
    import json
    assert json.loads(out.read_text(encoding="utf-8")) == seed.STARTER_ROWS
    seed.seed(table, json.loads(out.read_text(encoding="utf-8")))  # and it can be loaded again


def test_export_records_a_hand_edit_a_disabled_row_and_a_row_without_a_note(table, tmp_path):
    table.put_item(Item={"scope": "contact", "name": "b", "phrases": {"casino", "forex"}, "enabled": False})
    table.put_item(Item={"scope": "contact", "name": "a", "phrases": "free quote"})
    assert helper.export(table) == [
        {"scope": "contact", "name": "a", "enabled": True, "phrases": "free quote"},
        {"scope": "contact", "name": "b", "enabled": False, "phrases": "casino, forex"}]
