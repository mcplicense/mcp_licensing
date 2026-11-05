"""core/spam.py: the contact form's spam rules. Phrases are data (rows of a table, validated here); links are code.
Real spam is caught, and ordinary questions to a licensing service are not."""
import importlib.util
import pathlib
import time

import pytest

from core import spam

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STARTER, _ = spam.phrases_from_rows(load_script("seed_spam_phrases").STARTER_ROWS)
LEGIT = [line for line in (ROOT / "scripts" / "legit_messages.txt").read_text(encoding="utf-8").splitlines() if line.strip()]

# The message that prompted the filter (a real one, with the sender's details removed).
SEO_PITCH = """Hello http://mcplicense.net,

I wanted to reach out to see if you're open to exploring ways to grow your website traffic and boost online performance.

We offer customized SEO services that deliver measurable improvements.

Once you share your target keywords and target market, I'll send a full proposal.

Best Regards,
Juliana"""


# ------------------------------------------------------------------ one phrase

@pytest.mark.parametrize("raw,clean", [
    ("SEO", "seo"), ("  Link   Building ", "link building"), ("backlink*", "backlink*"), ("web-traffic", "web-traffic"),
    ("it's a deal", "it's a deal"), ("outsourc*", "outsourc*"), ("Marketing Services", "marketing services"),
])
def test_usable_phrases_are_cleaned(raw, clean):
    assert spam.check_phrase(raw) == (clean, None)


@pytest.mark.parametrize("raw,fragment", [
    ("", "empty"), ("  ", "empty"), ("ab", "shorter"), ("x" * 61, "longer"),
    ("seat", "too common"), ("License", "too common"), ("license*", "too common"), ("website", "too common"),
    ("a.*", "allowed"), ("(seo|ads)", "allowed"), ("se*o", "allowed"), ("***", "allowed"), ("seo?", "allowed"),
    ("**", "shorter"), ("a*", "shorter"), ("ab*", "too short without"), ("; drop table", "allowed"),
    ("<b>seo</b>", "allowed"),
])
def test_unusable_phrases_are_refused_with_a_reason(raw, fragment):
    phrase, problem = spam.check_phrase(raw)
    assert phrase is None and fragment in problem


# --------------------------------------------------------------------- a row

def test_a_row_may_hold_one_phrase_or_many_in_any_separator():
    good, skipped = spam.parse_phrases("seo, backlinks;  link building\ncasino\r\nbitcoin")
    assert good == ["seo", "backlinks", "link building", "casino", "bitcoin"] and skipped == []


def test_a_row_may_be_a_dynamodb_string_set():
    good, _ = spam.parse_phrases({"seo", "casino"})
    assert sorted(good) == ["casino", "seo"]


def test_unusable_entries_are_skipped_not_fatal():
    good, skipped = spam.parse_phrases("seo, a, license, (x|y), " + "z" * 80 + ", casino")
    assert good == ["seo", "casino"] and len(skipped) == 4


@pytest.mark.parametrize("value", [None, "", "  ,, ;", 0, [], set()])
def test_an_empty_row_gives_nothing(value):
    assert spam.parse_phrases(value) == ([], [])


def test_disabled_rows_are_ignored_and_duplicates_collapse():
    rows = [{"phrases": "seo, casino", "enabled": True}, {"phrases": "casino, forex", "enabled": False},
            {"phrases": "SEO, bitcoin"}]
    phrases, skipped = spam.phrases_from_rows(rows)
    assert phrases == ["seo", "casino", "bitcoin"] and skipped == 0


def test_the_list_is_capped():
    rows = [{"phrases": ", ".join("phrase{}x".format(i) for i in range(700))}]
    phrases, skipped = spam.phrases_from_rows(rows)
    assert len(phrases) == spam.MAX_PHRASES and skipped == 200


# ------------------------------------------------------------------- matching

def test_matching_is_whole_word_case_insensitive_and_treats_spaces_and_hyphens_alike():
    phrases = ["link building", "seo", "outsourc*"]
    assert spam.reason("", "We do LINK   Building", phrases) == "sales phrase: link building"
    assert spam.reason("", "good link-building tips", phrases) == "sales phrase: link-building"
    assert spam.reason("", "Seoul is far", phrases) is None
    assert spam.reason("", "reseo", phrases) is None
    assert spam.reason("", "we are outsourcing", phrases) == "sales phrase: outsourcing"
    assert spam.reason("", "the SEO team", phrases) == "sales phrase: seo"


def test_the_longest_phrase_names_the_reason():
    assert spam.reason("", "cheap seo services", ["seo", "seo services"]) == "sales phrase: seo services"


def test_a_phrase_with_regular_expression_characters_cannot_act_as_a_pattern():
    # an entry like "a.*" is refused when read; and even a raw tuple handed to the matcher is escaped
    assert spam.reason("", "abc and axyz", ["a.b"]) is None
    assert spam.reason("", "a.b is here", ["a.b"]) == "sales phrase: a.b"


def test_five_hundred_phrases_are_fast_even_on_a_long_message():
    phrases = ["word{}ending".format(i) for i in range(500)]
    started = time.perf_counter()
    assert spam.reason("", "lorem ipsum " * 400, phrases) is None
    assert time.perf_counter() - started < 0.5


def test_a_missing_or_empty_list_means_the_builtin_fallback():
    for phrases in (None, []):
        assert spam.reason("", "Our SEO team can help.", phrases) == "sales phrase: seo"
        assert spam.reason("", "Hello, how do seats work?", phrases) is None


def test_the_table_list_replaces_the_fallback():
    assert spam.reason("", "Our SEO team can help.", ["casino"]) is None


# --------------------------------------------------------- links and real spam

def test_the_seo_pitch_that_started_it_is_caught():
    assert spam.reason("Juliana Bryant", SEO_PITCH, STARTER) == "link"
    assert spam.reason("", SEO_PITCH.replace("http://mcplicense.net", "your team"), STARTER).startswith("sales phrase")
    assert spam.reason("", SEO_PITCH.replace("http://mcplicense.net", "your team"), None).startswith("sales phrase")


@pytest.mark.parametrize("message", [
    "Check this out https://example.com/offer", "see HTTP://EXAMPLE.COM", "visit www.example.org today",
    "ftp://files.example.net/x", "I put the code on https://github.com/me/tool, please look",
])
def test_a_link_is_spam(message):
    assert spam.reason("", message, STARTER) == "link"


def test_a_link_in_the_name_is_spam_too():
    assert spam.reason("https://spam.example", "How do seats work for my team?", STARTER) == "link"


@pytest.mark.parametrize("message,phrase", [
    ("We build backlinks for you and improve your Google ranking.", "backlinks"),
    ("Our SEO team can help.", "seo"),
    ("Improve your website traffic with us", "website traffic"),
    ("Best digital marketing agency", "digital marketing"),
    ("Boost your sales this month", "boost your sales"),
    ("Invest in Bitcoin now", "bitcoin"),
    ("Online casino bonus", "casino"),
    ("We do web development and web design at low prices", "web development"),
    ("Please share your target keywords", "target keywords"),
    ("Need to boost online performance?", "boost online"),
])
def test_starter_phrases_catch_sales_pitches(message, phrase):
    assert spam.reason("", message, STARTER) == "sales phrase: " + phrase


@pytest.mark.parametrize("message", LEGIT)
def test_ordinary_messages_pass_with_the_starter_list_and_the_fallback(message):
    assert spam.reason("Jane Doe", message, STARTER) is None
    assert spam.reason("Jane Doe", message, None) is None


def test_the_starter_rows_are_all_usable():
    rows = load_script("seed_spam_phrases").STARTER_ROWS
    for row in rows:
        good, skipped = spam.parse_phrases(row["phrases"])
        assert good and skipped == [], row["name"]


def test_empty_input_is_not_spam():
    assert spam.reason(None, None, STARTER) is None and spam.reason("", "", None) is None


def test_the_reason_never_contains_more_than_the_matched_phrase():
    text = "x" * 500 + " SEO " + "y" * 500
    assert len(spam.reason("", text, STARTER)) < 80
