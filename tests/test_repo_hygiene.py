import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".aws-sam", "site_dist", "node_modules"}
PRIVATE_WORDS = ROOT / "tests" / "private_words.json"
LOCAL_ONLY = {PRIVATE_WORDS, ROOT / "site_local.json"}  # gitignored, never exported


def private_words(kind):
    """Words that must never appear anywhere in the repository, for example the owner's name or an
    identifier from an earlier product. They live in a gitignored local file so this repository does not
    spell them out; without the file (a fresh clone) the tests that need them are skipped."""
    try:
        return json.loads(PRIVATE_WORDS.read_text(encoding="utf-8")).get(kind, [])
    except FileNotFoundError:
        return []


def _text_files():
    for path in ROOT.rglob("*"):
        if path.is_file() and path not in LOCAL_ONLY and not (set(path.relative_to(ROOT).parts) & SKIP_DIRS):
            if path.suffix in {".py", ".yml", ".yaml", ".md", ".json", ".txt", ".toml", ".html", ".js", ".css"}:
                yield path


def _hits(words, skip=()):
    skip = {pathlib.Path(p).resolve() for p in skip}
    found = []
    for path in _text_files():
        if path.resolve() in skip:
            continue
        text = path.read_text(encoding="utf-8").lower()
        found.extend("{}: {}".format(path.relative_to(ROOT), word) for word in words if word.lower() in text)
    return found


def test_no_legacy_identifiers():
    words = private_words("forbidden")
    if not words:
        pytest.skip("no tests/private_words.json")
    assert not _hits(words)


def test_no_hardcoded_api_urls():
    # A real API id is 10 lowercase alphanumerics; placeholders like YOUR-API-ID do not match.
    real_url = re.compile(r"https://[a-z0-9]{10}\.execute-api\.")
    for path in _text_files():
        assert not real_url.search(path.read_text(encoding="utf-8")), path


def test_no_credentials_or_account_ids():
    """No AWS access key, private key block or account id (ARNs use ${AWS::AccountId}; the all-same-digit
    and 123456789012 ids that tests use are placeholders)."""
    key = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----")
    arn = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):")
    for path in _text_files():
        text = path.read_text(encoding="utf-8")
        assert not key.search(text), path
        for account in arn.findall(text):
            assert account in {"123456789012", "000000000000"} or len(set(account)) == 1, (path, "account id")


# The service is run anonymously: no person's name, personal mailbox or AWS account id belongs in the
# repository (addresses and ids are given at deploy time). test_site.py keeps its own check of the website.
PERSONAL_MAILBOXES = ["@gmail.", "@yahoo.", "@hotmail.", "@outlook."]


def test_no_personal_details_in_the_repository():
    words = private_words("personal")
    if not words:
        pytest.skip("no tests/private_words.json")
    here = [pathlib.Path(__file__), ROOT / "tests" / "test_site.py"]
    assert not _hits(words + PERSONAL_MAILBOXES, skip=here)


def test_no_personal_mailbox_in_the_repository():
    assert not _hits(PERSONAL_MAILBOXES, skip=[pathlib.Path(__file__), ROOT / "tests" / "test_site.py"])
