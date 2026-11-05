"""A deliberately small filter for the contact form: links and sales phrases.

The form is a plain HTML post, so what gets through the visitor limits is mostly real-browser outreach (SEO
offers, link drops). Two rules catch nearly all of it and are easy to explain to a legitimate sender:

  * a link (http://, https://, ftp:// or www.) in the name or the message;
  * a phrase that only a sales pitch uses (SEO, backlinks, "website traffic", casino ...).

The links rule is code. The phrases are DATA: rows of the mcp_spam_phrase table, edited by hand (console, CSV
import or scripts/spam_phrases.py) so a new pitch needs no deploy. A row has a `scope` ("contact"), a `name` (any
label), `phrases` (comma or line separated; a row can hold one or many), `enabled` (false switches the row off) and
a `note`. Phrases are PLAIN TEXT, never patterns: matched whole-word and case-insensitively, spaces and hyphens
alike, with an optional trailing * for word endings ("outsourc*"). Anything unusable (too short, too long, on the
stoplist, odd characters) is skipped, so a careless edit cannot break the form or drop ordinary mail; if the table
cannot be read or has no usable phrase, FALLBACK_PHRASES apply.

reason() returns why a message looks like spam, or None. The caller drops it silently (the sender still sees the
thank-you page, so nobody tunes their text against the filter) and logs the reason, never the message.
"""
import functools
import re

LINK_RE = re.compile(r"(?:https?|ftp)://|\bwww\.", re.IGNORECASE)

MIN_PHRASE = 3
MAX_PHRASE = 60
MAX_PHRASES = 500
PHRASE_RE = re.compile(r"^\w[\w '\-]*\*?$")

# Words an ordinary question to a licensing service uses: never accepted as a phrase on their own.
STOPWORDS = frozenset("""
    license licence licenses licences seat seats key keys api tenant tenants verify verified login log password account
    accounts support help limit limits question questions hello thanks thank please code error errors bug issue problem
    mcp server tool tools price pricing plan trial demo email message contact form site website web page pages
    sign signup install update version docs documentation customer customers device devices laptop expire expired
    revoke revoked renew renewal billing invoice payment refund cancel delete data privacy security terms
""".split())

# Used only when the table is unreachable or has no usable phrase: enough to catch the commonest pitches.
FALLBACK_PHRASES = (
    "seo", "backlink*", "link building", "website traffic", "web traffic", "digital marketing",
    "marketing services", "lead generation", "casino", "bitcoin", "cryptocurrency", "viagra",
)


def check_phrase(raw):
    """(clean phrase, None) for a usable one, or (None, why not)."""
    phrase = " ".join(str(raw).split()).lower()
    core = phrase.rstrip("*")
    if not phrase:
        return None, "empty"
    if len(phrase) < MIN_PHRASE:
        return None, "shorter than {} characters".format(MIN_PHRASE)
    if len(phrase) > MAX_PHRASE:
        return None, "longer than {} characters".format(MAX_PHRASE)
    if not PHRASE_RE.match(phrase) or "*" in core:
        return None, "only letters, digits, spaces, hyphens and one trailing * are allowed"
    if len(core.strip()) < MIN_PHRASE:
        return None, "too short without the *"
    if core in STOPWORDS:
        return None, "too common a word: it would catch ordinary messages"
    return phrase, None


def parse_phrases(value):
    """([usable phrases], [(entry, why skipped)]) from a row's `phrases`: text with commas, semicolons or lines,
    or a set/list of strings."""
    if isinstance(value, (set, frozenset, list, tuple)):
        entries = [str(item) for item in value]
    else:
        entries = re.split(r"[,;\n\r]+", str(value or ""))
    good, skipped = [], []
    for entry in entries:
        if not entry.strip():
            continue
        phrase, problem = check_phrase(entry)
        if phrase:
            good.append(phrase)
        else:
            skipped.append((entry.strip()[:MAX_PHRASE], problem))
    return good, skipped


def phrases_from_rows(rows):
    """(distinct phrases of the enabled rows, up to MAX_PHRASES; number of entries skipped)."""
    seen, skipped = [], 0
    for row in rows:
        if row.get("enabled") is False:
            continue
        good, bad = parse_phrases(row.get("phrases"))
        skipped += len(bad)
        for phrase in good:
            if phrase not in seen:
                seen.append(phrase)
    return seen[:MAX_PHRASES], skipped + max(0, len(seen) - MAX_PHRASES)


@functools.lru_cache(maxsize=8)
def _compile(phrases):
    parts = []
    for phrase in sorted(phrases, key=len, reverse=True):  # longest first, so the reason names the whole phrase
        words = [re.escape(word) for word in re.split(r"[\s-]+", phrase.rstrip("*")) if word]
        parts.append(r"[\s-]+".join(words) + (r"\w*" if phrase.endswith("*") else ""))
    return re.compile(r"(?<!\w)(?:{})(?!\w)".format("|".join(parts)), re.IGNORECASE)


def reason(name, message, phrases=None):
    """'link', 'sales phrase: <phrase>', or None when the message looks like it came from a person.
    `phrases` is the usable list from the table; None or empty means FALLBACK_PHRASES."""
    text = "{}\n{}".format(name or "", message or "")
    if LINK_RE.search(text):
        return "link"
    found = _compile(tuple(phrases) if phrases else FALLBACK_PHRASES).search(text)
    if found:
        return "sales phrase: {}".format(" ".join(found.group(0).lower().split())[:40])
    return None
