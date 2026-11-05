"""core/spam.py: the contact form's spam rules. Real spam is caught, and ordinary questions to a licensing
service are not."""
import pytest

from core import spam

# The message that prompted the filter (a real one, with the sender's details removed).
SEO_PITCH = """Hello http://mcplicense.net,

I wanted to reach out to see if you're open to exploring ways to grow your website traffic and boost online performance.

We offer customized SEO services that deliver measurable improvements.

Once you share your target keywords and target market, I'll send a full proposal.

Best Regards,
Juliana"""


def test_the_seo_pitch_that_started_it_is_caught():
    assert spam.reason("Juliana Bryant", SEO_PITCH) == "link"
    assert spam.reason("", SEO_PITCH.replace("http://mcplicense.net", "your team")).startswith("sales phrase")


@pytest.mark.parametrize("message", [
    "Check this out https://example.com/offer",
    "see HTTP://EXAMPLE.COM",
    "visit www.example.org today",
    "ftp://files.example.net/x",
    "I put the code on https://github.com/me/tool, please look",
])
def test_a_link_is_spam(message):
    assert spam.reason("", message) == "link"


def test_a_link_in_the_name_is_spam_too():
    assert spam.reason("https://spam.example", "How do seats work for my team?") == "link"


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
])
def test_sales_phrases_are_spam(message, phrase):
    assert spam.reason("", message) == "sales phrase: " + phrase


@pytest.mark.parametrize("message", [
    "Hello, I would like to know how seats work.",
    "My license shows SEAT_LIMIT but I only use one laptop. Can you raise the limit to 5 seats?",
    "Does the verify endpoint return lease_expires_at in UTC? The docs say epoch seconds.",
    "The Node example fails with a TLS error on Windows 11; the Python one works.",
    "We ship a cryptography plugin and want one license per customer. Is that possible?",
    "How do I report a security problem in the console? I found the website's login confusing.",
    "Please delete my account and data under the privacy policy. My tenant id is mcp-k7m2x9.",
    "Is there a way to export the audit log as CSV?",
    "Our company name is Seoul Tools Ltd and we need 20 seats.",
    "Contact me at jane@example.com",
])
def test_ordinary_messages_pass(message):
    assert spam.reason("Jane Doe", message) is None


def test_empty_input_is_not_spam():
    assert spam.reason(None, None) is None and spam.reason("", "") is None


def test_the_reason_never_contains_more_than_the_matched_phrase():
    text = "x" * 500 + " SEO " + "y" * 500
    assert len(spam.reason("", text)) < 80
