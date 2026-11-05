"""A deliberately small filter for the contact form: sales spam and links.

The form is a plain HTML post, so what gets through the visitor limits is mostly real-browser outreach (SEO
offers, link drops). Two rules catch nearly all of it and are easy to explain to a legitimate sender:

  * a link (http://, https://, ftp:// or www.) in the name or the message;
  * a phrase that only a sales pitch uses (SEO, backlinks, "website traffic", casino ...).

reason() returns why a message looks like spam, or None. The caller drops it silently (the sender still sees the
thank-you page, so nobody tunes their text against the filter) and logs the reason, never the message.
"""
import re

LINK_RE = re.compile(r"(?:https?|ftp)://|\bwww\.", re.IGNORECASE)

# Word-boundary phrases; a plain support question never contains them.
SALES_PHRASES = (
    r"seo", r"search engines?", r"search rankings?", r"google rankings?", r"first page of google",
    r"backlinks?", r"link[- ]building", r"guest posts?", r"(?:web)?site traffic", r"web traffic", r"organic traffic",
    r"digital marketing", r"marketing services", r"social media (?:marketing|management)", r"lead generation",
    r"web (?:design|development)", r"app development", r"increase (?:your )?(?:sales|traffic|revenue|conversions)",
    r"boost (?:your )?(?:sales|traffic|rankings?|website|business|online)", r"online (?:presence|visibility|performance)",
    r"target keywords?", r"cold emails?", r"email lists?", r"bitcoin", r"crypto(?:currency)?", r"casino", r"forex",
    r"viagra", r"payday loans?", r"make money", r"work from home", r"outsourc(?:e|ing)",
)
SALES_RE = re.compile(r"\b(?:{})\b".format("|".join(SALES_PHRASES)), re.IGNORECASE)


def reason(name, message):
    """'link', 'sales phrase: <phrase>', or None when the message looks like it came from a person."""
    text = "{}\n{}".format(name or "", message or "")
    if LINK_RE.search(text):
        return "link"
    found = SALES_RE.search(text)
    if found:
        return "sales phrase: {}".format(found.group(0).lower()[:40])
    return None
