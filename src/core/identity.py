"""Rules for the people who sign up: how an email address is compared, and what
a password and a company name must look like. Pure functions, no AWS."""
import hashlib
import re

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
MAX_EMAIL = 200
MIN_PASSWORD = 12
MAX_PASSWORD = 128
MIN_COMPANY = 2
MAX_COMPANY = 100
GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}

# A few of the passwords people reach for first. Cognito enforces length and
# character classes; this only refuses the obvious.
COMMON_PASSWORDS = {
    "password1234", "password12345", "passw0rd1234", "qwertyuiop12", "qwerty123456",
    "123456789012", "1234567890ab", "iloveyou1234", "letmein12345", "welcome12345",
    "administrator", "changeme1234", "mcplicensing1",
}


def clean_email(value):
    """The address as typed, trimmed and lower-cased, or None when it is not one."""
    email = (value or "").strip().lower() if isinstance(value, str) else ""
    if not email or len(email) > MAX_EMAIL or not EMAIL_RE.match(email):
        return None
    return email


def normalize_email(email):
    """The form used to recognise the same mailbox: lower case, without a +tag
    and, for Gmail, without dots. Ban lists and per-address limits use this, so
    a banned person cannot return by adding a +tag or, at Gmail, dots to the address."""
    local, _, domain = email.lower().partition("@")
    local = local.split("+", 1)[0]
    if domain in GMAIL_DOMAINS:
        local = local.replace(".", "")
        domain = "gmail.com"
    return "{}@{}".format(local, domain)


def email_hash(email):
    """A stable, non-reversible key for an address (never store or log the address for limits)."""
    return hashlib.sha256(normalize_email(email).encode("utf-8")).hexdigest()


def password_problem(password, email=None):
    """Why a password is not acceptable, or None."""
    if not isinstance(password, str):
        return "Enter a password."
    if len(password) < MIN_PASSWORD:
        return "The password must be at least {} characters.".format(MIN_PASSWORD)
    if len(password) > MAX_PASSWORD:
        return "The password must be at most {} characters.".format(MAX_PASSWORD)
    if not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password) and re.search(r"\d", password)):
        return "The password needs a lower-case letter, a capital letter and a number."
    if password.lower() in COMMON_PASSWORDS:
        return "That password is too common. Please choose another."
    local = normalize_email(email).split("@")[0] if email else ""
    if len(local) >= 4 and local in password.lower():  # shorter names would match almost any password
        return "The password must not contain your email name."
    return None


def clean_company(value):
    """The company name, tidied, or None when it is unusable."""
    if not isinstance(value, str):
        return None
    name = " ".join(CONTROL_RE.sub(" ", value).split())  # a newline or tab separates words, it does not join them
    return name if MIN_COMPANY <= len(name) <= MAX_COMPANY else None
