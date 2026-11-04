"""Key generation, parsing and hashing.

License key   <tenant_id>_<5 groups of 5 chars>   e.g. acme_7K2M9-X4QPD-8WHT3-NB6RC-ZV5YA
              25 random characters from a 32 symbol alphabet is about 125 bits.
API key       mcpk_<key_id>.<secret>              used in the X-Tenant-Api-Key header.

Only SHA-256 hashes of keys are stored. The keys carry enough entropy that a
plain hash is sufficient.
"""
import hashlib
import hmac
import re
import secrets

LICENSE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I
# A tenant id is either a name chosen by the platform owner (3-12 lowercase
# letters or digits) or a generated one, mcp-xxxxxx. Ids are stored lowercase
# and may be shown in capitals (MCP-XXXXXX); license keys accept either case.
_TENANT_ID = r"(?:[a-z0-9]{3,12}|mcp-[a-hj-np-z2-9]{6})"
TENANT_ID_RE = re.compile(r"^" + _TENANT_ID + r"$")
LICENSE_KEY_RE = re.compile(
    r"^(" + _TENANT_ID + r")_([A-HJ-NP-Z2-9]{5}(?:-[A-HJ-NP-Z2-9]{5}){4})$"
)
API_KEY_PREFIX = "mcpk_"
GENERATED_TENANT_PREFIX = "mcp-"


def is_valid_tenant_id(tenant_id):
    return isinstance(tenant_id, str) and bool(TENANT_ID_RE.match(tenant_id))


def generate_tenant_id():
    """mcp-xxxxxx: six random characters from the unambiguous alphabet
    (about a billion combinations). Uniqueness is enforced by the caller's
    conditional write."""
    return GENERATED_TENANT_PREFIX + "".join(
        secrets.choice(LICENSE_ALPHABET.lower()) for _ in range(6))


def generate_license_key(tenant_id):
    groups = [
        "".join(secrets.choice(LICENSE_ALPHABET) for _ in range(5))
        for _ in range(5)
    ]
    return "{}_{}".format(tenant_id, "-".join(groups))


def parse_license_key(raw):
    """Return (tenant_id, normalized_key) or None when the shape is wrong."""
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip().replace(" ", "")
    if "_" not in cleaned:
        return None
    tenant_part, random_part = cleaned.split("_", 1)
    normalized = "{}_{}".format(tenant_part.lower(), random_part.upper())
    match = LICENSE_KEY_RE.match(normalized)
    if not match:
        return None
    return match.group(1), normalized


def hash_key(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_api_key():
    """Return (key_id, full_key, key_hash)."""
    key_id = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    full_key = "{}{}.{}".format(API_KEY_PREFIX, key_id, secret)
    return key_id, full_key, hash_key(full_key)


def parse_api_key(raw):
    """Return key_id or None when the shape is wrong."""
    if not isinstance(raw, str) or not raw.startswith(API_KEY_PREFIX):
        return None
    body = raw[len(API_KEY_PREFIX):]
    if "." not in body:
        return None
    key_id = body.split(".", 1)[0]
    if not re.fullmatch(r"[0-9a-f]{12}", key_id):
        return None
    return key_id


def hashes_match(expected_hash, key):
    return hmac.compare_digest(expected_hash, hash_key(key))


def new_license_id():
    return secrets.token_hex(6)
