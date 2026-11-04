from core import keys


def test_license_key_shape_and_roundtrip():
    key = keys.generate_license_key("acme")
    assert key.startswith("acme_")
    tenant_id, normalized = keys.parse_license_key(key)
    assert tenant_id == "acme" and normalized == key


def test_license_key_is_case_and_space_insensitive():
    key = keys.generate_license_key("acme")
    messy = "  ACME_" + key.split("_", 1)[1].lower() + " "
    assert keys.parse_license_key(messy) == ("acme", key)


def test_license_key_entropy_is_not_trivially_small():
    assert len({keys.generate_license_key("acme") for _ in range(200)}) == 200


def test_malformed_license_keys_are_rejected():
    for bad in [None, "", "nounderscore", "acme_short", "ac_AAAAA-AAAAA-AAAAA-AAAAA-AAAAA",
                "acme_0OIl1-AAAAA-AAAAA-AAAAA-AAAAA", 123]:
        assert keys.parse_license_key(bad) is None


def test_tenant_id_rules():
    assert keys.is_valid_tenant_id("acme1")
    for bad in ["ab", "has_underscore", "UPPER", "toolongtenantid1", "a-b-c", None]:
        assert not keys.is_valid_tenant_id(bad)


def test_api_key_roundtrip_and_hash():
    key_id, full_key, key_hash = keys.generate_api_key()
    assert keys.parse_api_key(full_key) == key_id
    assert keys.hashes_match(key_hash, full_key)
    assert not keys.hashes_match(key_hash, full_key + "x")


def test_malformed_api_keys_are_rejected():
    for bad in [None, "", "mcpk_", "mcpk_nodot", "other_abcdef123456.secret", "mcpk_XYZ.secret"]:
        assert keys.parse_api_key(bad) is None
