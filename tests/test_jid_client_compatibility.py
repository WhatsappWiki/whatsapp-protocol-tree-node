"""Client JID normalization and independent preservation expectations.

All addresses are synthetic. Golden bytes follow the client's A05 string-JID
selection and A02/A00 compact-JID read/write branches; they are not generated
by the codec under test and do not contain private hook payloads.
"""
from dataclasses import replace

import pytest

from protocol_tree_node import Attribute, Codec, JID, Node, ProtocolError, TokenDictionary


@pytest.fixture
def client_codec():
    return Codec(TokenDictionary([
        None, None, None, "iq", "to", "s.whatsapp.net", "lid", "interop",
        "interop.g.us", "broadcast", "g.us", "hosted", "hosted.lid",
    ]))


def packet(value):
    return b"\xf8\x03\x03\x04" + value


@pytest.mark.parametrize("user_token", [b"\x00", b"\xfc\x00"])
def test_empty_interop_group_factory_fallback_keeps_original_tuple(client_codec, user_token):
    original = packet(b"\xf4" + user_token + b"\x00\x00\x00\x00\x02")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    assert node.attrs[0].value == "interop.g.us"
    assert client_codec.write(node, framed=False, preserve_wire=True) == original


@pytest.mark.parametrize("suffix", [".ignored", ":0", ".ignored:0"])
@pytest.mark.parametrize("marker", [244, 250])
def test_interop_account_spelling_survives_normalization_and_edits(client_codec, suffix, marker):
    wire_user = ("42-" if marker == 250 else "") + "123" + suffix
    tail = b"\x07" if marker == 250 else b"\x00\x00\x00\x2a\x00"
    original = packet(bytes([marker]) + raw(wire_user) + tail)
    node = client_codec.read(original, framed=False, preserve_wire=True)
    assert node.attrs[0].value.user == "123"
    assert node.attrs[0].value.integrator == 42
    assert client_codec.write(node, framed=False, preserve_wire=True) == original
    changed = replace(node, attrs=(Attribute("to", replace(node.attrs[0].value, user="456")),))
    assert client_codec.write(changed, framed=False, preserve_wire=True) == packet(
        bytes([marker]) + raw(("42-" if marker == 250 else "") + "456" + suffix) + tail
    )


def raw(text):
    data = text.encode("utf-8")
    return b"\xfc" + bytes([len(data)]) + data


@pytest.mark.parametrize("flags", [0, 1, 64, 65])
@pytest.mark.parametrize("suffix,device", [
    (":7", 7), (":+007", 7), (":256", 256), (":-256", -256), (".+1:7", 7),
])
def test_f7_zero_outer_device_keeps_device_inside_user_token(client_codec, flags, suffix, device):
    original = packet(bytes([247, flags, 0]) + raw("12345" + suffix))
    node = client_codec.read(original, framed=False, preserve_wire=True)
    jid = node.attrs[0].value
    assert isinstance(jid, JID)
    assert jid.user == "12345"
    assert jid.device == device
    assert client_codec.write(node, framed=False, preserve_wire=True) == original


def test_f7_user_device_edit_updates_lexeme_without_changing_outer_zero(client_codec):
    original = packet(b"\xf7\x41\x00" + raw("12345:+007"))
    node = client_codec.read(original, framed=False, preserve_wire=True)
    jid = replace(node.attrs[0].value, user="45678", device=9)
    changed = replace(node, attrs=(Attribute("to", jid),))
    output = client_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(b"\xf7\x41\x00" + raw("45678:+009"))
    assert client_codec.read(output, framed=False).attrs[0].value == jid


@pytest.mark.parametrize("user", ["12:3@x", "123@foo"])
def test_fa_empty_server_with_embedded_at_preserves_string_fallback(client_codec, user):
    original = packet(b"\xfa" + raw(user) + raw(""))
    node = client_codec.read(original, framed=False, preserve_wire=True)
    assert node.attrs[0].value == user + "@"
    assert client_codec.write(node, framed=False, preserve_wire=True) == original


def test_attribute_string_address_uses_client_jid_encoding(client_codec):
    expected = bytes.fromhex("f8030304faff8312345f05")
    node = Node("iq", attrs={"to": "12345@s.whatsapp.net"})
    assert client_codec.write(node, framed=False) == expected
    explicit = Node("iq", attrs={"to": JID("12345", "s.whatsapp.net")})
    assert client_codec.write(explicit, framed=False) == expected
    assert str(client_codec.read(expected, framed=False).attrs[0].value) == "12345@s.whatsapp.net"


def test_tag_string_address_uses_client_jid_encoding(client_codec):
    expected = bytes.fromhex("f801faff8312345f05")
    assert client_codec.write(Node("12345@s.whatsapp.net"), framed=False) == expected
    assert client_codec.read(expected, framed=False).tag == "12345@s.whatsapp.net"


def test_attribute_name_is_never_automatically_a_jid(client_codec):
    expected = b"\xf8\x03\x03" + raw("12345@s.whatsapp.net") + b"\x03"
    node = Node("iq", attrs={"12345@s.whatsapp.net": "iq"})
    assert client_codec.write(node, framed=False) == expected
    assert client_codec.read(expected, framed=False) == node


def test_data_address_remains_raw_bytes(client_codec):
    data = b"12345@s.whatsapp.net"
    expected = b"\xf8\x02\x03\xfc\x14" + data
    assert client_codec.write(Node("iq", data=data), framed=False) == expected
    assert client_codec.read(expected, framed=False).data == data


def test_full_address_dictionary_token_precedes_string_jid_inference(client_codec):
    codec = Codec(TokenDictionary(list(client_codec.dictionary.single) + ["12345@s.whatsapp.net"]))
    expected = bytes.fromhex("f80303040d")
    assert codec.write(Node("iq", attrs={"to": "12345@s.whatsapp.net"}), framed=False) == expected
    assert codec.read(expected, framed=False).attrs[0].value == "12345@s.whatsapp.net"
    # A typed JID goes straight to the JID writer, without full-address lookup.
    explicit = Node("iq", attrs={"to": JID("12345", "s.whatsapp.net")})
    assert codec.write(explicit, framed=False) == bytes.fromhex("f8030304faff8312345f05")


def test_raw_address_stays_text_on_read_but_default_write_infers_jid(client_codec):
    original = packet(raw("12345@s.whatsapp.net"))
    ordinary = client_codec.read(original, framed=False)
    preserved = client_codec.read(original, framed=False, preserve_wire=True)
    assert ordinary == preserved
    assert ordinary.attrs[0].value == "12345@s.whatsapp.net"
    assert client_codec.write(ordinary, framed=False) == bytes.fromhex("f8030304faff8312345f05")
    assert client_codec.write(preserved, framed=False, preserve_wire=True) == original


def test_preserved_raw_address_edit_reencodes_current_text(client_codec):
    original = packet(raw("12345@s.whatsapp.net"))
    node = client_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("to", "45678@s.whatsapp.net"),))
    assert client_codec.write(changed, framed=False, preserve_wire=True) == packet(raw("45678@s.whatsapp.net"))
    assert client_codec.write(changed, framed=False) == bytes.fromhex("f8030304faff8345678f05")


@pytest.mark.parametrize("flags,domain,device,canonical_flags", [
    (0x40, "s.whatsapp.net", 7, 0),
    (0x41, "lid", 7, 1),
    (0xFE, "hosted", 99, 128),
    (0xFF, "hosted.lid", 99, 129),
])
def test_f7_uninterpreted_flags_normalize_but_preserve_wire_restores_them(
    client_codec, flags, domain, device, canonical_flags,
):
    original = packet(bytes([247, flags, device]) + bytes.fromhex("ff8312345f"))
    ordinary = client_codec.read(original, framed=False)
    preserved = client_codec.read(original, framed=False, preserve_wire=True)
    assert ordinary == preserved
    jid = ordinary.attrs[0].value
    assert isinstance(jid, JID)
    assert jid.user == "12345"
    assert jid.server == domain
    assert jid.device == device
    expected = packet(bytes([247, canonical_flags, device]) + bytes.fromhex("ff8312345f"))
    assert client_codec.write(ordinary, framed=False) == expected
    assert client_codec.write(preserved, framed=False) == expected
    assert client_codec.write(preserved, framed=False, preserve_wire=True) == original


def test_preserved_f7_edit_reencodes_current_user_with_saved_flag_bits(client_codec):
    original = bytes.fromhex("f8030304f74107ff82123f")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    jid = replace(node.attrs[0].value, user="456")
    changed = replace(node, attrs=(Attribute("to", jid),))
    assert client_codec.write(changed, framed=False) == bytes.fromhex("f8030304f70107ff82456f")
    assert client_codec.write(changed, framed=False, preserve_wire=True) == bytes.fromhex("f8030304f74107ff82456f")


def test_preserved_f7_edit_updates_domain_bits_but_keeps_other_bits(client_codec):
    original = bytes.fromhex("f8030304f74107ff82123f")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("to", JID("45678", "s.whatsapp.net", device=9)),))
    assert client_codec.write(changed, framed=False) == bytes.fromhex("f8030304f70009ff8345678f")
    assert client_codec.write(changed, framed=False, preserve_wire=True) == bytes.fromhex("f8030304f74009ff8345678f")


def test_f7_zero_device_normalizes_to_fa_and_still_preserves_f7(client_codec):
    original = bytes.fromhex("f8030304f70000ff8312345f")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    assert isinstance(node.attrs[0].value, JID)
    assert str(node.attrs[0].value) == "12345@s.whatsapp.net"
    assert client_codec.write(node, framed=False) == bytes.fromhex("f8030304faff8312345f05")
    assert client_codec.write(node, framed=False, preserve_wire=True) == original


def test_fa_device_address_normalizes_to_f7_and_preserves_pair_layout(client_codec):
    original = packet(b"\xfa" + raw("123:7") + b"\x06")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    jid = node.attrs[0].value
    assert isinstance(jid, JID)
    assert jid.user == "123"
    assert jid.server == "lid"
    assert jid.device == 7
    assert client_codec.write(node, framed=False) == bytes.fromhex("f8030304f70107ff82123f")
    assert client_codec.write(node, framed=False, preserve_wire=True) == original


def test_preserved_fa_device_edit_updates_original_user_string(client_codec):
    original = packet(b"\xfa" + raw("123:7") + b"\x06")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    jid = replace(node.attrs[0].value, user="456", device=9)
    changed = replace(node, attrs=(Attribute("to", jid),))
    assert client_codec.write(changed, framed=False, preserve_wire=True) == packet(
        b"\xfa" + raw("456:9") + b"\x06"
    )
    assert client_codec.write(changed, framed=False) == bytes.fromhex("f8030304f70109ff82456f")


@pytest.mark.parametrize("server", ["c.us", "unknown.test"])
def test_fa_factory_failure_falls_back_to_full_address_text(client_codec, server):
    original = packet(b"\xfa" + raw("123") + raw(server))
    ordinary = client_codec.read(original, framed=False)
    preserved = client_codec.read(original, framed=False, preserve_wire=True)
    assert ordinary == preserved
    assert ordinary.attrs[0].value == f"123@{server}"
    assert client_codec.write(ordinary, framed=False) == packet(raw(f"123@{server}"))
    assert client_codec.write(preserved, framed=False, preserve_wire=True) == original


def test_fa_fallback_preserved_edit_reencodes_text(client_codec):
    original = packet(b"\xfa" + raw("123") + raw("unknown.test"))
    node = client_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("to", "456@unknown.test"),))
    assert client_codec.write(changed, framed=False, preserve_wire=True) == packet(
        b"\xfa" + raw("456") + raw("unknown.test")
    )


def test_json_model_keeps_normalized_semantics_but_drops_preservation_layout(client_codec):
    original = bytes.fromhex("f8030304f74107ff82123f")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    restored = Node.from_dict(node.to_dict())
    assert restored == node
    assert client_codec.write(restored, framed=False) == bytes.fromhex("f8030304f70107ff82123f")
    assert restored._wire_layout is None


def test_invalid_short_phone_address_is_not_inferred_as_a_jid(client_codec):
    # PhoneUserJid requires at least five ASCII digits; the LID domain differs.
    text = "123@s.whatsapp.net"
    expected = packet(raw(text))
    assert client_codec.write(Node("iq", attrs={"to": text}), framed=False) == expected
    assert client_codec.read(expected, framed=False).attrs[0].value == text


@pytest.mark.parametrize("user,server", [
    ("123", "s.whatsapp.net"),
    ("012345", "s.whatsapp.net"),
    ("12345", "unknown.test"),
    ("0", "lid"),
    ("0123", "lid"),
    ("1234567890123456", "lid"),
])
def test_invalid_fa_jid_falls_back_to_string_instead_of_failing(client_codec, user, server):
    original = packet(b"\xfa" + raw(user) + raw(server))
    node = client_codec.read(original, framed=False, preserve_wire=True)
    assert node.attrs[0].value == f"{user}@{server}"
    assert client_codec.write(node, framed=False) == packet(raw(f"{user}@{server}"))
    assert client_codec.write(node, framed=False, preserve_wire=True) == original


@pytest.mark.parametrize("flags,device,user,address", [
    (0, 7, "123", "123:7@s.whatsapp.net"),
    (1, 7, "0", "0:7@lid"),
    (1, 7, "0123", "0123:7@lid"),
    (128, 7, "12345", "12345:7@hosted"),
    (129, 7, "12345", "12345:7@hosted.lid"),
    (1, 100, "123", "123:100@lid"),
    (1, 255, "123", "123:255@lid"),
])
def test_invalid_f7_jid_factory_falls_back_to_address_text(
    client_codec, flags, device, user, address,
):
    # Native execution and the DEX shared catch cover FA, F7, and F4, even
    # though the decompiled Java initially made the catch look FA-specific.
    encoded = packet(bytes([247, flags, device]) + raw(user))
    ordinary = client_codec.read(encoded, framed=False)
    preserved = client_codec.read(encoded, framed=False, preserve_wire=True)
    assert ordinary == preserved
    assert ordinary.attrs[0].value == address
    assert client_codec.write(ordinary, framed=False) == packet(raw(address))
    assert client_codec.write(preserved, framed=False, preserve_wire=True) == encoded


def test_fa_explicit_zero_device_keeps_device_wrapper_while_f7_zero_is_omitted(client_codec):
    pair = packet(b"\xfa" + raw("123:0") + b"\x06")
    compact = bytes.fromhex("f8030304f70100ff82123f")
    from_pair = client_codec.read(pair, framed=False, preserve_wire=True)
    from_compact = client_codec.read(compact, framed=False, preserve_wire=True)
    assert from_pair.attrs[0].value.user == "123"
    assert from_pair.attrs[0].value.server == "lid"
    assert from_pair.attrs[0].value.device == 0
    assert str(from_compact.attrs[0].value) == "123@lid"
    assert client_codec.write(from_pair, framed=False) == compact
    assert client_codec.write(from_compact, framed=False) == bytes.fromhex("f8030304faff82123f06")
    assert client_codec.write(from_pair, framed=False, preserve_wire=True) == pair
    assert client_codec.write(from_compact, framed=False, preserve_wire=True) == compact


def test_fa_interop_normalizes_to_f4_and_preserves_original_pair(client_codec):
    original = packet(b"\xfa" + raw("42-123") + b"\x07")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    jid = node.attrs[0].value
    assert isinstance(jid, JID)
    assert jid.user == "123"
    assert jid.server == "interop"
    assert jid.integrator == 42
    assert jid.device == 0
    assert client_codec.write(node, framed=False) == bytes.fromhex("f8030304f4ff82123f0000002a00")
    assert client_codec.write(node, framed=False, preserve_wire=True) == original


def test_preserved_fa_interop_edit_reencodes_current_fields(client_codec):
    original = packet(b"\xfa" + raw("42-123") + b"\x07")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    jid = replace(node.attrs[0].value, user="456", integrator=43)
    changed = replace(node, attrs=(Attribute("to", jid),))
    assert client_codec.write(changed, framed=False) == bytes.fromhex("f8030304f4ff82456f0000002b00")
    assert client_codec.write(changed, framed=False, preserve_wire=True) == packet(
        b"\xfa" + raw("43-456") + b"\x07"
    )


def test_nonzero_interop_device_factory_falls_back_to_text(client_codec):
    wire = bytes.fromhex("f8030304f4ff82123f0001002a00")
    node = client_codec.read(wire, framed=False, preserve_wire=True)
    assert node.attrs[0].value == "42-123:1@interop"
    assert client_codec.write(node, framed=False) == packet(raw("42-123:1@interop"))
    assert client_codec.write(node, framed=False, preserve_wire=True) == wire


def test_f4_fallback_preserved_account_edit_reencodes_current_text(client_codec):
    original = bytes.fromhex("f8030304f4ff82123f0001002a00")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("to", "42-456:1@interop"),))
    assert client_codec.write(changed, framed=False) == packet(raw("42-456:1@interop"))
    assert client_codec.write(changed, framed=False, preserve_wire=True) == bytes.fromhex(
        "f8030304f4ff82456f0001002a00"
    )


def test_f4_zero_integrator_factory_falls_back_and_preserves_tuple(client_codec):
    original = bytes.fromhex("f8030304f4ff82123f0000000000")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    assert node.attrs[0].value == "0-123@interop"
    assert client_codec.write(node, framed=False) == packet(raw("0-123@interop"))
    assert client_codec.write(node, framed=False, preserve_wire=True) == original


def test_f7_empty_user_device_fallback_preserves_omitted_device(client_codec):
    original = bytes.fromhex("f8030304f7010700")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    assert node.attrs[0].value == "lid"
    # The fallback is a string, so its dictionary token wins on default write.
    assert client_codec.write(node, framed=False) == bytes.fromhex("f803030406")
    assert client_codec.write(node, framed=False, preserve_wire=True) == original


@pytest.mark.parametrize("tuple_bytes", [
    "f4ff82123f0000000001",  # Unknown interop domain.
    "f4ff82123f0001000002",  # Group device must be zero.
    "f4ff82123f0000000102",  # Group integrator must be zero.
    "f4000000002a00",        # Missing interop account.
    "f4ff000000002a00",      # Empty interop account.
])
def test_f4_structure_errors_do_not_use_factory_string_fallback(client_codec, tuple_bytes):
    for preserve in (False, True):
        with pytest.raises(ProtocolError):
            client_codec.read(packet(bytes.fromhex(tuple_bytes)), framed=False, preserve_wire=preserve)


def test_ignored_agent_spelling_and_device_lexeme_survive_preservation(client_codec):
    original = packet(b"\xfa" + raw("12345.ignored:+007") + b"\x05")
    node = client_codec.read(original, framed=False, preserve_wire=True)
    jid = node.attrs[0].value
    assert isinstance(jid, JID)
    assert jid.user == "12345"
    assert jid.server == "s.whatsapp.net"
    assert jid.device == 7
    assert client_codec.write(node, framed=False) == bytes.fromhex("f8030304f70007ff8312345f")
    assert client_codec.write(node, framed=False, preserve_wire=True) == original
    changed = replace(node, attrs=(Attribute("to", replace(jid, user="45678")),))
    assert client_codec.write(changed, framed=False) == bytes.fromhex("f8030304f70007ff8345678f")
    assert client_codec.write(changed, framed=False, preserve_wire=True) == packet(
        b"\xfa" + raw("45678.ignored:+007") + b"\x05"
    )


@pytest.mark.parametrize("user,wire_domain,semantic_domain,canonical_domain", [
    ("12345", 11, "s.whatsapp.net", 5),
    ("123", 12, "lid", 6),
])
def test_fa_hosted_without_device_normalizes_domain_and_preserves_original(
    client_codec, user, wire_domain, semantic_domain, canonical_domain,
):
    original = packet(b"\xfa" + raw(user) + bytes([wire_domain]))
    node = client_codec.read(original, framed=False, preserve_wire=True)
    jid = node.attrs[0].value
    assert isinstance(jid, JID)
    assert jid.user == user
    assert jid.server == semantic_domain
    packed_user = bytes.fromhex("ff8312345f" if user == "12345" else "ff82123f")
    expected = packet(b"\xfa" + packed_user + bytes([canonical_domain]))
    assert client_codec.write(node, framed=False) == expected
    assert client_codec.write(node, framed=False, preserve_wire=True) == original


@pytest.mark.parametrize("flags,user,semantic_domain,canonical_domain", [
    (128, "12345", "s.whatsapp.net", 5),
    (129, "123", "lid", 6),
])
def test_f7_hosted_zero_device_normalizes_domain_and_preserves_original(
    client_codec, flags, user, semantic_domain, canonical_domain,
):
    packed_user = bytes.fromhex("ff8312345f" if user == "12345" else "ff82123f")
    original = packet(bytes([247, flags, 0]) + packed_user)
    node = client_codec.read(original, framed=False, preserve_wire=True)
    jid = node.attrs[0].value
    assert isinstance(jid, JID)
    assert jid.user == user
    assert jid.server == semantic_domain
    expected = packet(b"\xfa" + packed_user + bytes([canonical_domain]))
    assert client_codec.write(node, framed=False) == expected
    assert client_codec.write(node, framed=False, preserve_wire=True) == original
