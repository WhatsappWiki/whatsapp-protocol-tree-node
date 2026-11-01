"""Synthetic FA tuples whose wire separator differs from the address factory's."""
from dataclasses import replace

import pytest

from protocol_tree_node import Attribute, Codec, JID, ProtocolError, TokenDictionary


def raw(value):
    data = value.encode("utf-8")
    return bytes([252, len(data)]) + data


def pair(user, server):
    return b"\xfa" + user + server


def packet(value, position="attribute_value"):
    return {
        "tag": b"\xf8\x01" + value,
        "attribute_name": b"\xf8\x03\x03" + value + b"\x00",
        "attribute_value": b"\xf8\x03\x03\x04" + value,
        "data": b"\xf8\x02\x03" + value,
    }[position]


@pytest.fixture
def boundary_codec():
    return Codec(TokenDictionary([None, None, None, "node", "key", "x", "a@newsletter"]))


@pytest.mark.parametrize("position", ["tag", "attribute_name", "attribute_value", "data"])
@pytest.mark.parametrize("wire,local", [
    (pair(b"\0", raw("a@newsletter")), "a"),
    (pair(raw(""), raw("a@newsletter")), "a"),
    (pair(raw("x"), raw("a@newsletter")), "x@a"),
    (pair(b"\x05", b"\x06"), "x@a"),
    (pair(b"\0", pair(raw("a"), raw("newsletter"))), "a"),
    (pair(raw("x"), pair(raw("a"), raw("newsletter"))), "x@a"),
    (pair(pair(raw("x"), raw("s")), pair(raw("a"), raw("newsletter"))), "x@s@a"),
])
def test_factory_keeps_text_but_changes_component_boundary(boundary_codec, wire, local, position):
    encoded = packet(wire, position)
    node = boundary_codec.read(encoded, framed=False, preserve_wire=True)
    assert boundary_codec.read(encoded, framed=False) == node
    address = local + "@newsletter"
    if position == "attribute_value":
        assert node.attrs[0].value == JID(local, "newsletter")
    elif position == "attribute_name":
        assert node.attrs[0].name == address
    elif position == "tag":
        assert node.tag == address
    else:
        assert node.data == address.encode()
    assert boundary_codec.write(node, framed=False, preserve_wire=True) == encoded


@pytest.mark.parametrize("local,expected", [
    ("y@a", pair(raw("y"), raw("a@newsletter"))),
    ("x@long", pair(raw("x"), raw("long@newsletter"))),
])
def test_edits_reencode_fields_without_changing_the_wire_boundary(boundary_codec, local, expected):
    original = packet(pair(raw("x"), raw("a@newsletter")))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", JID(local, "newsletter")),))
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(expected)
    assert boundary_codec.read(output, framed=False) == changed


def test_null_outer_user_allows_edits_in_nested_server(boundary_codec):
    original = packet(pair(b"\0", pair(raw("a"), raw("newsletter"))))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", JID("long", "newsletter")),))
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(pair(b"\0", pair(raw("long"), raw("newsletter"))))
    assert boundary_codec.read(output, framed=False) == changed


@pytest.mark.parametrize("outer_user", [b"\0", raw(""), b"\xff\0", pair(b"\0", raw(""))])
@pytest.mark.parametrize("nested_server", [False, True])
@pytest.mark.parametrize("address,edits,expected", [
    ("42-123.ignored@interop", {"user": "456"}, "42-456.ignored@interop"),
    ("42-123.ignored@interop", {"integrator": 43}, "43-123.ignored@interop"),
    ("+0-123.ignored:0@interop", {"user": "456"}, "+0-456.ignored:0@interop"),
    ("+04-123.ignored@interop", {"user": "456", "integrator": 43}, "43-456.ignored@interop"),
    ("12345.ignored:+007@s.whatsapp.net", {"user": "45678", "device": 9},
     "45678.ignored:+009@s.whatsapp.net"),
    ("123.ignored:+007@lid", {"user": "456", "device": 9}, "456.ignored:+009@lid"),
    ("12345@hosted", {"user": "45678"}, "45678@hosted"),
    ("123@hosted.lid", {"user": "456"}, "456@hosted.lid"),
])
def test_normalized_address_in_fa_server_keeps_its_spelling_on_edit(
    boundary_codec, outer_user, nested_server, address, edits, expected,
):
    def server(value):
        if nested_server:
            local, domain = value.rsplit("@", 1)
            return pair(raw(local), raw(domain))
        return raw(value)

    original = packet(pair(outer_user, server(address)))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    assert isinstance(node.attrs[0].value, JID)
    assert boundary_codec.write(node, framed=False, preserve_wire=True) == original
    changed = replace(node, attrs=(Attribute("key", replace(node.attrs[0].value, **edits)),))
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(pair(outer_user, server(expected)))
    assert boundary_codec.read(output, framed=False) == changed


@pytest.mark.parametrize("outer_user", [b"\0", raw("")])
def test_normalized_address_edit_cannot_change_a_server_dictionary_entry(outer_user):
    address = "42-123.ignored@interop"
    codec = Codec(TokenDictionary([None, None, None, "node", "key", address]))
    original = packet(pair(outer_user, b"\x05"))
    node = codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", replace(node.attrs[0].value, user="456")),))
    with pytest.raises(ProtocolError, match="dictionary changed"):
        codec.write(changed, framed=False, preserve_wire=True)
    assert codec.write(node, framed=False, preserve_wire=True) == original


@pytest.mark.parametrize("outer_user", [b"\0", raw("")])
def test_normalized_server_address_edit_respects_its_byte_length_width(boundary_codec, outer_user):
    suffix = "." + "x" * 220 + "@s.whatsapp.net"
    original = packet(pair(outer_user, raw("12345" + suffix)))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    user = "1234567890123456789"
    changed = replace(node, attrs=(Attribute("key", replace(node.attrs[0].value, user=user)),))
    assert len((user + suffix).encode()) == 255
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(pair(outer_user, raw(user + suffix)))
    assert boundary_codec.read(output, framed=False) == changed
    changed = replace(node, attrs=(Attribute("key", replace(node.attrs[0].value, user=user + "0")),))
    with pytest.raises(ProtocolError, match="preserved length width"):
        boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert boundary_codec.write(node, framed=False, preserve_wire=True) == original


@pytest.mark.parametrize("address", [
    "12345.agent:+007@s.whatsapp.net", "123.agent:+007@lid", "12345@hosted",
])
@pytest.mark.parametrize("user_encoding", ["raw", "wide", "nested"])
@pytest.mark.parametrize("nested_server", [False, True])
@pytest.mark.parametrize("target", [JID("hello@z", "newsletter"), JID("1", "g.us")])
def test_cross_domain_edits_can_still_fill_an_empty_outer_user(
    boundary_codec, address, user_encoding, nested_server, target,
):
    def user(value):
        if user_encoding == "wide":
            encoded = value.encode()
            return b"\xfd" + len(encoded).to_bytes(3, "big") + encoded
        if user_encoding == "nested":
            return pair(b"\0", raw(value))
        return raw(value)

    def server(value):
        return pair(b"\0", raw(value)) if nested_server else raw(value)

    original = packet(pair(user(""), server(address)))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", target),))
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(pair(user(target.user), server(target.server)))
    assert boundary_codec.read(output, framed=False) == changed
    assert boundary_codec.write(node, framed=False, preserve_wire=True) == original


@pytest.mark.parametrize("address", [
    "12345.agent:+007@s.whatsapp.net", "123.agent:+007@lid", "12345@hosted",
])
def test_cross_domain_edits_with_null_user_can_still_select_a_bare_address(boundary_codec, address):
    node = boundary_codec.read(packet(pair(b"\0", raw(address))),
                               framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", JID(None, "g.us")),))
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(pair(b"\0", raw("g.us")))
    assert boundary_codec.read(output, framed=False) == changed


@pytest.mark.parametrize("target", [JID(None, "g.us"), JID("hello@z", "newsletter")])
@pytest.mark.parametrize("nested_server", [False, True])
def test_null_user_interop_cross_domain_edits_raise_protocol_errors(boundary_codec, target, nested_server):
    server = raw("42-123.agent@interop")
    if nested_server:
        server = pair(b"\0", server)
    original = packet(pair(b"\0", server))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", target),))
    with pytest.raises(ProtocolError, match="JID edit no longer fits preserved tuple semantics"):
        boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert boundary_codec.write(node, framed=False, preserve_wire=True) == original


@pytest.mark.parametrize("outer_user", [b"\0", raw(""), b"\xff\0", pair(b"\0", raw(""))])
@pytest.mark.parametrize("nested_server", [False, True])
def test_cross_domain_edits_keep_compatible_server_spelling(boundary_codec, outer_user, nested_server):
    def server(value):
        return pair(b"\0", raw(value)) if nested_server else raw(value)

    original = packet(pair(outer_user, server("12345.agent:+007@s.whatsapp.net")))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", JID("456", "lid", device=9, flags=1)),))
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(pair(outer_user, server("456.agent:+009@lid")))
    assert boundary_codec.read(output, framed=False) == changed


def test_null_user_interop_edit_can_rebuild_a_bare_server_when_spelling_allows(boundary_codec):
    node = boundary_codec.read(packet(pair(b"\0", raw("+04-123@interop"))),
                               framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", JID(None, "g.us")),))
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(pair(b"\0", raw("g.us")))
    assert boundary_codec.read(output, framed=False) == changed


@pytest.mark.parametrize("packed", [False, True])
def test_server_rebuild_discards_partial_output_from_an_incompatible_user_encoding(boundary_codec, packed):
    outer_user = b"\xff\0" if packed else raw("")
    address = "12345@hosted".encode()
    # The wide server remains usable even when a filled FC user exceeds 255 bytes.
    def server(value):
        return b"\xfd" + len(value).to_bytes(3, "big") + value

    original = packet(pair(outer_user, server(address)))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    target = JID("hello@z" if packed else "x" * 256, "newsletter")
    changed = replace(node, attrs=(Attribute("key", target),))
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(pair(outer_user, server(str(target).encode())))
    assert boundary_codec.read(output, framed=False) == changed
    assert boundary_codec.write(node, framed=False, preserve_wire=True) == original


def test_ambiguous_separator_edit_is_rejected(boundary_codec):
    original = packet(pair(raw("x"), raw("a@newsletter")))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", JID("long@a", "newsletter")),))
    with pytest.raises(ProtocolError, match="separator"):
        boundary_codec.write(changed, framed=False, preserve_wire=True)


def test_single_separator_still_allows_user_length_change(boundary_codec):
    original = packet(pair(raw("x"), raw("newsletter")))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", JID("long", "newsletter")),))
    assert boundary_codec.write(changed, framed=False, preserve_wire=True) == packet(
        pair(raw("long"), raw("newsletter"))
    )


@pytest.mark.parametrize("user", ["long@a", "@long", "a@@b", "长@账户"])
@pytest.mark.parametrize("server", [raw("newsletter"), pair(b"\0", raw("newsletter"))])
def test_plain_server_allows_user_length_and_separator_edits(boundary_codec, user, server):
    original = packet(pair(raw("x"), server))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", JID(user, "newsletter")),))
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(pair(raw(user), server))
    assert boundary_codec.read(output, framed=False) == changed


@pytest.mark.parametrize("server,user", [
    ("s.whatsapp.net", "12345"),
    ("g.us", "1"),
    ("call", "0123456789abcdefab"),
])
def test_plain_server_edit_fills_an_empty_user_token(boundary_codec, server, user):
    original = packet(pair(raw(""), raw(server)))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    assert node.attrs[0].value == JID(None, server)
    changed = replace(node, attrs=(Attribute("key", JID(user, server)),))
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(pair(raw(user), raw(server)))
    assert boundary_codec.read(output, framed=False) == changed


def test_plain_server_edit_cannot_fill_a_null_user_token(boundary_codec):
    original = packet(pair(b"\0", raw("s.whatsapp.net")))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", JID("12345", "s.whatsapp.net")),))
    with pytest.raises(ProtocolError, match="null layout"):
        boundary_codec.write(changed, framed=False, preserve_wire=True)


def test_string_edit_cannot_silently_discard_a_leading_separator(boundary_codec):
    original = packet(pair(raw("x"), raw("unknown")))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", "@unknown"),))
    with pytest.raises(ProtocolError, match="separator"):
        boundary_codec.write(changed, framed=False, preserve_wire=True)


@pytest.mark.parametrize("user", [b"\0", raw("")])
def test_leading_separator_is_allowed_inside_the_server_token(boundary_codec, user):
    original = packet(pair(user, raw("unknown")))
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", "@unknown"),))
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(pair(user, raw("@unknown")))
    assert boundary_codec.read(output, framed=False) == changed


@pytest.mark.parametrize("device", ["256", "-1", "2147483648", "-2147483649"])
@pytest.mark.parametrize("position", ["tag", "attribute_name", "attribute_value", "data"])
def test_device_text_overflow_always_raises_protocol_error(boundary_codec, device, position):
    # Keep the delimiter at its saved index, so the actual edited device is
    # validated instead of failing an unrelated separator-position check.
    original = packet(b"\xf7\x00\x07" + raw("x" * len(device)), position)
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    value = "x:" + device + "@s.whatsapp.net"
    if position == "tag":
        changed = replace(node, tag=value)
    elif position == "attribute_name":
        changed = replace(node, attrs=(Attribute(value, None),))
    elif position == "attribute_value":
        changed = replace(node, attrs=(Attribute("key", value),))
    else:
        changed = replace(node, data=value.encode())
    with pytest.raises(ProtocolError, match="device layout"):
        boundary_codec.write(changed, framed=False, preserve_wire=True)


@pytest.mark.parametrize("user", [b"\0", raw(""), raw("1"), raw("group"),
                                  b"\xff\x81\x1f", pair(raw("x"), raw("s"))])
def test_interop_group_edit_cannot_discard_a_leading_separator(boundary_codec, user):
    original = packet(b"\xf4" + user + b"\0\0\0\0\x02")
    node = boundary_codec.read(original, framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", "@interop.g.us"),))
    with pytest.raises(ProtocolError, match="interop text no longer fits tuple semantics"):
        boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert boundary_codec.write(node, framed=False, preserve_wire=True) == original


@pytest.mark.parametrize("value,user", [
    ("interop.g.us", ""),
    ("group@interop.g.us", "group"),
    ("@@interop.g.us", "@"),
    ("a@@interop.g.us", "a@"),
])
@pytest.mark.parametrize("suffix", [b"\0\0\0\0\x02", b"\0\0\0\x01\0"])
def test_interop_group_text_edits_keep_valid_user_boundaries(boundary_codec, value, user, suffix):
    node = boundary_codec.read(packet(b"\xf4" + raw("1") + suffix),
                               framed=False, preserve_wire=True)
    changed = replace(node, attrs=(Attribute("key", value),))
    output = boundary_codec.write(changed, framed=False, preserve_wire=True)
    assert output == packet(b"\xf4" + raw(user) + b"\0\0\0\0\x02")
    assert boundary_codec.read(output, framed=False) == changed
