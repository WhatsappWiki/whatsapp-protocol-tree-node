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
