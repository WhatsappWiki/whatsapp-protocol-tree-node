"""Synthetic wire choices; no private capture contents are embedded here."""
from dataclasses import fields, is_dataclass, replace
import zlib

import pytest

from protocol_tree_node import (
    Attribute, Codec, JID, Limits, Node, ProtocolError, STREAM_END,
    TokenDictionary, read, write,
)


def binary(data, marker=252, prefix_bits=0):
    width = {252: 1, 253: 3, 254: 4}[marker]
    return bytes([marker]) + (prefix_bits | len(data)).to_bytes(width, "big") + data


def attr_packet(value, *, tag=b"\x03", key=b"\x04", head=b"\xf8\x03"):
    return head + tag + key + value


def preserved(codec, packet):
    node = codec.read(packet, framed=False, preserve_wire=True)
    assert codec.write(node, framed=False, preserve_wire=True) == packet
    return node


@pytest.mark.parametrize("marker,bits", [(252, 0), (253, 0), (253, 0xA00000),
                                         (254, 0), (254, 0x80000000)])
def test_binary_width_and_ignored_length_bits(codec, marker, bits):
    packet = attr_packet(binary(b"123", marker, bits),
                         tag=binary(b"node", marker, bits),
                         key=binary(b"key", marker, bits), head=b"\xf9\x00\x03")
    node = preserved(codec, packet)
    assert node == Node("node", {"key": "123"})
    assert codec.write(node, framed=False) != packet
    changed = replace(node, attrs=(Attribute("key", "4567"),))
    output = codec.write(changed, framed=False, preserve_wire=True)
    assert output != packet
    assert codec.read(output, framed=False).attrs[0].value == "4567"


@pytest.mark.parametrize("marker,bits", [(252, 0), (253, 0xF00000), (254, 0x80000000)])
def test_binary_payload_reencoded_from_current_value(codec, marker, bits):
    packet = b"\xf9\x00\x02\x03" + binary(b"\x00\xff\x80", marker, bits)
    node = preserved(codec, packet)
    changed = replace(node, data=b"\x01\x02\x03\x04")
    assert codec.write(changed, framed=False, preserve_wire=True) == (
        b"\xf9\x00\x02\x03" + binary(changed.data, marker, bits)
    )


@pytest.mark.parametrize("packed", [b"\xff\x81\x10", b"\xff\x81\x1e",
                                   b"\xfb\x81\x1a", b"\xff\x00", b"\xfb\x00",
                                   b"\xfb\x02\xab\xcd", b"\xff\x02\xab\xc0"])
def test_packed_kind_padding_and_empty(codec, packed):
    preserved(codec, attr_packet(packed))
    preserved(codec, b"\xf8\x02\x03" + packed)


@pytest.mark.parametrize("marker", [251, 255])
def test_packed_read_supports_full_254_char_capacity(codec, marker):
    packet = attr_packet(bytes([marker, 127]) + b"\x11" * 127)
    node = preserved(codec, packet)
    assert node.attrs[0].value == "1" * 254
    # The ordinary writer deliberately packs only inputs shorter than 128.
    assert codec.write(node, framed=False) != packet


def test_packed_edits_keep_padding_and_recompute_length(codec):
    node = preserved(codec, attr_packet(b"\xff\x81\x10"))
    changed = replace(node, attrs=(Attribute("key", "123"),))
    assert codec.write(changed, framed=False, preserve_wire=True) == attr_packet(b"\xff\x82\x12\x30")


def test_dictionary_alias_and_hex_over_dictionary_are_preserved():
    dictionary = TokenDictionary([None] * 3 + ["node", "key", "1", "same", "same"],
                                 [["same", "same"]])
    codec = Codec(dictionary)
    for value in (b"\x06", b"\x07", b"\xec\x00", b"\xec\x01", b"\xfb\x81\x1f"):
        preserved(codec, attr_packet(value))
        preserved(codec, b"\xf8\x02\x03" + value)


@pytest.mark.parametrize("replacement", [TokenDictionary([], []),
                                        TokenDictionary([None]*3+["changed", "key"], [])])
def test_changed_dictionary_rejects_saved_token(codec, replacement):
    node = preserved(codec, b"\xf8\x01\x03")
    with pytest.raises(ProtocolError, match="dictionary"):
        Codec(replacement).write(node, framed=False, preserve_wire=True)


def test_new_equivalent_dictionary_is_allowed(codec, dictionary):
    node = preserved(codec, b"\xf8\x01\x03")
    other = TokenDictionary(list(dictionary.single), list(dictionary.dictionaries))
    assert Codec(other).write(node, framed=False, preserve_wire=True) == b"\xf8\x01\x03"


@pytest.mark.parametrize("children_head", [b"\x00", b"\xf8\x00", b"\xf9\x00\x00"])
def test_empty_children_are_kept_only_in_preservation_mode(codec, children_head):
    node = preserved(codec, b"\xf9\x00\x02\x03" + children_head)
    assert node.children == ()
    assert codec.write(node, framed=False) == b"\xf8\x01\x03"


def test_nested_nodes_have_independent_layouts(codec):
    child = b"\xf9\x00\x01" + binary(b"child", 254)
    packet = b"\xf9\x00\x02\x03\xf9\x00\x02" + child * 2
    node = preserved(codec, packet)
    changed = replace(node, children=node.children[:1])
    assert codec.write(changed, framed=False, preserve_wire=True) == (
        b"\xf9\x00\x02\x03\xf9\x00\x01" + child
    )


def test_stream_end_preserves_list_width(codec):
    node = preserved(codec, b"\xf9\x00\x01\x02")
    assert node == STREAM_END
    assert repr(node) == repr(STREAM_END)


@pytest.mark.parametrize("jid,semantic_type", [
    (b"\xfa" + binary(b"12", 253) + binary(b"example.test", 254), str),
    (b"\xfa\x00\x06", str),
    (b"\xfa" + binary(b"") + b"\x06", str),
    (b"\xf7\x80\x00" + binary(b"12345", 254), JID),
    (b"\xf7\x7e\x02\xff\x83\x12\x34\x5f", JID),
    (b"\xf7\x00\x00\x00", JID),
    (b"\xf4" + binary(b"12", 253) + b"\x00\x00\x03\xe7\x00", JID),
    (b"\xf4" + binary(b"123") + b"\x00\x00\x00\x00\x02", JID),
])
def test_jid_layouts_and_zero_device_flags(codec, jid, semantic_type):
    node = preserved(codec, attr_packet(jid))
    assert isinstance(node.attrs[0].value, semantic_type)


@pytest.mark.parametrize("jid,address", [
    (b"\xf7\x80\x00" + binary(b"12", 254), "12@hosted"),
    (b"\xf7\x7e\x02\xff\x01\x12", "12:2@s.whatsapp.net"),
    (b"\xf7\x01\x00\x00", "lid"),
    (b"\xf4" + binary(b"12", 253) + b"\x01\x23\x04\x56\x00", "1110-12:291@interop"),
    (b"\xf4" + binary(b"group") + b"\x00\x00\x00\x00\x02", "group@interop.g.us"),
])
def test_jid_factory_fallback_keeps_text_and_preserves_original_tuple(codec, jid, address):
    node = preserved(codec, attr_packet(jid))
    assert node.attrs[0].value == address
    assert codec.write(node, framed=False) == attr_packet(binary(address.encode()))


@pytest.mark.parametrize("jid", [
    b"\xfa" + binary(b"a@b") + binary(b"c@d"),
    b"\xfa\x00" + binary(b"c@d"),
    b"\xfa" + binary(b"") + binary(b"c@d"),
    b"\xf7\x7e\x02" + binary(b"12:3@x"),
    b"\xf7\x01\x00" + binary(b"12:3@x"),
    b"\xfa\xfa" + binary(b"nested") + binary(b"host") + binary(b"outer"),
])
def test_jids_in_string_positions_preserve_separator_layout(codec, jid):
    preserved(codec, b"\xf8\x01" + jid)
    preserved(codec, b"\xf8\x02\x03" + jid)
    preserved(codec, attr_packet(binary(b"value"), key=jid))


@pytest.mark.parametrize("flags,device,address", [(0, 2, "s.whatsapp.net"), (1, 7, "lid")])
def test_nonattribute_jid_omitted_user_preserves_device_from_layout(codec, flags, device, address):
    packet = b"\xf8\x01" + bytes([247, flags, device, 0])
    node = codec.read(packet, framed=False, preserve_wire=True)
    assert node.tag == address
    assert codec.write(node, framed=False, preserve_wire=True) == packet


@pytest.mark.parametrize("tag", ["12:0@s.whatsapp.net", "12:02@s.whatsapp.net",
                                 "123:2@s.whatsapp.net"])
def test_jid_string_edit_must_fit_delimiter_and_rendering(codec, tag):
    node = preserved(codec, b"\xf8\x01\xf7\x00\x02" + binary(b"12"))
    with pytest.raises(ProtocolError, match="JID"):
        codec.write(replace(node, tag=tag), framed=False, preserve_wire=True)


def test_typed_jid_edits_are_encoded_from_current_values(codec):
    node = preserved(codec, attr_packet(b"\xf7\x00\x00" + binary(b"12345")))
    changed = replace(node, attrs=(Attribute("key", JID("4567", "lid", 9, flags=1)),))
    assert codec.write(changed, framed=False, preserve_wire=True) == attr_packet(
        b"\xf7\x01\x09" + binary(b"4567")
    )


@pytest.mark.parametrize("packet,change", [
    (attr_packet(binary(b"1")), lambda n: replace(n, attrs=(Attribute("key", "x" * 256),))),
    (attr_packet(b"\xff\x81\x1f"), lambda n: replace(n, attrs=(Attribute("key", "text"),))),
    (attr_packet(b"\x00"), lambda n: replace(n, attrs=(Attribute("key", "text"),))),
    (attr_packet(b"\x05"), lambda n: replace(n, attrs=(Attribute("key", "different"),))),
    (attr_packet(binary(b"1")), lambda n: replace(n, attrs=())),
    (b"\xf8\x01\x03", lambda n: replace(n, data=b"new")),
    (b"\xf8\x02\x03\xf8\x00", lambda n: replace(n, children=None)),
    (b"\xf8\x02\x03\x00", lambda n: replace(n, children=(Node("child"),))),
    (b"\xf8\x02\x03\xfb\x81\xaf", lambda n: replace(n, data=b"\xff")),
])
def test_incompatible_edits_raise_instead_of_returning_stale_packet(codec, packet, change):
    node = preserved(codec, packet)
    with pytest.raises(ProtocolError):
        codec.write(change(node), framed=False, preserve_wire=True)


def test_metadata_contains_only_layout_and_lost_jid_spelling_not_packet_bytes(codec):
    node = preserved(codec, attr_packet(
        b"\xfa" + binary(b"12345.ignored:+007") + binary(b"s.whatsapp.net")
    ))

    def check(value):
        if is_dataclass(value):
            for field in fields(value):
                if field.name == "jid_spelling":
                    spelling = getattr(value, field.name)
                    assert spelling is None or (
                        isinstance(spelling, tuple) and len(spelling) == 2
                        and (spelling[0] is None or isinstance(spelling[0], str))
                        and isinstance(spelling[1], str)
                    )
                    continue
                check(getattr(value, field.name))
        elif isinstance(value, tuple):
            for child in value:
                check(child)
        else:
            assert value is None or type(value) in (int, bool) or value in ("none", "data", "children")

    check(node._wire_layout)
    assert node == replace(node, _wire_layout=None)
    assert "wire_layout" not in repr(node)
    assert Node.from_dict(node.to_dict()) == node
    assert Node.from_dict(node.to_dict())._wire_layout is None


@pytest.mark.parametrize("node", [Node("node"), STREAM_END])
def test_preserve_write_requires_metadata(codec, node):
    with pytest.raises(ProtocolError, match="read with preserve_wire=True"):
        codec.write(node, preserve_wire=True)


def test_framing_and_compression_are_explicit(codec, dictionary):
    packet = attr_packet(binary(b"123", 253))
    envelope = b"\x02" + zlib.compress(packet, level=0)
    node = read(envelope, dictionary=dictionary, preserve_wire=True)
    assert write(node, dictionary=dictionary, framed=False, preserve_wire=True) == packet
    assert write(node, dictionary=dictionary, preserve_wire=True) == b"\x00" + packet
    compressed = write(node, dictionary=dictionary, compress=True, preserve_wire=True)
    assert compressed[0] == 2
    assert zlib.decompress(compressed[1:]) == packet
    assert codec.read(envelope) == node


@pytest.mark.parametrize("limit", [Limits(max_bytes=4), Limits(max_depth=1), Limits(max_nodes=1)])
def test_preserved_writer_enforces_resource_limits(codec, dictionary, limit):
    node = preserved(codec, b"\xf8\x02\x03\xf8\x01\xf8\x01\x05")
    with pytest.raises(ProtocolError, match="limit"):
        Codec(dictionary, limits=limit).write(node, framed=False, preserve_wire=True)


def test_preservation_reads_apply_normal_malformed_packet_checks(codec):
    packet = attr_packet(binary(b"123", 254))
    for end in range(len(packet)):
        with pytest.raises(ProtocolError):
            codec.read(packet[:end], framed=False, preserve_wire=True)
    with pytest.raises(ProtocolError, match="trailing"):
        codec.read(packet + b"\x00", framed=False, preserve_wire=True)
