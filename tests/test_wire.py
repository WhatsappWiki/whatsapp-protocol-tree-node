"""Literal golden bytes and format boundaries, independent of the encoder.

The nibble and byte-length golden cases correspond to the APK A06 DEX replay
documented in protocol-tree-analysis. No captured account data is embedded.
"""
import zlib

import pytest

from protocol_tree_node import Attribute, Codec, Node, ProtocolError, STREAM_END, TokenDictionary


def raw(hex_text):
    return bytes.fromhex(hex_text)


@pytest.mark.parametrize(
    "node, wire",
    [
        (Node("node"), "f80103"),
        (Node("node", data=b""), "f80203fc00"),
        (Node("node", data=b"123"), "f80203fc03313233"),
        (Node("node", attrs=(Attribute("key", None),)), "f803030400"),
        (Node("node", attrs=(Attribute("key", ""),)), "f8030304ff00"),
        (Node("node", children=(Node("child"),)), "f80203f801f80105"),
        (Node("node", attrs=(Attribute("key", "node"),)), "f803030403"),
        (Node("node", attrs=(Attribute("key", "A:B"),)), "f8030304fc03413a42"),
    ],
)
def test_literal_nodes(codec, node, wire):
    encoded = raw(wire)
    assert codec.read(encoded, framed=False) == node
    assert codec.write(node, framed=False) == encoded
    assert codec.read(b"\0" + encoded) == node
    assert codec.write(node) == b"\0" + encoded


@pytest.mark.parametrize(
    "text, packed",
    [
        ("12345", "ff8312345f"),
        ("12:34", "ff8312c34f"),
        ("12-.", "ff0212ab"),
        ("ABCDEF", "fb03abcdef"),
        ("abc", "fc03616263"),
        ("A:B", "fc03413a42"),
        ("0", "ff810f"),
        ("-", "ff81af"),
        (".", "ff81bf"),
        (":", "ff81cf"),
        ("0123456789-.:", "ff870123456789abcf"),
        ("0123456789ABCDEF", "fb080123456789abcdef"),
    ],
)
def test_packed_literals(codec, text, packed):
    node = Node("node", attrs=(Attribute("key", text),))
    encoded = raw("f8030304" + packed)
    assert codec.write(node, framed=False) == encoded
    assert codec.read(encoded, framed=False) == node


@pytest.mark.parametrize("length", [0, 1, 2, 127, 128, 255, 256, 65535, 65536, 1048575, 1048576])
def test_data_byte_length_boundaries(codec, length):
    data = bytes((i % 256 for i in range(length)))
    if length < 256:
        header = b"\xfc" + bytes([length])
    elif length < 1048576:
        header = b"\xfd" + length.to_bytes(3, "big")
    else:
        header = b"\xfe" + length.to_bytes(4, "big")
    expected = raw("f80203") + header + data
    node = Node("node", data=data)
    assert codec.write(node, framed=False) == expected
    assert codec.read(expected, framed=False) == node


@pytest.mark.parametrize("length, prefix", [(127, "ffc0"), (128, "fc80"), (255, "fcff"), (256, "fd000100")])
def test_packing_cutoff(codec, length, prefix):
    node = Node("node", attrs=(Attribute("key", "1" * length),))
    wire = codec.write(node, framed=False)
    assert wire.startswith(raw("f8030304" + prefix))
    assert codec.read(wire, framed=False) == node


@pytest.mark.parametrize("count, prefix", [(1, "f801"), (255, "f8ff"), (256, "f90100"), (65535, "f9ffff")])
def test_child_list_width(codec, count, prefix):
    child = Node("child")
    node = Node("node", children=(child,) * count)
    encoded = codec.write(node, framed=False)
    assert encoded == raw("f80203" + prefix) + raw("f80105") * count
    assert codec.read(encoded, framed=False) == node


def test_attribute_list_width_and_order(codec):
    attrs = tuple(Attribute("key", str(i)) for i in range(128))
    node = Node("node", attrs=attrs)
    encoded = codec.write(node, framed=False)
    assert encoded[:4] == raw("f9010103")  # 1 + 2 * 128 = 257
    assert codec.read(encoded, framed=False) == node
    assert len(codec.read(encoded, framed=False).attrs) == 128


def test_tag_and_key_not_nibble_packed(codec):
    node = Node("123", attrs=(Attribute("456", "789"),))
    assert codec.write(node, framed=False) == raw("f803fc03313233fc03343536ff82789f")


def test_unicode_lengths_are_utf8_bytes(codec):
    node = Node("节点", attrs=(Attribute("键", "你好🙂"),), data="🚀".encode())
    wire = codec.write(node, framed=False)
    assert b"\xfc\x06" + "节点".encode() in wire
    assert b"\xfc\x0a" + "你好🙂".encode() in wire
    assert codec.read(wire, framed=False) == node


def test_empty_children_normalize_to_no_content(codec):
    assert codec.write(Node("node", children=()), framed=False) == raw("f80103")


@pytest.mark.parametrize("value", ["12345", "ABCDEF"])
def test_packed_leaf_read_rewrites_as_bytes(codec, value):
    source = "ff8312345f" if value == "12345" else "fb03abcdef"
    node = codec.read(raw("f80203" + source), framed=False)
    assert node == Node("node", data=value.encode())
    assert codec.write(node, framed=False) == raw("f80203fc") + bytes([len(value)]) + value.encode()


def test_token_leaf_content(codec):
    node = codec.read(raw("f8020305"), framed=False)
    assert node == Node("node", data=b"child")


def test_bundled_iq_example():
    codec = Codec(TokenDictionary.bundled())
    node = Node("iq", attrs=(Attribute("id", "12345"), Attribute("type", "get")),
                children=(Node("ping", attrs=(Attribute("xmlns", "urn:xmpp:ping"),)),))
    expected = raw("00f8061908ff8312345f0429f801f80356162b")
    assert codec.write(node) == expected
    assert codec.read(expected) == node


@pytest.mark.parametrize("compressed", [False, True])
def test_stream_end(codec, compressed):
    expected = b"\x02" + zlib.compress(raw("f80102")) if compressed else raw("00f80102")
    assert codec.read(expected) == STREAM_END
    encoded = codec.write(STREAM_END, compress=compressed)
    assert codec.read(encoded) == STREAM_END
    if not compressed:
        assert encoded == expected
    assert codec.write(STREAM_END, framed=False) == raw("f80102")


def test_compression_has_zlib_wrapper_and_outside_flag(codec):
    node = Node("node", data=b"hello" * 1000)
    wire = codec.write(node, compress=True)
    assert wire[0] == 2
    assert zlib.decompress(wire[1:]) == codec.write(node, framed=False)
    assert codec.read(wire) == node
    external = b"\x02" + zlib.compress(codec.write(node, framed=False), level=1)
    assert codec.read(external) == node


def test_compression_requires_framed_api(codec):
    with pytest.raises(ValueError):
        codec.write(Node("node"), framed=False, compress=True)
