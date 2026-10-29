import random
import zlib

import pytest

from protocol_tree_node import Attribute, Codec, Limits, Node, ProtocolError


@pytest.mark.parametrize("wire", [
    "", "f8", "f9", "f901", "00", "f80003", "f80100", "f80101",
    "f801f0", "f801f5", "f801f6", "fc0003", "f803030000", "f803030401",
    "f80203fc02ff", "f80203fd000002ff", "f80203fe00000002ff",
    "f8030304ff80", "f8030304ff01dd", "f8030304ff01ee", "f8030304ff01ff",
    "f8030304ff811f00",  # valid value with trailing data
    "f80203f801f80102",  # stream end cannot be a child
    "f80103ff", "f80103f80105",  # trailing byte / extra root
])
def test_invalid_or_incomplete_raw_wire(codec, wire):
    with pytest.raises(ProtocolError):
        codec.read(bytes.fromhex(wire), framed=False)


@pytest.mark.parametrize("flag", [1, 3, 4, 5, 128, 255])
def test_unsupported_frame_flags(codec, flag):
    with pytest.raises(ProtocolError):
        codec.read(bytes([flag]) + bytes.fromhex("f80103"))


@pytest.mark.parametrize("wire", [b"", b"\x00", b"\x02", b"\x02not-zlib"])
def test_invalid_frame_payload(codec, wire):
    with pytest.raises(ProtocolError):
        codec.read(wire)


@pytest.mark.parametrize("trailer", [b"\x00", b"garbage", zlib.compress(b"anything")])
def test_compressed_trailing_and_concatenated_members_rejected(codec, trailer):
    wire = b"\x02" + zlib.compress(bytes.fromhex("f80103")) + trailer
    with pytest.raises(ProtocolError):
        codec.read(wire)


def test_compressed_bad_checksum(codec):
    wire = bytearray(b"\x02" + zlib.compress(bytes.fromhex("f80103")))
    wire[-1] ^= 1
    with pytest.raises(ProtocolError):
        codec.read(bytes(wire))


def test_every_truncation_of_nested_node(codec):
    node = Node("node", attrs={"key": "12345"}, children=(
        Node("child", data=bytes(range(256))),
        Node("child", attrs={"key": "non-numeric"}),
    ))
    for compressed in (False, True):
        complete = codec.write(node, compress=compressed)
        for boundary in range(len(complete)):
            with pytest.raises(ProtocolError):
                codec.read(complete[:boundary])


@pytest.mark.parametrize("wire", ["f801fc01ff", "f8030304fc01ff", "f80303fc01ff00"])
def test_invalid_utf8_in_text_is_reported(codec, wire):
    with pytest.raises(ProtocolError):
        codec.read(bytes.fromhex(wire), framed=False)


def test_binary_data_does_not_require_utf8(codec):
    node = Node("node", data=b"\xff\xc0\x80\0")
    assert codec.read(codec.write(node)) == node


def test_noncanonical_binary20_high_nibble_is_masked(codec):
    assert codec.read(bytes.fromhex("f80203fdf0000161"), framed=False) == Node("node", data=b"a")


def test_noncanonical_binary32_sign_bit_is_masked(codec):
    assert codec.read(bytes.fromhex("f80203fe8000000161"), framed=False) == Node("node", data=b"a")


def test_declared_huge_content_rejected_before_allocation(dictionary):
    codec = Codec(dictionary, limits=Limits(max_bytes=256))
    with pytest.raises(ProtocolError):
        codec.read(bytes.fromhex("f80203fe7fffffff"), framed=False)


def test_packet_and_expanded_size_limits(dictionary):
    normal = Codec(dictionary)
    small = Codec(dictionary, limits=Limits(max_bytes=128))
    node = Node("node", data=b"x" * 10000)
    for compressed in (False, True):
        with pytest.raises(ProtocolError):
            small.read(normal.write(node, compress=compressed))
        with pytest.raises(ProtocolError):
            small.write(node, compress=compressed)


def test_node_count_limit(dictionary):
    normal = Codec(dictionary)
    small = Codec(dictionary, limits=Limits(max_nodes=3))
    node = Node("node", children=(Node("child"),) * 4)
    with pytest.raises(ProtocolError):
        small.read(normal.write(node))
    with pytest.raises(ProtocolError):
        small.write(node)


def test_depth_limit(dictionary):
    normal = Codec(dictionary)
    small = Codec(dictionary, limits=Limits(max_depth=2))
    node = Node("node")
    for _ in range(8):
        node = Node("node", children=(node,))
    with pytest.raises(ProtocolError):
        small.read(normal.write(node))
    with pytest.raises(ProtocolError):
        small.write(node)


def test_attribute_limit(dictionary):
    normal = Codec(dictionary)
    small = Codec(dictionary, limits=Limits(max_attributes=2))
    node = Node("node", attrs=tuple(Attribute("key", "1") for _ in range(3)))
    with pytest.raises(ProtocolError):
        small.read(normal.write(node))
    with pytest.raises(ProtocolError):
        small.write(node)


def test_list_count_protocol_limit(codec):
    with pytest.raises(ProtocolError):
        codec.write(Node("node", children=(Node("child"),) * 65536))


def test_bounded_arbitrary_bytes_raise_only_protocol_errors(dictionary):
    codec = Codec(dictionary, limits=Limits(max_bytes=512, max_depth=8, max_nodes=32, max_attributes=16))
    rng = random.Random(481516)
    for _ in range(1500):
        sample = bytes(rng.randrange(256) for _ in range(rng.randrange(64)))
        try:
            codec.read(sample, framed=False)
        except ProtocolError:
            pass


def test_recursive_jid_is_bounded_separately_from_node_depth(dictionary):
    codec = Codec(dictionary, limits=Limits(max_depth=4))
    value = bytes.fromhex("fc0178")
    for _ in range(12):
        value = b"\xfa" + value + bytes.fromhex("fc0173")
    with pytest.raises(ProtocolError):
        codec.read(bytes.fromhex("f8030304") + value, framed=False)


@pytest.mark.parametrize("kwargs", [
    {"max_bytes": 0}, {"max_bytes": -1}, {"max_bytes": True},
    {"max_depth": 0}, {"max_depth": 257}, {"max_depth": 1.5},
    {"max_nodes": 0}, {"max_attributes": -1},
])
def test_invalid_limits(kwargs):
    with pytest.raises(ValueError):
        Limits(**kwargs)


def test_packet_header_counts_toward_output_byte_limit(dictionary):
    codec = Codec(dictionary, limits=Limits(max_bytes=3))
    assert codec.write(Node("node"), framed=False) == bytes.fromhex("f80103")
    with pytest.raises(ProtocolError):
        codec.write(Node("node"))


def test_unpaired_surrogates_have_protocol_error(codec):
    for node in [Node("\ud800"), Node("node", attrs={"key": "\ud800"})]:
        with pytest.raises(ProtocolError):
            codec.write(node)


def test_invalid_api_types(codec, dictionary):
    with pytest.raises(TypeError):
        codec.read("00f80103")
    with pytest.raises(ProtocolError):
        codec.write({"tag": "node"})
    with pytest.raises(TypeError):
        Codec({"single": [], "dictionaries": []})
    with pytest.raises(TypeError):
        Codec(dictionary, limits={})


@pytest.mark.parametrize("view", [
    lambda data: memoryview(data).cast("I"),
    lambda data: memoryview(data).cast("B", shape=[1, len(data)]),
])
def test_memoryview_limit_uses_total_bytes_before_copy(dictionary, view):
    packet = bytes.fromhex("f80203fc13") + b"x" * 19  # 24 bytes
    codec = Codec(dictionary, limits=Limits(max_bytes=20))
    buffer = view(packet)
    assert len(buffer) < 20 < buffer.nbytes
    with pytest.raises(ProtocolError, match="input exceeds byte limit"):
        codec.read(buffer, framed=False)
