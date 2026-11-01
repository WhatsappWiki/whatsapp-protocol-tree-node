"""Public imports and per-call isolation across codec modes."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import zlib

import pytest

from protocol_tree_node import Codec, Limits, Node, ProtocolError, read, write
from protocol_tree_node.codec import Limits as LegacyLimits, ProtocolError as LegacyError
from protocol_tree_node.errors import ProtocolError as DefinedError
from protocol_tree_node.limits import Limits as DefinedLimits


# Noncanonical list width and packed padding must survive preservation.
RAW = bytes.fromhex("f900030304ff82123a")
CANONICAL = bytes.fromhex("f8030304ff82123f")


def test_existing_codec_imports_keep_type_identity(dictionary):
    assert LegacyLimits is DefinedLimits is Limits
    assert LegacyError is DefinedError is ProtocolError
    codec = Codec(dictionary, limits=LegacyLimits(max_bytes=3))
    with pytest.raises(LegacyError, match="packet exceeds byte limit"):
        codec.write(Node("node"))


@pytest.mark.parametrize("framed,compress", [(False, False), (True, False), (True, True)])
@pytest.mark.parametrize("preserve_wire", [False, True])
def test_function_api_forwards_wire_and_frame_options(dictionary, framed, compress, preserve_wire):
    limits = Limits(max_bytes=64)
    packet = (b"\x02" + zlib.compress(RAW) if compress else b"\0" + RAW) if framed else RAW
    node = read(packet, dictionary=dictionary, limits=limits,
                framed=framed, preserve_wire=preserve_wire)
    result = write(node, dictionary=dictionary, limits=limits,
                   framed=framed, compress=compress, preserve_wire=preserve_wire)
    payload = zlib.decompress(result[1:]) if compress else result[1:] if framed else result
    assert payload == (RAW if preserve_wire else CANONICAL)
    assert node == Node("node", attrs={"key": "123"})


@pytest.mark.parametrize("preserve_wire", [False, True])
def test_failures_do_not_leak_reader_or_writer_state(dictionary, preserve_wire):
    codec = Codec(dictionary, limits=Limits(max_nodes=2))
    good = codec.read(RAW, framed=False, preserve_wire=preserve_wire)
    with pytest.raises(ProtocolError, match="truncated"):
        codec.read(RAW[:-1], framed=False, preserve_wire=preserve_wire)
    bad = replace(good, data=b"x") if preserve_wire else Node("node", children=(good, good))
    with pytest.raises(ProtocolError):
        codec.write(bad, framed=False, preserve_wire=preserve_wire)
    assert codec.read(RAW, framed=False, preserve_wire=preserve_wire) == good
    assert codec.write(good, framed=False, preserve_wire=preserve_wire) == (
        RAW if preserve_wire else CANONICAL
    )


def test_same_codec_can_mix_preserved_and_canonical_calls_concurrently(codec):
    def roundtrip(index):
        preserve_wire = bool(index % 2)
        compress = bool(index % 3)
        node = codec.read(RAW, framed=False, preserve_wire=preserve_wire)
        packet = codec.write(node, compress=compress, preserve_wire=preserve_wire)
        payload = zlib.decompress(packet[1:]) if compress else packet[1:]
        assert payload == (RAW if preserve_wire else CANONICAL)
        assert codec.read(packet) == node

    with ThreadPoolExecutor(max_workers=8) as workers:
        list(workers.map(roundtrip, range(96)))
