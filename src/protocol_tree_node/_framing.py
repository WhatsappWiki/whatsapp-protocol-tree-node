"""Bounded flags + node envelopes and optional zlib compression."""
from __future__ import annotations

import sys
import zlib

from protocol_tree_node.errors import ProtocolError

__all__ = []


def decode_packet(data: bytes | bytearray | memoryview, *, framed: bool, max_bytes: int) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if size > max_bytes:
        raise ProtocolError("input exceeds byte limit")
    data = bytes(data)
    if framed:
        if not data:
            raise ProtocolError("missing packet flags")
        flags, data = data[0], data[1:]
        if flags & 1:
            raise ProtocolError("fragmented stanza is unsupported")
        if flags & ~2:
            raise ProtocolError("unknown packet flags")
        if flags & 2:
            try:
                inflater = zlib.decompressobj()
                # zlib takes Py_ssize_t; Limits accepts any positive Python int.
                data = inflater.decompress(data, min(max_bytes + 1, sys.maxsize))
            except zlib.error as exc:
                raise ProtocolError("invalid zlib packet") from exc
            if len(data) > max_bytes:
                raise ProtocolError("decompressed packet exceeds byte limit")
            if not inflater.eof or inflater.unconsumed_tail or inflater.unused_data:
                raise ProtocolError("incomplete or trailing zlib packet")
    return data


def encode_packet(data: bytes, *, framed: bool, compress: bool, max_bytes: int) -> bytes:
    if framed:
        data = b"\x02" + zlib.compress(data) if compress else b"\0" + data
    if len(data) > max_bytes:
        raise ProtocolError("packet exceeds byte limit")
    return data
