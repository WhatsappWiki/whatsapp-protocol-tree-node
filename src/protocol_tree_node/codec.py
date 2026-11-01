"""Public codec orchestration; binary traversal and framing are internal."""
from __future__ import annotations

from protocol_tree_node._framing import decode_packet, encode_packet
from protocol_tree_node._reader import _Reader
from protocol_tree_node._writer import _Writer
from protocol_tree_node.dictionary import TokenDictionary
# Keep the original codec-module imports available to existing callers.
from protocol_tree_node.errors import ProtocolError
from protocol_tree_node.limits import Limits
from protocol_tree_node.model import Node, StreamEnd

__all__ = ['Codec', 'Limits', 'ProtocolError']


class Codec:
    """Reusable codec with independent reader/writer state for each call.

    framed=True means the decrypted flags+node envelope, NOT a transport frame.
    Default JID handling follows the client's address factories. Wire layout
    preservation is explicit and does not change the decoded field semantics.
    Do not replace dictionary or limits while a call is in progress.
    """

    def __init__(self, dictionary: TokenDictionary, *, limits: Limits = Limits()):
        if not isinstance(dictionary, TokenDictionary) or not isinstance(limits, Limits):
            raise TypeError("expected TokenDictionary and Limits")
        self.dictionary, self.limits = dictionary, limits


    def read(self, data: bytes | bytearray | memoryview, *, framed: bool = True,
             preserve_wire: bool = False) -> Node | StreamEnd:
        """Decode exactly one node, optionally retaining its encoding choices."""
        payload = decode_packet(data, framed=framed, max_bytes=self.limits.max_bytes)
        return _Reader(payload, self.dictionary, self.limits, preserve_wire).read()

    def write(self, node: Node | StreamEnd, *, framed: bool = True,
              compress: bool = False, preserve_wire: bool = False) -> bytes:
        """Encode current node fields in canonical or retained wire layout."""
        if compress and not framed:
            raise ValueError("compression requires framed=True")
        payload = _Writer(self.dictionary, self.limits, preserve_wire).write(node)
        return encode_packet(payload, framed=framed, compress=compress,
                             max_bytes=self.limits.max_bytes)
