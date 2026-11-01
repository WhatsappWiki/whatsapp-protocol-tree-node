"""WhatsApp Protocol Tree Node binary serialization and deserialization."""
from __future__ import annotations

from protocol_tree_node.codec import Codec
from protocol_tree_node.dictionary import TokenDictionary
from protocol_tree_node.errors import ProtocolError
from protocol_tree_node.limits import Limits
from protocol_tree_node.model import Attribute, JID, Node, STREAM_END, StreamEnd

__all__ = [
    "Codec", "Limits", "ProtocolError", "TokenDictionary", "Attribute",
    "JID", "Node", "STREAM_END", "StreamEnd", "read", "write",
]


def read(data: bytes | bytearray | memoryview, *, dictionary: TokenDictionary,
         framed: bool = True, limits: Limits = Limits(),
         preserve_wire: bool = False) -> Node | StreamEnd:
    """Read one node using an explicitly supplied token dictionary."""
    return Codec(dictionary, limits=limits).read(
        data, framed=framed, preserve_wire=preserve_wire,
    )


def write(node: Node | StreamEnd, *, dictionary: TokenDictionary,
          framed: bool = True, compress: bool = False, limits: Limits = Limits(),
          preserve_wire: bool = False) -> bytes:
    """Write one node using an explicitly supplied token dictionary."""
    return Codec(dictionary, limits=limits).write(
        node, framed=framed, compress=compress, preserve_wire=preserve_wire,
    )
