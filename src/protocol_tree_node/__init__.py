"""WhatsApp Protocol Tree Node binary serialization and deserialization."""
from .codec import Codec, Limits, ProtocolError
from .dictionary import TokenDictionary
from .model import Attribute, JID, Node, STREAM_END, StreamEnd


def read(data, *, dictionary, framed=True, limits=Limits(), preserve_wire=False):
    return Codec(dictionary, limits=limits).read(data, framed=framed, preserve_wire=preserve_wire)


def write(node, *, dictionary, framed=True, compress=False, limits=Limits(), preserve_wire=False):
    return Codec(dictionary, limits=limits).write(node, framed=framed, compress=compress,
                                                preserve_wire=preserve_wire)


__all__ = ["Codec", "Limits", "ProtocolError", "TokenDictionary", "Attribute",
           "JID", "Node", "STREAM_END", "StreamEnd", "read", "write"]
