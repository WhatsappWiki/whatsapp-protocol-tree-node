"""Canonical and layout-preserving binary node encoding."""
from __future__ import annotations

from protocol_tree_node._jid_wire import preserved_jid_parts
from protocol_tree_node.dictionary import TokenDictionary
from protocol_tree_node.errors import ProtocolError
from protocol_tree_node.jid import is_protocol_compliant, normalize_jid, try_parse_jid
from protocol_tree_node.layout import NodeLayout, TokenLayout
from protocol_tree_node.limits import Limits
from protocol_tree_node.model import JID, Node, StreamEnd

__all__ = []


class _Writer:
    """One node traversal and output buffer per write operation."""

    def __init__(self, dictionary: TokenDictionary, limits: Limits, preserve_wire: bool = False):
        self.dictionary, self.limits = dictionary, limits
        self.output = bytearray()
        self.nodes = 0
        self.preserve_wire = preserve_wire

    def emit(self, data: bytes | bytearray) -> None:
        if len(data) > self.limits.max_bytes - len(self.output):
            raise ProtocolError("output exceeds byte limit")
        self.output.extend(data)

    def list_size(self, size):
        if size == 0:
            self.emit(b"\0")
        elif size < 256:
            self.emit(bytes([248, size]))
        elif size < 65536:
            self.emit(b"\xf9" + size.to_bytes(2, "big"))
        else:
            raise ProtocolError("list too long")

    def raw(self, data, pack=False):
        length = len(data)
        if length > self.limits.max_bytes or length >= 1 << 31:
            raise ProtocolError("binary value exceeds byte limit")
        if pack and length < 128:
            for marker, alphabet in ((255, b"0123456789-.:"), (251, b"0123456789ABCDEF")):
                if all(c in alphabet for c in data):
                    packed = bytearray((length + 1) // 2)
                    for i, c in enumerate(data):
                        packed[i // 2] |= alphabet.index(c) << (4 if i % 2 == 0 else 0)
                    if length & 1:
                        packed[-1] |= 15
                    self.emit(bytes([marker, len(packed) | ((length & 1) << 7)]))
                    self.emit(packed)
                    return
        if length < 256:
            self.emit(bytes([252, length]))
        elif length < 1 << 20:
            self.emit(b"\xfd" + length.to_bytes(3, "big"))
        else:
            self.emit(b"\xfe" + length.to_bytes(4, "big"))
        self.emit(data)

    def text(self, value, *, pack=False, infer_jid=False):
        if value is None:
            self.emit(b"\0")
        elif isinstance(value, JID):
            try:
                value = normalize_jid(value)
            except ValueError as exc:
                raise ProtocolError("invalid JID object") from exc
            if is_protocol_compliant(value):
                self.jid(value)
            else:
                self.text(str(value), pack=pack)
        else:
            token = self.dictionary.token(value)
            if token is not None:
                self.emit(token)
            else:
                jid = try_parse_jid(value, bare=value.find("@") < 1) if infer_jid else None
                if jid is not None and is_protocol_compliant(jid):
                    self.jid(jid)
                    return
                try:
                    self.raw(value.encode("utf-8"), pack)
                except UnicodeEncodeError as exc:
                    raise ProtocolError("string contains unpaired surrogate") from exc

    def jid(self, jid):
        if jid.integrator is not None:
            if not 0 <= jid.device < 65536 or not 0 <= jid.integrator < 65536:
                raise ProtocolError("interop JID exceeds uint16 wire width")
            self.emit(b"\xf4")
            self.text(jid.user, pack=True)
            self.emit(jid.device.to_bytes(2, "big") + jid.integrator.to_bytes(2, "big"))
            self.emit(bytes([0 if jid.server == "interop" else 2]))
        elif jid.device > 0 or (jid.flags is not None and jid.server in ("lid", "hosted.lid")):
            if not 0 <= jid.device < 256:
                raise ProtocolError("device JID exceeds uint8 wire width")
            flags = {"s.whatsapp.net": 0, "lid": 1, "hosted": 128,
                     "hosted.lid": 129, "bot": 0}[jid.server]
            self.emit(bytes([247, flags, jid.device]))
            self.text(jid.user, pack=True)
        else:
            self.emit(b"\xfa")
            self.text(jid.user or None, pack=True)
            self.text(jid.server)

    def preserved_list(self, size, marker):
        if marker == 0 and size == 0:
            self.emit(b"\0")
        elif marker == 248 and 0 <= size < 256:
            self.emit(bytes([248, size]))
        elif marker == 249 and 0 <= size < 65536:
            self.emit(b"\xf9" + size.to_bytes(2, "big"))
        else:
            raise ProtocolError("list no longer fits preserved layout")

    def preserved_token(self, value, layout, nesting=0):
        if not isinstance(layout, TokenLayout):
            raise ProtocolError("missing token layout")
        if nesting > self.limits.max_depth:
            raise ProtocolError("preserved JID nesting exceeds depth limit")
        marker = layout.marker
        if marker == 0:
            if value is not None:
                raise ProtocolError("value no longer fits null layout")
            self.emit(b"\0")
            return
        if marker in (252, 253, 254):
            if isinstance(value, str):
                try:
                    data = value.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise ProtocolError("string contains unpaired surrogate") from exc
            elif isinstance(value, bytes):
                data = value
            else:
                raise ProtocolError("value no longer fits binary layout")
            width = {252: 1, 253: 3, 254: 4}[marker]
            maximum = {252: 256, 253: 1 << 20, 254: 1 << 31}[marker]
            if len(data) >= maximum:
                raise ProtocolError("value no longer fits preserved length width")
            self.emit(bytes([marker]) + (layout.prefix_bits | len(data)).to_bytes(width, "big"))
            self.emit(data)
            return
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ProtocolError("content no longer fits preserved text encoding") from exc
        if 3 <= marker < 240:
            try:
                text = (self.dictionary.single[marker] if marker < 236 else
                        self.dictionary.dictionaries[marker - 236][layout.index])
            except (IndexError, TypeError) as exc:
                raise ProtocolError("preserved dictionary entry is unavailable") from exc
            if not text or value != text:
                raise ProtocolError("value or dictionary changed at preserved token")
            self.emit(bytes([marker]) if marker < 236 else bytes([marker, layout.index]))
            return
        if marker in (251, 255):
            alphabet = "0123456789ABCDEF" if marker == 251 else "0123456789-.:"
            if not isinstance(value, str) or len(value) > 254 or any(c not in alphabet for c in value):
                raise ProtocolError("value no longer fits preserved packed encoding")
            packed = bytearray((len(value) + 1) // 2)
            for i, char in enumerate(value):
                packed[i // 2] |= alphabet.index(char) << (4 if i % 2 == 0 else 0)
            if len(value) & 1:
                packed[-1] |= layout.padding
            self.emit(bytes([marker, len(packed) | ((len(value) & 1) << 7)]))
            self.emit(packed)
            return
        if marker == 250:
            # Prefer the existing FA field rules whenever they still fit.
            # Keep retries inline to avoid an extra frame per nested JID.
            alternatives = ((False, True) if isinstance(value, JID) and
                            layout.jid_spelling is not None and not layout.jid_spelling[0]
                            else (True,))
            for server_spelling in alternatives:
                start = len(self.output)
                try:
                    user, server, _, _ = preserved_jid_parts(value, layout, server_spelling=server_spelling)
                    self.emit(b"\xfa")
                    self.preserved_token(user, layout.user, nesting+1)
                    self.preserved_token(server, layout.server, nesting+1)
                    return
                except ProtocolError:
                    del self.output[start:]
                    if server_spelling:
                        raise
        if marker in (244, 247):
            user, server, device, integrator = preserved_jid_parts(value, layout)
            if marker == 247:
                domains = {"s.whatsapp.net": 0, "lid": 1, "hosted": 128, "hosted.lid": 129}
                if server not in domains or integrator or not 0 <= device < 256:
                    raise ProtocolError("JID no longer fits device layout")
                flags = (layout.flags & ~129) | domains[server]
                self.emit(bytes([247, flags, device]))
                self.preserved_token(user, layout.user, nesting+1)
            else:
                if ((isinstance(value, JID) and value.integrator is None)
                        or server not in ("interop", "interop.g.us")
                        or not 0 <= device < 65536 or not 0 <= integrator < 65536):
                    raise ProtocolError("JID no longer fits interop layout")
                self.emit(b"\xf4")
                self.preserved_token(user, layout.user, nesting+1)
                self.emit(device.to_bytes(2, "big") + integrator.to_bytes(2, "big"))
                self.emit(bytes([0 if server == "interop" else 2]))
            return
        raise ProtocolError("unsupported preserved token layout")

    def preserved_node(self, node, depth):
        if not isinstance(node, (Node, StreamEnd)) or not isinstance(node._wire_layout, NodeLayout):
            raise ProtocolError("preserve_wire requires a node read with preserve_wire=True")
        layout = node._wire_layout
        if isinstance(node, StreamEnd):
            if depth:
                raise ProtocolError("stream end is only valid at root")
            self.preserved_list(1, layout.list_marker)
            self.emit(b"\x02")
            return
        if len(node.attrs) > self.limits.max_attributes:
            raise ProtocolError("attribute count exceeds limit")
        if len(node.attrs) != len(layout.attrs):
            raise ProtocolError("attribute count changed from preserved layout")
        if layout.content_kind == "none":
            if node.data is not None or node.children is not None:
                raise ProtocolError("content kind changed from preserved layout")
        elif layout.content_kind == "data":
            if node.data is None or node.children is not None:
                raise ProtocolError("content kind changed from preserved layout")
        elif layout.content_kind == "children":
            if node.data is not None or node.children is None:
                raise ProtocolError("content kind changed from preserved layout")
        else:
            raise ProtocolError("invalid preserved content kind")
        self.preserved_list(1 + 2 * len(node.attrs) + (layout.content_kind != "none"), layout.list_marker)
        self.preserved_token(node.tag, layout.tag)
        for attr, (key_layout, value_layout) in zip(node.attrs, layout.attrs):
            self.preserved_token(attr.name, key_layout)
            self.preserved_token(attr.value, value_layout)
        if layout.content_kind == "data":
            self.preserved_token(node.data, layout.content)
        elif layout.content_kind == "children":
            self.preserved_list(len(node.children), layout.children_marker)
            for child in node.children:
                self.node(child, depth+1)

    def node(self, node: Node | StreamEnd, depth: int = 0) -> None:
        if depth >= self.limits.max_depth:
            raise ProtocolError("node depth exceeds limit")
        self.nodes += 1
        if self.nodes > self.limits.max_nodes:
            raise ProtocolError("node count exceeds limit")
        if self.preserve_wire:
            return self.preserved_node(node, depth)
        if isinstance(node, StreamEnd):
            if depth:
                raise ProtocolError("stream end is only valid at root")
            self.emit(b"\xf8\x01\x02")
            return
        if not isinstance(node, Node):
            raise ProtocolError("expected Node or STREAM_END")
        if len(node.attrs) > self.limits.max_attributes:
            raise ProtocolError("attribute count exceeds limit")
        has_content = node.data is not None or bool(node.children)
        self.list_size(1 + 2 * len(node.attrs) + int(has_content))
        self.text(node.tag, infer_jid=True)
        for attr in node.attrs:
            self.text(attr.name)
            self.text(attr.value, pack=True, infer_jid=True)
        if node.data is not None:
            self.raw(node.data)
        elif node.children:
            self.list_size(len(node.children))
            for child in node.children:
                self.node(child, depth+1)

    def write(self, node: Node | StreamEnd) -> bytes:
        self.node(node)
        return bytes(self.output)
