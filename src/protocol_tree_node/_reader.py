"""Binary node decoding with bounded per-call state."""
from __future__ import annotations

from typing import NoReturn

from protocol_tree_node._jid_wire import format_address
from protocol_tree_node.dictionary import TokenDictionary
from protocol_tree_node.errors import ProtocolError
from protocol_tree_node.jid import InvalidJID, parse_jid
from protocol_tree_node.layout import NodeLayout, TokenLayout
from protocol_tree_node.limits import Limits
from protocol_tree_node.model import Attribute, JID, Node, STREAM_END, StreamEnd

__all__ = []


class _Reader:
    """One input cursor and node count per read operation."""

    def __init__(self, data: bytes, dictionary: TokenDictionary, limits: Limits,
                 preserve_wire: bool = False):
        self.data, self.dictionary, self.limits = data, dictionary, limits
        self.pos = 0
        self.nodes = 0
        self.preserve_wire = preserve_wire

    def fail(self, message: str) -> NoReturn:
        raise ProtocolError(f"{message} at byte {self.pos}")

    def take(self, count: int) -> bytes:
        if count < 0 or count > self.limits.max_bytes:
            self.fail("byte length exceeds limit")
        if count > len(self.data) - self.pos:
            self.fail("truncated data")
        start = self.pos
        self.pos += count
        return self.data[start:self.pos]

    def byte(self) -> int:
        return self.take(1)[0]

    def uint(self, count: int) -> int:
        return int.from_bytes(self.take(count), "big")

    def list_size(self, token: int) -> int:
        if token == 0:
            return 0
        if token == 248:
            return self.byte()
        if token == 249:
            return self.uint(2)
        self.fail("invalid list marker")

    def raw(self, token: int) -> tuple[bytes, TokenLayout]:
        prefix_bits = 0
        if token == 252:
            length = self.byte()
        elif token == 253:
            header = self.uint(3)
            length, prefix_bits = header & 0xfffff, header & 0xf00000
        elif token == 254:
            header = self.uint(4)
            length, prefix_bits = header & 0x7fffffff, header & 0x80000000
        else:
            self.fail("invalid binary marker")
        return self.take(length), TokenLayout(token, prefix_bits=prefix_bits)

    def packed(self, token: int) -> tuple[bytes, TokenLayout]:
        length = self.byte()
        count, odd = length & 127, length >> 7
        if count == 0 and odd:
            self.fail("negative packed character count")
        data = self.take(count)
        alphabet = b"0123456789ABCDEF" if token == 251 else b"0123456789-.:"
        result = bytearray()
        for i in range(count * 2 - odd):
            value = (data[i // 2] >> (4 if i % 2 == 0 else 0)) & 15
            if value >= len(alphabet):
                self.fail("invalid packed character")
            result.append(alphabet[value])
        # The original reader ignores the omitted padding nibble, even if not F.
        layout = TokenLayout(token, padding=(data[-1] & 15) if odd else 15)
        return bytes(result), layout

    def text(self, token=None, *, attribute=False, nesting=0) -> tuple[str | JID | None, TokenLayout]:
        """Return a value and its layout together, including nested JID tokens."""
        if nesting > self.limits.max_depth:
            self.fail("JID nesting exceeds depth limit")
        token = self.byte() if token is None else token
        if token == 0:
            return None, TokenLayout(0)
        if 3 <= token < 240:
            index = None
            try:
                if token < 236:
                    value = self.dictionary.single[token]
                else:
                    index = self.byte()
                    value = self.dictionary.dictionaries[token - 236][index]
            except IndexError:
                self.fail("unknown dictionary token")
            if not value:
                self.fail("empty dictionary token")
            return value, TokenLayout(token, index=index)
        if token in (251, 255, 252, 253, 254):
            value, layout = self.packed(token) if token in (251, 255) else self.raw(token)
            try:
                return value.decode("utf-8"), layout
            except UnicodeDecodeError as exc:
                raise ProtocolError(f"invalid UTF-8 at byte {self.pos}") from exc
        if token in (247, 250) or (token == 244 and attribute):
            return self.jid(token, attribute=attribute, nesting=nesting)
        self.fail(f"unsupported string token 0x{token:02x}")

    def jid(self, token: int, *, attribute: bool, nesting: int) -> tuple[str | JID, TokenLayout]:
        server_layout, flags, device, integrator = None, 0, 0, 0
        if token == 247:
            flags, device = self.byte(), self.byte()
            user, user_layout = self.text(nesting=nesting+1)
            server = {0: "s.whatsapp.net", 1: "lid", 128: "hosted", 129: "hosted.lid"}[flags & 129]
            address = format_address(user, server, device)
        elif token == 250:
            user, user_layout = self.text(nesting=nesting+1)
            server, server_layout = self.text(nesting=nesting+1)
            if server is None:
                self.fail("missing JID server")
            address = format_address(user, server)
        else:
            user, user_layout = self.text(nesting=nesting+1)
            device, integrator, domain = self.uint(2), self.uint(2), self.byte()
            if domain not in (0, 2):
                self.fail("invalid interop domain")
            if domain == 2 and (device or integrator):
                self.fail("invalid interop group tuple")
            if domain == 0 and not user:
                self.fail("missing interop user")
            server = "interop" if domain == 0 else "interop.g.us"
            address = (format_address(f"{integrator}-{user}", server, device)
                       if domain == 0 else format_address(user, server))
        value = address
        if attribute:
            try:
                value = parse_jid(address)
            except InvalidJID:
                # All three tuple branches share this factory fallback in
                # DEX. Tuple structure checks above are outside the catch.
                value = address
        layout = TokenLayout(token, user=user_layout, server=server_layout,
                             flags=flags, device_suffix=bool(device),
                             separator=(len(user) + (len(str(device)) + 1 if device else 0)
                                        if user else None),
                             jid_spelling=((user, server) if str(value) != address or
                                           (token == 247 and isinstance(value, JID) and
                                            (value.user != user or value.device != device))
                                           else None),
                             device=device, integrator=integrator)
        return value, layout

    def node(self, depth: int = 0) -> Node | StreamEnd:
        if depth >= self.limits.max_depth:
            self.fail("node depth exceeds limit")
        self.nodes += 1
        if self.nodes > self.limits.max_nodes:
            self.fail("node count exceeds limit")
        list_marker = self.byte()
        size = self.list_size(list_marker)
        if size == 0:
            self.fail("empty node list")
        token = self.byte()
        if token == 2:
            if depth or size != 1:
                self.fail("stream end must be a singleton root")
            return StreamEnd(NodeLayout(list_marker)) if self.preserve_wire else STREAM_END
        tag, tag_layout = self.text(token)
        if not tag:
            self.fail("missing node tag")
        count = (size - 1) // 2
        if count > self.limits.max_attributes:
            self.fail("attribute count exceeds limit")
        attrs, attr_layouts = [], []
        for _ in range(count):
            name, name_layout = self.text()
            if not name:
                self.fail("missing attribute name")
            value, value_layout = self.text(attribute=True)
            attrs.append(Attribute(name, value))
            attr_layouts.append((name_layout, value_layout))
        def layout(kind="none", content=None, children_marker=None):
            return (NodeLayout(list_marker, tag_layout, tuple(attr_layouts), kind,
                               content, children_marker) if self.preserve_wire else None)
        if size & 1:
            return Node(tag, tuple(attrs), _wire_layout=layout())
        token = self.byte()
        if token in (0, 248, 249):
            count = self.list_size(token)
            if count > self.limits.max_nodes - self.nodes:
                self.fail("child count exceeds node limit")
            # A generator adds a frame for every ancestor. Leave that stack
            # space available for JID tokens nested inside the deepest node.
            children = []
            for _ in range(count):
                children.append(self.node(depth+1))
            return Node(tag, tuple(attrs), children=children,
                        _wire_layout=layout("children", children_marker=token))
        if token in (252, 253, 254):
            data, content_layout = self.raw(token)
        elif token in (251, 255):
            data, content_layout = self.packed(token)
        else:
            text, content_layout = self.text(token)
            if text is None:
                self.fail("missing content")
            data = text.encode("utf-8")
        return Node(tag, tuple(attrs), data=data, _wire_layout=layout("data", content_layout))

    def read(self) -> Node | StreamEnd:
        try:
            node = self.node()
        except ProtocolError:
            raise
        except ValueError as exc:
            raise ProtocolError(f"invalid node at byte {self.pos}: {exc}") from exc
        if self.pos != len(self.data):
            raise ProtocolError(f"trailing bytes at byte {self.pos}")
        return node
