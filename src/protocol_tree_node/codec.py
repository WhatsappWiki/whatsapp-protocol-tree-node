"""Pure binary node serialization. No sockets, Noise keys or HTTP framing."""
from __future__ import annotations

import zlib
from dataclasses import dataclass

from .dictionary import TokenDictionary
from .model import Attribute, JID, Node, STREAM_END, StreamEnd
from .layout import NodeLayout, TokenLayout
from .jid import InvalidJID, is_protocol_compliant, normalize_jid, parse_jid, try_parse_jid


def _address(user, server, device=0):
    if not user:
        return server
    return f"{user}{':' + str(device) if device else ''}@{server}"


class ProtocolError(ValueError):
    """Invalid, truncated or resource-limit-exceeding binary node data."""


@dataclass(frozen=True)
class Limits:
    max_bytes: int = 16 * 1024 * 1024
    max_depth: int = 128
    max_nodes: int = 100000
    max_attributes: int = 32767

    def __post_init__(self):
        for value in vars(self).values():
            if type(value) is not int or value < 1:
                raise ValueError("limits must be positive integers")
        if self.max_depth > 256:
            raise ValueError("max_depth must not exceed 256")


class _Reader:
    def __init__(self, data: bytes, dictionary: TokenDictionary, limits: Limits, preserve_wire=False):
        self.data, self.dictionary, self.limits = data, dictionary, limits
        self.pos = 0
        self.nodes = 0
        self.preserve_wire = preserve_wire
        self.last_layout = None

    def fail(self, message):
        raise ProtocolError(f"{message} at byte {self.pos}")

    def take(self, count):
        if count < 0 or count > self.limits.max_bytes:
            self.fail("byte length exceeds limit")
        if count > len(self.data) - self.pos:
            self.fail("truncated data")
        start = self.pos
        self.pos += count
        return self.data[start:self.pos]

    def byte(self):
        return self.take(1)[0]

    def uint(self, count):
        return int.from_bytes(self.take(count), "big")

    def list_size(self, token):
        if token == 0:
            return 0
        if token == 248:
            return self.byte()
        if token == 249:
            return self.uint(2)
        self.fail("invalid list marker")

    def raw(self, token):
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
        self.last_layout = TokenLayout(token, prefix_bits=prefix_bits)
        return self.take(length)

    def packed(self, token):
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
        self.last_layout = TokenLayout(token, padding=(data[-1] & 15) if odd else 15)
        return bytes(result)

    def text(self, token=None, *, attribute=False, nesting=0):
        if nesting > self.limits.max_depth:
            self.fail("JID nesting exceeds depth limit")
        token = self.byte() if token is None else token
        if token == 0:
            self.last_layout = TokenLayout(0)
            return None
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
            self.last_layout = TokenLayout(token, index=index)
            return value
        if token in (251, 255, 252, 253, 254):
            value = self.packed(token) if token in (251, 255) else self.raw(token)
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ProtocolError(f"invalid UTF-8 at byte {self.pos}") from exc
        if token in (247, 250) or (token == 244 and attribute):
            server_layout, flags, device, integrator = None, 0, 0, 0
            if token == 247:
                flags, device = self.byte(), self.byte()
                user = self.text(nesting=nesting+1)
                user_layout = self.last_layout
                server = {0: "s.whatsapp.net", 1: "lid", 128: "hosted", 129: "hosted.lid"}[flags & 129]
                address = _address(user, server, device)
            elif token == 250:
                user = self.text(nesting=nesting+1)
                user_layout = self.last_layout
                server = self.text(nesting=nesting+1)
                server_layout = self.last_layout
                if server is None:
                    self.fail("missing JID server")
                address = _address(user, server)
            else:
                user = self.text(nesting=nesting+1)
                user_layout = self.last_layout
                device, integrator, domain = self.uint(2), self.uint(2), self.byte()
                if domain not in (0, 2):
                    self.fail("invalid interop domain")
                if domain == 2 and (device or integrator):
                    self.fail("invalid interop group tuple")
                if domain == 0 and not user:
                    self.fail("missing interop user")
                server = "interop" if domain == 0 else "interop.g.us"
                address = (_address(f"{integrator}-{user}", server, device)
                           if domain == 0 else _address(user, server))
            value = address
            if attribute:
                try:
                    value = parse_jid(address)
                except InvalidJID:
                    # All three tuple branches share this factory fallback in
                    # DEX. Tuple structure checks above are outside the catch.
                    value = address
            self.last_layout = TokenLayout(token, user=user_layout, server=server_layout,
                                           flags=flags, device_suffix=bool(device),
                                           separator=(len(user) + (len(str(device)) + 1 if device else 0)
                                                      if user else None),
                                           jid_spelling=((user, server) if str(value) != address or
                                                         (token == 247 and isinstance(value, JID) and
                                                          (value.user != user or value.device != device))
                                                         else None),
                                           device=device, integrator=integrator)
            return value
        self.fail(f"unsupported string token 0x{token:02x}")

    def node(self, depth=0):
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
        tag = self.text(token)
        tag_layout = self.last_layout
        if not tag:
            self.fail("missing node tag")
        count = (size - 1) // 2
        if count > self.limits.max_attributes:
            self.fail("attribute count exceeds limit")
        attrs, attr_layouts = [], []
        for _ in range(count):
            name = self.text()
            name_layout = self.last_layout
            if not name:
                self.fail("missing attribute name")
            attrs.append(Attribute(name, self.text(attribute=True)))
            attr_layouts.append((name_layout, self.last_layout))
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
            children = tuple(self.node(depth+1) for _ in range(count))
            return Node(tag, tuple(attrs), children=children,
                        _wire_layout=layout("children", children_marker=token))
        if token in (252, 253, 254):
            data = self.raw(token)
        elif token in (251, 255):
            data = self.packed(token)
        else:
            text = self.text(token)
            if text is None:
                self.fail("missing content")
            data = text.encode("utf-8")
        return Node(tag, tuple(attrs), data=data, _wire_layout=layout("data", self.last_layout))


class _Writer:
    def __init__(self, dictionary, limits, preserve_wire=False):
        self.dictionary, self.limits = dictionary, limits
        self.output = bytearray()
        self.nodes = 0
        self.preserve_wire = preserve_wire

    def emit(self, data):
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

    def preserved_jid_text(self, value, layout):
        """Invert a JID rendered in a string position (tag/key/leaf).

        The saved separator and device disambiguate components omitted by the
        text renderer. Attribute factory failures can also use this path.
        """
        if layout.separator is not None:
            if value[layout.separator:layout.separator+1] != "@":
                raise ProtocolError("JID string separator changed from preserved layout")
            user, server = value[:layout.separator], value[layout.separator+1:]
        else:
            user = None if layout.user.marker == 0 else ""
            server = value
        if layout.marker == 250:
            return JID(user, server)
        device = layout.device if not user else 0
        if layout.device_suffix and user and ":" in user:
            user, number = user.rsplit(":", 1)
            try:
                device = int(number)
            except ValueError as exc:
                raise ProtocolError("invalid preserved JID device") from exc
        domains = {"s.whatsapp.net": 0, "lid": 1, "hosted": 128, "hosted.lid": 129}
        if server not in domains:
            raise ProtocolError("JID domain no longer fits compact layout")
        jid = JID(user, server, device=device, flags=(layout.flags & ~129) | domains[server])
        if str(jid) != value:
            raise ProtocolError("JID text no longer matches its rendered layout")
        return jid

    @staticmethod
    def spelled_user(original, current, spelling, *, pair):
        """Apply field edits to the lexical parts discarded by the factory."""
        if current == original:
            return spelling
        if original.integrator is not None:
            account = spelling
            prefix = str(current.integrator)
            if pair and original.server == "interop":
                old_prefix, separator, account = spelling.rpartition("-")
                if not separator:
                    return f"{current.integrator}-{current.user}"
                if current.integrator == original.integrator:
                    prefix = old_prefix
            suffix = (account[len(original.user):]
                      if account and original.user and account.startswith(original.user) else "")
            account = (current.user or "") + suffix
            return f"{prefix}-{account}" if pair and current.server == "interop" else account
        if not spelling or not original.user or not spelling.startswith(original.user):
            return current.user
        suffix = spelling[len(original.user):]
        if pair and current.device != original.device:
            if ":" in suffix:
                before, old_number = suffix.rsplit(":", 1)
                sign = "+" if old_number.startswith("+") and current.device >= 0 else ""
                digits = old_number.lstrip("+-")
                number = str(abs(current.device)).rjust(len(digits), "0")
                suffix = before + ":" + ("-" if current.device < 0 else sign) + number
            elif current.device or current.flags is not None:
                suffix += f":{current.device}"
        return (current.user or "") + suffix

    def preserved_jid(self, value, layout):
        """Recover tuple components while re-encoding the current fields."""
        marker = layout.marker
        if isinstance(value, str):
            # String positions and failed FA factories retain their address
            # text. The recorded separator disambiguates embedded '@' chars.
            if marker == 250 and layout.separator is None:
                return None if layout.user.marker == 0 else "", value, 0, 0
            if marker == 250:
                separator = layout.separator
                if value[separator:separator+1] == "@":
                    return value[:separator], value[separator+1:], 0, 0
                if value.count("@") == 1:
                    user, server = value.split("@")
                    return user, server, 0, 0
                raise ProtocolError("JID string separator changed from preserved layout")
            if marker == 244:
                if value == "interop.g.us":
                    return None if layout.user.marker == 0 else "", value, 0, 0
                local, separator, server = value.rpartition("@")
                if not separator or server not in ("interop", "interop.g.us"):
                    raise ProtocolError("interop text no longer fits tuple layout")
                if server == "interop.g.us":
                    return local, server, 0, 0
                number, separator, user = local.partition("-")
                if not separator:
                    raise ProtocolError("missing interop text integrator")
                try:
                    integrator = int(number)
                    device = 0
                    if layout.device_suffix:
                        user, separator, suffix = user.rpartition(":")
                        if not separator:
                            raise ValueError("missing device")
                        device = int(suffix)
                except ValueError as exc:
                    raise ProtocolError("invalid interop tuple text") from exc
                if not user or _address(f"{integrator}-{user}", server, device) != value:
                    raise ProtocolError("interop text no longer fits tuple semantics")
                return user, server, device, integrator
            jid = self.preserved_jid_text(value, layout)
            return jid.user, jid.server, jid.device, jid.integrator or 0
        if not isinstance(value, JID):
            raise ProtocolError("value no longer fits JID layout")
        try:
            expected = normalize_jid(value)
        except InvalidJID as exc:
            raise ProtocolError("invalid current JID") from exc
        user, server, device = value.user, value.server, value.device
        if marker == 250:
            address = str(value)
            if "@" in address:
                user, server = address.rsplit("@", 1)
            else:
                user, server = None, address
        if layout.jid_spelling is not None:
            old_user, old_server = layout.jid_spelling
            old_address = (_address(old_user, old_server, layout.device) if marker == 247 else
                           _address(f"{layout.integrator}-{old_user}", old_server, layout.device)
                           if marker == 244 and old_server == "interop" else
                           _address(old_user, old_server))
            try:
                original = parse_jid(old_address)
            except InvalidJID as exc:
                raise ProtocolError("invalid saved JID spelling") from exc
            # With an outer F7 device of zero, a colon inside the user token
            # supplies the factory's device. Keep that placement, rather than
            # appending the semantic device a second time to the tuple.
            user_device = marker == 247 and layout.device == 0 and old_user and ":" in old_user
            user = self.spelled_user(original, value, old_user,
                                     pair=marker == 250 or bool(user_device))
            if user_device:
                device = 0
            if value.server == original.server:
                server = old_server
        if not user:
            user = None if layout.user.marker == 0 else ""
            if marker == 247:
                device = layout.device
        address = (_address(f"{value.integrator}-{user}", server, device)
                   if marker == 244 and server == "interop" else
                   _address(user, server, device if marker == 247 else 0))
        try:
            if parse_jid(address) != expected:
                raise ProtocolError("JID edit no longer fits preserved tuple semantics")
        except InvalidJID as exc:
            raise ProtocolError("JID edit no longer fits preserved tuple semantics") from exc
        return user, server, device, value.integrator or 0

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
        if marker in (244, 247, 250):
            user, server, device, integrator = self.preserved_jid(value, layout)
            if marker == 250:
                self.emit(b"\xfa")
                self.preserved_token(user, layout.user, nesting+1)
                self.preserved_token(server, layout.server, nesting+1)
            elif marker == 247:
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
            if node.data is not None or node.children:
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

    def node(self, node, depth=0):
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


class Codec:
    """Reusable codec with immutable configuration and per-call state.

    framed=True means the decrypted flags+node envelope, NOT a transport frame.
    Default JID handling follows the client's address factories. Wire layout
    preservation is explicit and does not change the decoded field semantics.
    """

    def __init__(self, dictionary: TokenDictionary, *, limits: Limits = Limits()):
        if not isinstance(dictionary, TokenDictionary) or not isinstance(limits, Limits):
            raise TypeError("expected TokenDictionary and Limits")
        self.dictionary, self.limits = dictionary, limits

    def read(self, data: bytes, *, framed: bool = True, preserve_wire: bool = False) -> Node | StreamEnd:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > self.limits.max_bytes:
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
                    data = inflater.decompress(data, self.limits.max_bytes + 1)
                except zlib.error as exc:
                    raise ProtocolError("invalid zlib packet") from exc
                if len(data) > self.limits.max_bytes:
                    raise ProtocolError("decompressed packet exceeds byte limit")
                if not inflater.eof or inflater.unconsumed_tail or inflater.unused_data:
                    raise ProtocolError("incomplete or trailing zlib packet")
        reader = _Reader(data, self.dictionary, self.limits, preserve_wire)
        try:
            node = reader.node()
        except ProtocolError:
            raise
        except ValueError as exc:
            raise ProtocolError(f"invalid node at byte {reader.pos}: {exc}") from exc
        if reader.pos != len(data):
            raise ProtocolError(f"trailing bytes at byte {reader.pos}")
        return node

    def write(self, node: Node | StreamEnd, *, framed: bool = True,
              compress: bool = False, preserve_wire: bool = False) -> bytes:
        if compress and not framed:
            raise ValueError("compression requires framed=True")
        writer = _Writer(self.dictionary, self.limits, preserve_wire)
        writer.node(node)
        data = bytes(writer.output)
        if framed:
            data = b"\x02" + zlib.compress(data) if compress else b"\0" + data
        if len(data) > self.limits.max_bytes:
            raise ProtocolError("packet exceeds byte limit")
        return data
