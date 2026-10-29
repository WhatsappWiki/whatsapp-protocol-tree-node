"""Lossless byte content, ordered attributes and explicit JID tuples."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Mapping

from .layout import NodeLayout


def _uint(value: int, bits: int, name: str) -> None:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError(f"{name} must be uint{bits}")


@dataclass(frozen=True)
class JID:
    user: str | None
    server: str
    device: int = 0
    integrator: int | None = None
    flags: int | None = None

    def __post_init__(self):
        if self.user is not None and not isinstance(self.user, str):
            raise ValueError("JID user must be str or None")
        if not isinstance(self.server, str) or not self.server:
            raise ValueError("JID server must be nonempty str")
        _uint(self.device, 16, "device")
        if self.integrator is not None:
            if self.server not in ("interop", "interop.g.us"):
                raise ValueError("integrator is only valid for interop JIDs")
            if self.flags is not None:
                raise ValueError("interop JID cannot have device flags")
            _uint(self.integrator, 16, "integrator")
            if self.server == "interop" and not self.user:
                raise ValueError("interop user must be nonempty")
            if self.server == "interop.g.us" and (self.device or self.integrator):
                raise ValueError("interop group device/integrator must be zero")
        elif self.device or self.flags is not None:
            _uint(self.device, 8, "device")
            domains = {"s.whatsapp.net": 0, "lid": 1, "hosted": 128, "hosted.lid": 129}
            if self.server not in domains:
                raise ValueError("unsupported compact device JID server")
            if self.flags is not None:
                _uint(self.flags, 8, "flags")
                if self.flags & 129 != domains[self.server]:
                    raise ValueError("JID flags do not match server")

    def __str__(self):
        if not self.user:
            return self.server
        user = self.user
        if self.server == "interop" and self.integrator is not None:
            user = f"{self.integrator}-{user}"
        return f"{user}{':' + str(self.device) if self.device else ''}@{self.server}"


@dataclass(frozen=True)
class Attribute:
    name: str
    value: str | JID | None

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("attribute name must be nonempty str")
        if self.value is not None and not isinstance(self.value, (str, JID)):
            raise ValueError("attribute value must be str, JID or None")


@dataclass(frozen=True)
class Node:
    tag: str
    attrs: tuple[Attribute, ...] = ()
    data: bytes | None = None
    children: tuple[Node, ...] | None = None
    _wire_layout: NodeLayout | None = field(default=None, compare=False, repr=False)

    def __post_init__(self):
        if not isinstance(self.tag, str) or not self.tag:
            raise ValueError("tag must be nonempty str")
        attrs = (tuple(Attribute(k, v) for k, v in self.attrs.items())
                 if isinstance(self.attrs, Mapping) else tuple(self.attrs))
        if not all(isinstance(a, Attribute) for a in attrs):
            raise ValueError("attrs must contain Attribute objects")
        object.__setattr__(self, "attrs", attrs)
        if self.data is not None:
            if not isinstance(self.data, bytes):
                raise ValueError("data must be bytes")
            if self.children is not None:
                raise ValueError("node cannot have both data and children")
        if self.children is not None:
            children = tuple(self.children)
            if not all(isinstance(c, Node) for c in children):
                raise ValueError("children must contain Node objects")
            object.__setattr__(self, "children", children)

    def to_dict(self) -> dict:
        def value(v):
            if isinstance(v, JID):
                return {"jid": {"user": v.user, "server": v.server, "device": v.device,
                                "integrator": v.integrator, "flags": v.flags}}
            return v
        return {"tag": self.tag, "attrs": [[a.name, value(a.value)] for a in self.attrs],
                "data": None if self.data is None else base64.b64encode(self.data).decode("ascii"),
                "children": None if self.children is None else [c.to_dict() for c in self.children]}

    @classmethod
    def from_dict(cls, obj: Mapping) -> Node:
        attrs = []
        for k, v in obj.get("attrs", []):
            attrs.append(Attribute(k, JID(**v["jid"]) if isinstance(v, dict) else v))
        data = obj.get("data")
        children = obj.get("children")
        return cls(obj["tag"], tuple(attrs),
                   None if data is None else base64.b64decode(data, validate=True),
                   None if children is None else tuple(cls.from_dict(c) for c in children))


@dataclass(frozen=True)
class StreamEnd:
    """Root stream-close marker, distinct from a node with empty content."""
    _wire_layout: NodeLayout | None = field(default=None, compare=False, repr=False)


STREAM_END = StreamEnd()
