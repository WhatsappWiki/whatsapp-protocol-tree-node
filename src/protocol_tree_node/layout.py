"""Encoding choices and lossy JID spelling; never a cached packet or payload."""
from __future__ import annotations

from dataclasses import dataclass

__all__ = []


@dataclass(frozen=True)
class TokenLayout:
    marker: int
    index: int | None = None
    prefix_bits: int = 0
    padding: int = 15
    user: TokenLayout | None = None
    server: TokenLayout | None = None
    flags: int = 0
    device_suffix: bool = False
    separator: int | None = None
    # The address factory can discard arbitrary agent spelling or normalize
    # numeric suffixes. Keep only those otherwise-lost tuple strings, not a
    # packet copy. The writer checks their semantics against the current JID.
    jid_spelling: tuple[str | None, str] | None = None
    device: int = 0
    integrator: int = 0
    # FA servers containing '@' have a different boundary from the address
    # factory. None keeps older layouts conservative when this fact is unknown.
    server_has_at: bool | None = None


@dataclass(frozen=True)
class NodeLayout:
    list_marker: int
    tag: TokenLayout | None = None
    attrs: tuple[tuple[TokenLayout, TokenLayout], ...] = ()
    content_kind: str = "none"
    content: TokenLayout | None = None
    children_marker: int | None = None
