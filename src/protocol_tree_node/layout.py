"""Encoding choices only; no original packet or payload bytes are retained."""
from __future__ import annotations

from dataclasses import dataclass


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


@dataclass(frozen=True)
class NodeLayout:
    list_marker: int
    tag: TokenLayout | None = None
    attrs: tuple[tuple[TokenLayout, TokenLayout], ...] = ()
    content_kind: str = "none"
    content: TokenLayout | None = None
    children_marker: int | None = None
