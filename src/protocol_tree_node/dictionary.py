"""Immutable, externally supplied string-token dictionaries."""
from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence


class TokenDictionary:
    """Token positions are wire IDs. None/empty entries are unavailable.

    Duplicate strings resolve to the last position, matching the writer's
    ordered map construction. Reserved single positions 0..2 are never emitted
    as ordinary strings. Inputs are copied; the dictionary is immutable.
    """

    __slots__ = ("_single", "_dictionaries", "_reverse")

    def __init__(self, single: Sequence[str | None],
                 dictionaries: Sequence[Sequence[str | None]] = ()):
        if isinstance(single, (str, bytes)) or isinstance(dictionaries, (str, bytes)):
            raise ValueError("dictionary tables must be sequences, not strings")
        first = tuple(single)
        pages = []
        for page in dictionaries:
            if isinstance(page, (str, bytes)):
                raise ValueError("dictionary page must be a sequence")
            pages.append(tuple(page))
        if len(first) > 236 or len(pages) > 4 or any(len(p) > 256 for p in pages):
            raise ValueError("dictionary exceeds single/page token ranges")
        if any(s is not None and not isinstance(s, str) for p in (first, *pages) for s in p):
            raise ValueError("dictionary entries must be strings or None")
        reverse = {}
        for i, text in enumerate(first):
            if i >= 3 and text:
                reverse[text] = bytes([i])
        for i, page in enumerate(pages):
            for j, text in enumerate(page):
                if text:
                    reverse[text] = bytes([236 + i, j])
        self._single = first
        self._dictionaries = tuple(pages)
        self._reverse = MappingProxyType(reverse)

    @property
    def single(self) -> tuple[str | None, ...]:
        return self._single

    @property
    def dictionaries(self) -> tuple[tuple[str | None, ...], ...]:
        return self._dictionaries

    def token(self, text: str) -> bytes | None:
        return self._reverse.get(text)

    @classmethod
    def from_mapping(cls, value: Mapping) -> TokenDictionary:
        return cls(value["single"], value.get("dictionaries", ()))

    @classmethod
    def from_json(cls, path: str | Path) -> TokenDictionary:
        with Path(path).open(encoding="utf-8") as stream:
            return cls.from_mapping(json.load(stream))

    @classmethod
    def bundled(cls) -> TokenDictionary:
        """Opt-in snapshot; callers can replace it without modifying the codec."""
        resource = files("protocol_tree_node").joinpath("data/tokens.json")
        return cls.from_mapping(json.loads(resource.read_text(encoding="utf-8")))
