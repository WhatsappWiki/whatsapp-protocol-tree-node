"""Shared resource limits for reading, writing and framing."""
from __future__ import annotations

from dataclasses import dataclass

__all__ = ['Limits']


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
