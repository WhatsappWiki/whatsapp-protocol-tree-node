"""Protocol parsing and encoding errors."""
from __future__ import annotations


__all__ = ['ProtocolError']


class ProtocolError(ValueError):
    """Invalid, truncated or resource-limit-exceeding binary node data."""
