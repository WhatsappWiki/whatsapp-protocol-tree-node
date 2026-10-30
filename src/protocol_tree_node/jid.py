"""Client address factories used by the node reader and writer.

This models the address/type decisions, not Android identity caches or logging.
Device ``flags`` identify a device wrapper here; only its interpreted domain
bits are canonical. Packet encoding choices belong to the wire layout.
"""
from __future__ import annotations

import unicodedata

from .model import JID


class InvalidJID(ValueError):
    """The client's strict address factory cannot construct this address."""


_BARE = frozenset(("s.whatsapp.net", "g.us", "call"))
_USER_DOMAINS = frozenset(("s.whatsapp.net", "lid", "hosted", "hosted.lid", "bot", "interop"))
_FLAGS = {"s.whatsapp.net": 0, "lid": 1, "hosted": 128, "hosted.lid": 129, "bot": 0}


def _length(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _digits(value: str, minimum: int, maximum: int) -> bool:
    return minimum <= len(value) <= maximum and "1" <= value[0] <= "9" and all("0" <= c <= "9" for c in value)


def _phone(value: str) -> bool:
    return _digits(value, 5, 20) and (not value.startswith("10") or value.startswith("1008"))


def _java_int(value: str) -> int:
    """Integer.parseInt radix 10, including signs and BMP decimal digits."""
    original = value
    negative = value.startswith("-")
    if value.startswith(("+", "-")):
        value = value[1:]
    if not value:
        raise InvalidJID(f"invalid integer: {original!r}")
    result = 0
    for char in value:
        if ord(char) > 0xffff:
            raise InvalidJID(f"invalid integer: {original!r}")
        try:
            digit = unicodedata.decimal(char)
        except ValueError as exc:
            raise InvalidJID(f"invalid integer: {original!r}") from exc
        result = result * 10 + digit
        if result > (1 << 31) - (not negative):
            raise InvalidJID(f"integer outside int32: {original!r}")
    return -result if negative else result


def _group(value: str, *, interop: bool = False) -> bool:
    if _digits(value, 1, 20):
        return True
    if interop:
        return False
    phone, separator, suffix = value.partition("-")
    return bool(separator) and _phone(phone) and _digits(suffix, 10, 10)


def _interop(value: str) -> JID:
    integrator, separator, account = value.rpartition("-")
    if not separator or not 1 <= _length(integrator) <= 3 or integrator.startswith("0"):
        raise InvalidJID(f"invalid interop integrator: {value!r}")
    number = _java_int(integrator)
    if not _digits(account, 1, 15):
        raise InvalidJID(f"invalid interop account: {value!r}")
    return JID(account, "interop", integrator=number)


def _user(value: str, server: str) -> JID:
    if server in ("s.whatsapp.net", "hosted"):
        if value not in ("0", "Server") and not _phone(value):
            raise InvalidJID(f"invalid phone user: {value!r}")
        return JID(value, "s.whatsapp.net")
    if server in ("lid", "hosted.lid"):
        if not _digits(value, 1, 15):
            raise InvalidJID(f"invalid LID: {value!r}")
        return JID(value, "lid")
    if server == "bot":
        if not _digits(value, 1, 20):
            raise InvalidJID(f"invalid bot user: {value!r}")
        return JID(value, "bot")
    if server == "interop":
        return _interop(value)
    raise InvalidJID(f"invalid user domain: {server!r}")


def _device(user: JID, server: str, device: int) -> JID:
    # The base constructor validates the *signed byte cast*, while subclasses
    # keep the original int for getDevice(). Wire widths are checked later.
    signed_byte = (device + 128) % 256 - 128
    if not 0 <= signed_byte <= 99:
        raise InvalidJID(f"invalid device: {device}")
    if server in ("hosted", "hosted.lid") and device != 99:
        raise InvalidJID("hosted device must be 99")
    if server == "interop":
        if device != 0:
            raise InvalidJID("interop device must be 0")
        return user
    # Bot device != 0 is logged by the client, but does not throw.
    return JID(user.user, server, device=device, flags=_FLAGS[server])


def parse_jid(value: str) -> JID:
    """Construct an address like the client's strict Jid.Companion factory.

    Success does not imply is_protocol_compliant(): several internal address
    types are valid objects but are written as ordinary strings by the writer.
    """
    if not isinstance(value, str) or not value:
        raise InvalidJID("empty or non-string address")
    local, separator, server = value.rpartition("@")
    if not separator:
        if value in _BARE or value in ("status_me", "lid_me"):
            return JID(None, value)
        raise InvalidJID(f"unknown bare address: {value!r}")
    if not local:
        raise InvalidJID("missing address user")
    if server == "s.whatsapp.net" and local == "gdpr":
        return JID("gdpr", server)
    if server in _USER_DOMAINS:
        dot, colon = local.rfind("."), local.rfind(":")
        if dot < 0 and colon < 0:
            return _user(local, server)
        if dot == len(local) - 1 or colon == len(local) - 1:
            raise InvalidJID(f"incomplete device address: {value!r}")
        end = colon if colon >= 0 else len(local)
        if dot >= 0 and (colon < 0 or dot < colon):
            end = dot
        user = _user(local[:end], server)
        device = _java_int(local[colon + 1:]) if colon >= 0 else 0
        return _device(user, server, device)
    if server in ("g.us", "interop.g.us"):
        if not _group(local, interop=server == "interop.g.us"):
            raise InvalidJID(f"invalid group: {local!r}")
        return JID(local, server, integrator=0 if server == "interop.g.us" else None)
    if server == "broadcast":
        if local not in ("status", "location") and not _digits(local, 1, 20):
            raise InvalidJID(f"invalid broadcast: {local!r}")
        return JID(local, server)
    if server == "call":
        if not 18 <= len(local) <= 32 or any(c not in "0123456789abcdefABCDEF" for c in local):
            raise InvalidJID(f"invalid call: {local!r}")
        return JID(local, server)
    if server == "temp":
        if "-" not in local:
            raise InvalidJID(f"invalid temporary group: {local!r}")
        return JID(local, server)
    if server == "newsletter":
        # Java trim removes code units <= U+0020. The constructor performs no
        # numeric-only validation and retains the original untrimmed user.
        trimmed = local.strip("".join(chr(i) for i in range(33)))
        if not trimmed or trimmed.startswith("0"):
            raise InvalidJID(f"invalid newsletter: {local!r}")
        return JID(local, server)
    raise InvalidJID(f"unknown address domain: {server!r}")


def try_parse_jid(value: str, *, bare: bool = False) -> JID | None:
    """Soft writer factory; bare=True selects its three domain singletons."""
    if not isinstance(value, str):
        return None
    if bare:
        return JID(None, value) if value in _BARE else None
    try:
        return parse_jid(value)
    except ValueError:
        return None


def normalize_jid(jid: JID) -> JID:
    """Resolve explicit tuple fields using the corresponding client types."""
    if not isinstance(jid, JID):
        raise InvalidJID("expected JID")
    user = jid.user
    if jid.integrator is not None:
        if jid.server == "interop":
            # The source factory rejects an ASCII leading zero but accepts
            # Integer.parseInt("+0"). Thus zero is a possible object value,
            # although a freshly received F4 zero is rendered as "0-user",
            # rejected by the strict factory, and kept as plain text by the
            # node reader's InvalidJid fallback.
            number = "+0" if jid.integrator == 0 else str(jid.integrator)
            user = f"{number}-{user}"
        elif jid.server != "interop.g.us" or jid.integrator or jid.device:
            raise InvalidJID("invalid interop tuple")
    if jid.device or jid.flags is not None:
        if not user:
            raise InvalidJID("device wrapper requires a user")
        user = f"{user}:{jid.device}"
    return parse_jid(f"{user}@{jid.server}" if user else jid.server)


def is_protocol_compliant(jid: JID) -> bool:
    """Exclude the client's internal types 2, 8, 9 and 11."""
    if jid.server in ("temp", "status_me", "lid_me"):
        return False
    if jid.server == "s.whatsapp.net" and jid.user in ("Server", "gdpr"):
        return jid.flags is not None
    return True
