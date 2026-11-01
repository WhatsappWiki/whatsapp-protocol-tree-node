"""Reconstruct JID wire tuples from current values and retained spelling."""
from __future__ import annotations

from protocol_tree_node.errors import ProtocolError
from protocol_tree_node.jid import InvalidJID, normalize_jid, parse_jid
from protocol_tree_node.layout import TokenLayout
from protocol_tree_node.model import JID

__all__ = []


def format_address(user: str | None, server: str, device: int = 0) -> str:
    if not user:
        return server
    return f"{user}{':' + str(device) if device else ''}@{server}"


def preserved_jid_text(value: str, layout: TokenLayout) -> JID:
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
    # Check wire width before the model's int32 guard to keep protocol errors uniform.
    if not 0 <= device < 256:
        raise ProtocolError("JID no longer fits device layout")
    jid = JID(user, server, device=device, flags=(layout.flags & ~129) | domains[server])
    if str(jid) != value:
        raise ProtocolError("JID text no longer matches its rendered layout")
    return jid


def spelled_user(original: JID, current: JID, spelling: str | None, *, pair: bool) -> str | None:
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


def pair_components(value: str, layout: TokenLayout) -> tuple[str | None, str]:
    """Split at the wire boundary, which may precede the address factory's @."""
    if layout.separator is None:
        return None if layout.user.marker == 0 else "", value
    separator = layout.separator
    if value[separator:separator+1] == "@":
        return value[:separator], value[separator+1:]
    if value.count("@") == 1 and not value.startswith("@"):
        user, server = value.split("@")
        return user, server
    raise ProtocolError("JID string separator changed from preserved layout")


def preserved_jid_parts(value: str | JID, layout: TokenLayout) -> tuple[str | None, str, int, int]:
    """Recover tuple components while re-encoding the current fields."""
    marker = layout.marker
    if isinstance(value, str):
        # String positions and failed FA factories retain their address
        # text. The recorded separator disambiguates embedded '@' chars.
        if marker == 250:
            user, server = pair_components(value, layout)
            return user, server, 0, 0
        if marker == 244:
            if value == "interop.g.us":
                return None if layout.user.marker == 0 else "", value, 0, 0
            local, separator, server = value.rpartition("@")
            if not separator or server not in ("interop", "interop.g.us"):
                raise ProtocolError("interop text no longer fits tuple layout")
            if server == "interop.g.us":
                if not local:
                    raise ProtocolError("interop text no longer fits tuple semantics")
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
            if not user or format_address(f"{integrator}-{user}", server, device) != value:
                raise ProtocolError("interop text no longer fits tuple semantics")
            return user, server, device, integrator
        jid = preserved_jid_text(value, layout)
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
        if layout.jid_spelling is None and layout.server_has_at is not False:
            # A nested or raw server can itself contain an address. The
            # factory may then move part of that server into JID.user while
            # leaving str(JID) unchanged; retain the original tuple boundary.
            user, server = pair_components(address, layout)
        elif "@" in address:
            # With a known plain server, the final separator remains the
            # tuple boundary even when the edited user gains extra '@' chars.
            user, server = address.rsplit("@", 1)
        else:
            user, server = None, address
    if layout.jid_spelling is not None:
        old_user, old_server = layout.jid_spelling
        old_address = (format_address(old_user, old_server, layout.device) if marker == 247 else
                       format_address(f"{layout.integrator}-{old_user}", old_server, layout.device)
                       if marker == 244 and old_server == "interop" else
                       format_address(old_user, old_server))
        try:
            original = parse_jid(old_address)
        except InvalidJID as exc:
            raise ProtocolError("invalid saved JID spelling") from exc
        # With an outer F7 device of zero, a colon inside the user token
        # supplies the factory's device. Keep that placement, rather than
        # appending the semantic device a second time to the tuple.
        user_device = marker == 247 and layout.device == 0 and old_user and ":" in old_user
        user = spelled_user(original, value, old_user,
                                 pair=marker == 250 or bool(user_device))
        if user_device:
            device = 0
        if value.server == original.server:
            server = old_server
    if not user:
        user = None if layout.user.marker == 0 else ""
        if marker == 247:
            device = layout.device
    address = (format_address(f"{value.integrator}-{user}", server, device)
               if marker == 244 and server == "interop" else
               format_address(user, server, device if marker == 247 else 0))
    try:
        if parse_jid(address) != expected:
            raise ProtocolError("JID edit no longer fits preserved tuple semantics")
    except InvalidJID as exc:
        raise ProtocolError("JID edit no longer fits preserved tuple semantics") from exc
    return user, server, device, value.integrator or 0
