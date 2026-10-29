import pytest

from protocol_tree_node import Attribute, JID, Node, ProtocolError


def wrap(jid):
    return Node("node", attrs=(Attribute("key", jid),))


@pytest.mark.parametrize(
    "jid, payload",
    [
        (JID("12345", "example.test"), "faff8312345f06"),
        (JID(None, "example.test"), "fa0006"),
        (JID("123", "s.whatsapp.net", device=2, flags=0), "f70002ff82123f"),
        (JID("123", "lid", device=2, flags=1), "f70102ff82123f"),
        (JID("123", "hosted", device=99, flags=128), "f78063ff82123f"),
        (JID("123", "hosted.lid", device=99, flags=129), "f78163ff82123f"),
        (JID("123", "s.whatsapp.net", device=0, flags=0), "f70000ff82123f"),
        (JID("123", "interop", device=258, integrator=513), "f4ff82123f0102020100"),
        (JID("group", "interop.g.us", integrator=0), "f4fc0567726f75700000000002"),
    ],
)
def test_jid_golden(codec, jid, payload):
    wire = bytes.fromhex("f8030304" + payload)
    assert codec.write(wrap(jid), framed=False) == wire
    assert codec.read(wire, framed=False) == wrap(jid)


@pytest.mark.parametrize("server, flags", [("s.whatsapp.net", 0), ("lid", 1), ("hosted", 128), ("hosted.lid", 129)])
def test_device_domain_selection(codec, server, flags):
    node = wrap(JID("123", server, device=7))
    wire = codec.write(node, framed=False)
    assert wire[4:7] == bytes([247, flags, 7])
    assert codec.write(codec.read(wire, framed=False), framed=False) == wire


def test_string_jid_is_not_silently_coerced(codec):
    node = wrap("123@example.test")
    wire = codec.write(node, framed=False)
    assert wire[4] == 252
    assert codec.read(wire, framed=False) == node


@pytest.mark.parametrize("device", [0, 255])
def test_device_byte_extremes(codec, device):
    node = wrap(JID("x", "lid", device=device, flags=1))
    assert codec.read(codec.write(node)) == node


@pytest.mark.parametrize("device, integrator", [(0, 0), (65535, 65535)])
def test_interop_uint16_extremes(codec, device, integrator):
    node = wrap(JID("x", "interop", device=device, integrator=integrator))
    assert codec.read(codec.write(node)) == node


@pytest.mark.parametrize("suffix", [
    "fa0000",  # absent server
    "f4ff811f0000000001",  # unknown domain
    "f4ff811f0001000002",  # group device nonzero
    "f4ff811f0000000102",  # group integrator nonzero
])
def test_invalid_jid_wire(codec, suffix):
    with pytest.raises(ProtocolError):
        codec.read(bytes.fromhex("f8030304" + suffix), framed=False)


@pytest.mark.parametrize("jid", [
    {"user": "x", "server": "lid", "device": 256},
    {"user": "x", "server": "lid", "device": -1},
    {"user": "x", "server": "interop", "integrator": 65536},
    {"user": "x", "server": "interop", "integrator": -1},
    {"user": "x", "server": "interop.g.us", "device": 1, "integrator": 0},
    {"user": "x", "server": "interop.g.us", "device": 0, "integrator": 1},
])
def test_jid_input_bounds(codec, jid):
    with pytest.raises(ValueError):
        codec.write(wrap(JID(**jid)))


@pytest.mark.parametrize("kwargs", [
    {"user": 3, "server": "lid"},
    {"user": "x", "server": ""},
    {"user": "x", "server": "interop", "integrator": 0, "flags": 0},
    {"user": "x", "server": "lid", "integrator": 0},
    {"user": "x", "server": "unknown", "device": 1},
    {"user": "x", "server": "lid", "flags": 0},
    {"user": "x", "server": "lid", "flags": 256},
])
def test_invalid_jid_model(kwargs):
    with pytest.raises(ValueError):
        JID(**kwargs)


def test_device_flags_preserve_uninterpreted_bits(codec):
    jid = JID("123", "lid", device=7, flags=65)
    assert codec.read(codec.write(wrap(jid))) == wrap(jid)


def test_hosted_flag_device_mismatch_is_not_rejected(codec):
    jid = JID("123", "hosted", device=7, flags=128)
    assert codec.read(codec.write(wrap(jid))) == wrap(jid)


@pytest.mark.parametrize("user,server", [("42-123", "interop"), ("group", "interop.g.us")])
def test_fa_tuple_does_not_force_f4_semantics_by_domain(codec, user, server):
    # FA carries two generic strings. It has no device/integrator fields.
    payload = b"\xfa" + bytes([252, len(user)]) + user.encode()
    payload += bytes([252, len(server)]) + server.encode()
    wire = bytes.fromhex("f8030304") + payload
    jid = JID(user, server)
    assert codec.read(wire, framed=False) == wrap(jid)
    own = codec.write(wrap(jid), framed=False)
    assert own[4] == 250
    assert codec.read(own, framed=False) == wrap(jid)
    assert str(jid) == f"{user}@{server}"


@pytest.mark.parametrize("user", [None, ""])
def test_f4_user_requires_nonempty_string(codec, user):
    # APK X.00K.A05(CharSequence) calls TextUtils.isEmpty, not just null check.
    with pytest.raises(ValueError):
        JID(user, "interop", integrator=0)
    encoded_user = b"\0" if user is None else b"\xff\0"
    wire = bytes.fromhex("f8030304f4") + encoded_user + b"\0" * 5
    with pytest.raises(ProtocolError):
        codec.read(wire, framed=False)
