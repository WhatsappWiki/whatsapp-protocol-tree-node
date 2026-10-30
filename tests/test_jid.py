import pytest

from protocol_tree_node import Attribute, Codec, JID, Node, ProtocolError, TokenDictionary


def wrap(jid):
    return Node("node", attrs=(Attribute("key", jid),))


@pytest.mark.parametrize(
    "jid, payload",
    [
        (JID("123", "lid"), "faff82123ffc036c6964"),
        (JID(None, "s.whatsapp.net"), "fa0006"),
        (JID("12345", "s.whatsapp.net", device=2, flags=0), "f70002ff8312345f"),
        (JID("123", "lid", device=2, flags=1), "f70102ff82123f"),
        (JID("12345", "hosted", device=99, flags=128), "f78063ff8312345f"),
        (JID("123", "hosted.lid", device=99, flags=129), "f78163ff82123f"),
        (JID("12345", "s.whatsapp.net"), "faff8312345f06"),
        (JID("123", "interop", integrator=513), "f4ff82123f0000020100"),
        (JID("123", "interop.g.us", integrator=0), "f4ff82123f0000000002"),
    ],
)
def test_jid_golden(jid, payload):
    codec = Codec(TokenDictionary([None, None, None, "node", "key", "child", "s.whatsapp.net"]))
    wire = bytes.fromhex("f8030304" + payload)
    assert codec.write(wrap(jid), framed=False) == wire
    assert codec.read(wire, framed=False) == wrap(jid)


@pytest.mark.parametrize("server,flags,device", [
    ("s.whatsapp.net", 0, 7), ("lid", 1, 7),
    ("hosted", 128, 99), ("hosted.lid", 129, 99),
])
def test_device_domain_selection(codec, server, flags, device):
    node = wrap(JID("12345", server, device=device))
    wire = codec.write(node, framed=False)
    assert wire[4:7] == bytes([247, flags, device])
    assert codec.write(codec.read(wire, framed=False), framed=False) == wire


def test_unknown_domain_string_is_not_coerced(codec):
    node = wrap("123@example.test")
    wire = codec.write(node, framed=False)
    assert wire[4] == 252
    assert codec.read(wire, framed=False) == node


@pytest.mark.parametrize("device", [0, 99])
def test_device_client_range_extremes(codec, device):
    node = wrap(JID("123", "lid", device=device, flags=1))
    wire = codec.write(node)
    decoded = codec.read(wire)
    assert decoded.attrs[0].value.user == "123"
    assert decoded.attrs[0].value.device == device
    if device:
        assert decoded == node
    else:
        # F7 renders device zero without a suffix before using the factory.
        assert decoded.attrs[0].value.flags is None
        assert codec.write(decoded, framed=False)[4] == 250


@pytest.mark.parametrize("integrator", [1, 999])
def test_interop_integrator_client_range_extremes(codec, integrator):
    node = wrap(JID("123", "interop", integrator=integrator))
    assert codec.read(codec.write(node)) == node


@pytest.mark.parametrize("jid", [
    JID("12345", "example.test"), JID(None, "example.test"),
    JID("123", "s.whatsapp.net", device=2, flags=0),
    JID("123", "hosted", device=99, flags=128),
    JID("123", "s.whatsapp.net", device=0, flags=0),
    JID("x", "lid", flags=1), JID("123", "lid", device=255, flags=1),
    JID("123", "interop", device=258, integrator=513),
    JID("x", "interop", integrator=0),
    JID("x", "interop", device=65535, integrator=65535),
    JID("group", "interop.g.us", integrator=0),
])
def test_invalid_generic_tuples_are_rejected_by_client_writer(codec, jid):
    with pytest.raises(ProtocolError):
        codec.write(wrap(jid))


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
    {"user": "123", "server": "lid", "device": 256},
    {"user": "123", "server": "lid", "device": -1},
    {"user": "123", "server": "interop", "integrator": 65536},
    {"user": "123", "server": "interop", "integrator": -1},
    {"user": "123", "server": "interop.g.us", "device": 1, "integrator": 0},
    {"user": "123", "server": "interop.g.us", "device": 0, "integrator": 1},
])
def test_jid_input_bounds(codec, jid):
    with pytest.raises(ValueError):
        codec.write(wrap(JID(**jid)))


@pytest.mark.parametrize("kwargs", [
    {"user": 3, "server": "lid"},
    {"user": "x", "server": ""},
    {"user": "x", "server": "interop", "integrator": 0, "flags": 0},
    {"user": "x", "server": "lid", "integrator": 0},
    {"user": "x", "server": "lid", "flags": 256},
    {"user": "123", "server": "lid", "device": 1 << 31},
    {"user": "123", "server": "interop", "integrator": -(1 << 31) - 1},
])
def test_invalid_jid_model(kwargs):
    with pytest.raises(ValueError):
        JID(**kwargs)


def test_device_flags_normalize_uninterpreted_bits(codec):
    jid = JID("123", "lid", device=7, flags=65)
    wire = codec.write(wrap(jid), framed=False)
    assert wire == bytes.fromhex("f8030304f70107ff82123f")
    assert codec.read(wire, framed=False) == wrap(JID("123", "lid", device=7, flags=1))


def test_hosted_device_mismatch_rejects_explicit_object_but_reads_as_text(codec):
    jid = JID("12345", "hosted", device=7, flags=128)
    with pytest.raises(ProtocolError):
        codec.write(wrap(jid))
    wire = bytes.fromhex("f8030304f78007ff8312345f")
    node = codec.read(wire, framed=False, preserve_wire=True)
    assert node == wrap("12345:7@hosted")
    assert codec.write(node, framed=False) == b"\xf8\x03\x03\x04\xfc\x0e12345:7@hosted"
    assert codec.write(node, framed=False, preserve_wire=True) == wire


def test_explicit_tuple_model_accepts_domain_metadata_before_client_normalization(codec):
    unknown = JID("123", "unknown", device=1)
    with pytest.raises(ProtocolError):
        codec.write(wrap(unknown))
    mismatched = JID("123", "lid", flags=0)
    assert codec.write(wrap(mismatched), framed=False) == bytes.fromhex("f8030304f70100ff82123f")


@pytest.mark.parametrize("user,server,expected", [
    ("42-123", "interop", JID("123", "interop", integrator=42)),
    ("123", "interop.g.us", JID("123", "interop.g.us", integrator=0)),
])
def test_fa_tuple_uses_client_interop_factory(codec, user, server, expected):
    payload = b"\xfa" + bytes([252, len(user)]) + user.encode()
    payload += bytes([252, len(server)]) + server.encode()
    wire = bytes.fromhex("f8030304") + payload
    assert codec.read(wire, framed=False) == wrap(expected)
    own = codec.write(wrap(expected), framed=False)
    assert own[4] == 244
    assert codec.read(own, framed=False) == wrap(expected)


def test_fa_invalid_interop_group_falls_back_to_text(codec):
    wire = bytes.fromhex("f8030304fa") + b"\xfc\x05group\xfc\x0cinterop.g.us"
    assert codec.read(wire, framed=False) == wrap("group@interop.g.us")


@pytest.mark.parametrize("user", [None, ""])
def test_f4_user_requires_nonempty_string(codec, user):
    # APK X.00K.A05(CharSequence) calls TextUtils.isEmpty, not just null check.
    with pytest.raises(ValueError):
        JID(user, "interop", integrator=0)
    encoded_user = b"\0" if user is None else b"\xff\0"
    wire = bytes.fromhex("f8030304f4") + encoded_user + b"\0" * 5
    with pytest.raises(ProtocolError):
        codec.read(wire, framed=False)
