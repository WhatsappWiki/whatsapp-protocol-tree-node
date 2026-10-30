"""Fixed synthetic expectations from the client's DEX address factories.

These exercise domain constructors and Java integer/byte boundaries. They do
not claim fresh Android execution; source anchors are kept outside the package
in protocol-tree-analysis/jid-compatibility.
"""
import pytest

from protocol_tree_node import Codec, JID, Node, ProtocolError, TokenDictionary
from protocol_tree_node.jid import (
    InvalidJID, is_protocol_compliant, normalize_jid, parse_jid, try_parse_jid,
)


@pytest.mark.parametrize("text,expected", [
    ("12345@s.whatsapp.net", JID("12345", "s.whatsapp.net")),
    ("10080@s.whatsapp.net", JID("10080", "s.whatsapp.net")),
    ("1" * 20 + "@s.whatsapp.net", JID("1" * 20, "s.whatsapp.net")),
    ("0@s.whatsapp.net", JID("0", "s.whatsapp.net")),
    ("Server@s.whatsapp.net", JID("Server", "s.whatsapp.net")),
    ("gdpr@s.whatsapp.net", JID("gdpr", "s.whatsapp.net")),
    ("12345@hosted", JID("12345", "s.whatsapp.net")),
    ("0@hosted", JID("0", "s.whatsapp.net")),
    ("Server@hosted", JID("Server", "s.whatsapp.net")),
    ("1@lid", JID("1", "lid")),
    ("1" * 15 + "@lid", JID("1" * 15, "lid")),
    ("123@hosted.lid", JID("123", "lid")),
    ("123:0@lid", JID("123", "lid", flags=1)),
    ("12345:0@s.whatsapp.net", JID("12345", "s.whatsapp.net", flags=0)),
    ("12345.agent-text:7@s.whatsapp.net", JID("12345", "s.whatsapp.net", 7, flags=0)),
    ("12345.ignored@s.whatsapp.net", JID("12345", "s.whatsapp.net", flags=0)),
    ("12345:99@hosted", JID("12345", "hosted", 99, flags=128)),
    ("123:99@hosted.lid", JID("123", "hosted.lid", 99, flags=129)),
    ("1@bot", JID("1", "bot")),
    ("1" * 20 + "@bot", JID("1" * 20, "bot")),
    ("123:0@bot", JID("123", "bot", flags=0)),
    ("123:1@bot", JID("123", "bot", 1, flags=0)),
    ("42-123:0@interop", JID("123", "interop", integrator=42)),
    ("1@g.us", JID("1", "g.us")),
    ("1" * 20 + "@g.us", JID("1" * 20, "g.us")),
    ("12345-1234567890@g.us", JID("12345-1234567890", "g.us")),
    ("1@interop.g.us", JID("1", "interop.g.us", integrator=0)),
    ("1@broadcast", JID("1", "broadcast")),
    ("1" * 20 + "@broadcast", JID("1" * 20, "broadcast")),
    ("status@broadcast", JID("status", "broadcast")),
    ("location@broadcast", JID("location", "broadcast")),
    ("0123456789aBcDeFaB@call", JID("0123456789aBcDeFaB", "call")),
    ("A" * 32 + "@call", JID("A" * 32, "call")),
    ("-@temp", JID("-", "temp")),
    ("anything-else@temp", JID("anything-else", "temp")),
    ("non-digit@newsletter", JID("non-digit", "newsletter")),
    (" 1 @newsletter", JID(" 1 ", "newsletter")),
    ("\x00\t1\x1f@newsletter", JID("\x00\t1\x1f", "newsletter")),
    ("\u00a00@newsletter", JID("\u00a00", "newsletter")),
    ("a@b@newsletter", JID("a@b", "newsletter")),
    ("s.whatsapp.net", JID(None, "s.whatsapp.net")),
    ("g.us", JID(None, "g.us")),
    ("call", JID(None, "call")),
    ("status_me", JID(None, "status_me")),
    ("lid_me", JID(None, "lid_me")),
])
def test_fixed_domain_constructor_results(text, expected):
    assert parse_jid(text) == expected
    assert normalize_jid(expected) == expected


@pytest.mark.parametrize("text", [
    "", "@s.whatsapp.net", "12345@", "12345@c.us", "12345@unknown.test",
    "12345@S.WHATSAPP.NET", "lid", "hosted", "foo@status_me", "foo@lid_me",
    "1234@s.whatsapp.net", "1" * 21 + "@s.whatsapp.net",
    "01234@s.whatsapp.net", "10123@s.whatsapp.net", "10000@s.whatsapp.net",
    "１２３４５@s.whatsapp.net", "server@s.whatsapp.net", "gdpr@hosted",
    "0@lid", "01@lid", "1" * 16 + "@lid", "+1@lid", "١@lid",
    "0@bot", "1" * 21 + "@bot", "bot@bot",
    "12345.@s.whatsapp.net", "12345:@s.whatsapp.net",
    "12345:7.agent@s.whatsapp.net", "12345.ignored.again:7@s.whatsapp.net",
    "12345:7@hosted", "12345:355@hosted", "123:0@hosted.lid",
    "0@g.us", "1" * 21 + "@g.us", "1234-1234567890@g.us",
    "12345-0234567890@g.us", "12345-123456789@g.us",
    "12345-12345678901@g.us", "12345-1234567890@interop.g.us",
    "0@broadcast", "Status@broadcast", "1" * 21 + "@broadcast",
    "a" * 17 + "@call", "a" * 33 + "@call", "g" * 18 + "@call",
    "abc@temp", "01@newsletter", " \t\x1f@newsletter", " 0 @newsletter",
])
def test_invalid_addresses_fail_strictly_and_soft_factory_returns_none(text):
    with pytest.raises(InvalidJID):
        parse_jid(text)
    assert try_parse_jid(text) is None


@pytest.mark.parametrize("text", [None, 123, b"12345@s.whatsapp.net"])
def test_non_string_factory_inputs(text):
    with pytest.raises(InvalidJID):
        parse_jid(text)
    assert try_parse_jid(text) is None
    assert try_parse_jid(text, bare=True) is None


@pytest.mark.parametrize("text,device", [
    ("+7", 7), ("0007", 7), ("７", 7), ("٧", 7), ("-0", 0),
    ("99", 99), ("256", 256), ("355", 355), ("-256", -256), ("-157", -157),
    ("2147483392", 2147483392), ("-2147483648", -2147483648),
])
def test_device_int_parse_and_signed_byte_cast_keep_original_int(text, device):
    expected = JID("12345", "s.whatsapp.net", device, flags=0)
    assert parse_jid(f"12345:{text}@s.whatsapp.net") == expected
    assert normalize_jid(expected) == expected


@pytest.mark.parametrize("text", [
    "-1", "100", "127", "128", "255", "356", "-257",
    "2147483647", "2147483648", "-2147483649", "+", "--1", "²", "𝟟", " 7", "7 ",
])
def test_invalid_device_integers_or_signed_byte_cast(text):
    with pytest.raises(InvalidJID):
        parse_jid(f"12345:{text}@s.whatsapp.net")


@pytest.mark.parametrize("prefix,number", [
    ("1", 1), ("999", 999), ("+1", 1), ("-1", -1), ("-99", -99),
    ("+0", 0), ("-0", 0), ("+00", 0), ("٠", 0), ("١٢", 12),
])
def test_interop_integrator_source_spelling_is_parsed_numerically(prefix, number):
    expected = JID("123", "interop", integrator=number)
    assert parse_jid(f"{prefix}-123@interop") == expected
    assert normalize_jid(expected) == expected


@pytest.mark.parametrize("text", [
    "0-123@interop", "01-123@interop", "1000-123@interop", "-100-123@interop",
    "1-0@interop", "1-01@interop", "1-" + "1" * 16 + "@interop",
    "1-١٢٣@interop", "123@interop", "1-@interop", "1-123:1@interop",
])
def test_invalid_interop_components_and_nonzero_device(text):
    with pytest.raises(InvalidJID):
        parse_jid(text)


@pytest.mark.parametrize("text,compliant", [
    ("0@s.whatsapp.net", True), ("Server@s.whatsapp.net", False),
    ("gdpr@s.whatsapp.net", False), ("status_me", False), ("lid_me", False),
    ("-@temp", False), ("Server:0@s.whatsapp.net", True),
    ("Server:1@s.whatsapp.net", True), ("status@broadcast", True),
])
def test_compliance_depends_on_client_type_including_device_wrapper(text, compliant):
    assert is_protocol_compliant(parse_jid(text)) is compliant


@pytest.mark.parametrize("domain", ["s.whatsapp.net", "g.us", "call"])
def test_writer_bare_factory_only_recognizes_three_domain_singletons(domain):
    assert try_parse_jid(domain, bare=True) == JID(None, domain)


@pytest.mark.parametrize("text", ["status_me", "lid_me", "lid", "12345@s.whatsapp.net"])
def test_writer_bare_factory_does_not_call_the_general_factory(text):
    assert try_parse_jid(text, bare=True) is None


@pytest.mark.parametrize("source,expected", [
    (JID("123", "lid", flags=65), JID("123", "lid", flags=1)),
    (JID("123", "lid"), JID("123", "lid")),
    (JID("12345", "s.whatsapp.net", flags=64), JID("12345", "s.whatsapp.net", flags=0)),
    (JID("12345", "hosted"), JID("12345", "s.whatsapp.net")),
    (JID("123", "hosted.lid"), JID("123", "lid")),
    (JID("Server", "s.whatsapp.net", flags=0), JID("Server", "s.whatsapp.net", flags=0)),
])
def test_normalization_preserves_wrapper_identity_and_canonicalizes_flags(source, expected):
    assert normalize_jid(source) == expected


@pytest.mark.parametrize("source", [
    None, "123@lid", JID("123", "unknown.test"),
    JID(None, "s.whatsapp.net", flags=0),
    JID("123", "interop", integrator=1000),
])
def test_explicit_address_normalization_rejects_unconstructible_objects(source):
    with pytest.raises(InvalidJID):
        normalize_jid(source)


def test_factory_object_and_binary_wire_widths_are_separate():
    codec = Codec(TokenDictionary([None, None, None, "iq", "to", "s.whatsapp.net"]))
    def node(jid):
        return Node("iq", attrs={"to": jid})

    # Valid signed-byte cast, but its positive original int cannot fit F7.
    too_wide = parse_jid("12345:256@s.whatsapp.net")
    with pytest.raises(ProtocolError, match="uint8"):
        codec.write(node(too_wide), framed=False)

    # A nonpositive phone-device value does not select F7 in the writer.
    negative = parse_jid("12345:-256@s.whatsapp.net")
    assert codec.write(node(negative), framed=False) == bytes.fromhex("f8030304faff8312345f05")

    negative_integrator = parse_jid("-1-123@interop")
    with pytest.raises(ProtocolError, match="uint16"):
        codec.write(node(negative_integrator), framed=False)

    # '+0' constructs an interop object; the reader renders F4 zero as '0-123'
    # and the native strict factory rejects that spelling. The node reader
    # catches InvalidJid and retains it as an ordinary attribute string.
    zero_integrator = parse_jid("+0-123@interop")
    zero_wire = bytes.fromhex("f8030304f4ff82123f0000000000")
    assert codec.write(node(zero_integrator), framed=False) == zero_wire
    assert codec.read(zero_wire, framed=False).attrs[0].value == "0-123@interop"

    # The bot constructor's nonzero-device diagnostic does not throw.
    bot = parse_jid("123:1@bot")
    assert codec.write(node(bot), framed=False) == bytes.fromhex("f8030304f70001ff82123f")


def test_writer_first_at_dispatch_differs_from_strict_factory_last_at_split():
    text = "@foo@newsletter"
    assert parse_jid(text) == JID("@foo", "newsletter")
    codec = Codec(TokenDictionary([None, None, None, "iq", "to"]))
    # A05 chooses its bare-domain helper from firstIndexOf('@') < 1.
    assert codec.write(Node("iq", attrs={"to": text}), framed=False) == (
        b"\xf8\x03\x03\x04\xfc\x0f@foo@newsletter"
    )
