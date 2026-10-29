import json

import pytest

from protocol_tree_node import Attribute, Codec, Node, ProtocolError, TokenDictionary


@pytest.mark.parametrize("page", range(4))
@pytest.mark.parametrize("index", [0, 1, 255])
def test_all_dictionary_pages_and_index_extremes(page, index):
    pages = [[None] * 256 for _ in range(4)]
    pages[page][index] = "custom-token"
    codec = Codec(TokenDictionary([None] * 3, pages))
    expected = bytes([248, 1, 236 + page, index])
    node = Node("custom-token")
    assert codec.write(node, framed=False) == expected
    assert codec.read(expected, framed=False) == node


def test_replacement_dictionary_changes_meaning_without_codec_change():
    first = Codec(TokenDictionary([None, None, None, "first"], []))
    second = Codec(TokenDictionary([None, None, None, "second"], []))
    wire = bytes.fromhex("f80103")
    assert first.read(wire, framed=False).tag == "first"
    assert second.read(wire, framed=False).tag == "second"
    assert first.write(Node("first"), framed=False) == wire
    assert second.write(Node("second"), framed=False) == wire


def test_dictionary_copies_mutable_input():
    single = [None, None, None, "before"]
    pages = [["paged"]]
    codec = Codec(TokenDictionary(single, pages))
    single[3] = "after"
    pages[0][0] = "changed"
    assert codec.read(bytes.fromhex("f80103"), framed=False).tag == "before"
    assert codec.read(bytes.fromhex("f801ec00"), framed=False).tag == "paged"


def test_json_dictionary_input(tmp_path):
    payload = {"single": [None, None, None, "node"], "dictionaries": [["key"]]}
    path = tmp_path / "dictionary.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    node = Node("node", attrs=(Attribute("key", "hello"),))
    a = Codec(TokenDictionary.from_json(path))
    b = Codec(TokenDictionary.from_mapping(payload))
    assert a.write(node) == b.write(node)
    assert a.read(b.write(node)) == node


def test_duplicate_word_reverse_lookup_last_entry_wins():
    codec = Codec(TokenDictionary([None, None, None, "word"], [["word"], [None, "word"]]))
    assert codec.write(Node("word"), framed=False) == bytes.fromhex("f801ed01")
    for wire in ["f80103", "f801ec00", "f801ed01"]:
        assert codec.read(bytes.fromhex(wire), framed=False) == Node("word")


def test_dictionary_token_priority_over_nibble():
    codec = Codec(TokenDictionary([None, None, None, "node", "key", "123"], []))
    assert codec.write(Node("node", attrs={"key": "123"}), framed=False) == bytes.fromhex("f803030405")


def test_reserved_slots_do_not_encode_ordinary_strings():
    codec = Codec(TokenDictionary(["reserved0", "reserved1", "reserved2"], []))
    for word in ["reserved0", "reserved1", "reserved2"]:
        wire = codec.write(Node(word), framed=False)
        assert wire[2] == 252
        assert codec.read(wire, framed=False) == Node(word)


@pytest.mark.parametrize("single, pages", [
    ([None] * 237, []),
    ([None] * 3, [[], [], [], [], []]),
    ([None] * 3, [[None] * 257]),
    ([None, None, None, 3], []),
    ([None] * 3, [[123]]),
])
def test_bad_dictionary_shape(single, pages):
    with pytest.raises(ValueError):
        TokenDictionary(single, pages)


@pytest.mark.parametrize("wire", ["f80107", "f801ec00", "f801ef00"])
def test_missing_dictionary_entries_are_errors(codec, wire):
    with pytest.raises(ProtocolError):
        codec.read(bytes.fromhex(wire), framed=False)


def test_dictionary_holes():
    codec = Codec(TokenDictionary([None, None, None, None], [[None]]))
    for wire in ["f80103", "f801ec00"]:
        with pytest.raises(ProtocolError):
            codec.read(bytes.fromhex(wire), framed=False)


@pytest.mark.parametrize("single,pages", [("abc", []), ([], "abc"), ([], ["abc"])])
def test_dictionary_rejects_strings_as_containers(single, pages):
    with pytest.raises(ValueError):
        TokenDictionary(single, pages)
