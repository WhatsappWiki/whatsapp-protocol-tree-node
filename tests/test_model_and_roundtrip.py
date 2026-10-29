import json
import random
from concurrent.futures import ThreadPoolExecutor

import pytest

from protocol_tree_node import Attribute, JID, Node, read, write


def test_model_preserves_attribute_order_and_duplicates():
    node = Node("node", attrs=[Attribute("key", "first"), Attribute("key", "second")])
    assert [a.value for a in node.attrs] == ["first", "second"]
    assert isinstance(node.attrs, tuple)


def test_mapping_convenience(codec):
    node = Node("node", attrs={"first": "1", "second": "2"})
    assert tuple(a.name for a in node.attrs) == ("first", "second")
    assert codec.read(codec.write(node)) == node


def test_json_model_round_trip(codec):
    node = Node("node", attrs=(Attribute("key", JID("123", "lid", flags=1)), Attribute("key", None)),
                children=(Node("child", data=bytes(range(256))),))
    plain = json.loads(json.dumps(node.to_dict()))
    assert Node.from_dict(plain) == node
    assert codec.read(codec.write(Node.from_dict(plain))) == node


def test_none_and_empty_bytes_are_distinct(codec):
    none = Node("node")
    empty = Node("node", data=b"")
    assert none != empty
    assert codec.write(none) != codec.write(empty)
    assert codec.read(codec.write(none)).data is None
    assert codec.read(codec.write(empty)).data == b""


@pytest.mark.parametrize("kwargs", [
    {"tag": ""}, {"tag": 3}, {"tag": "node", "data": "text"},
    {"tag": "node", "data": b"", "children": ()},
    {"tag": "node", "children": ["child"]},
    {"tag": "node", "attrs": [("key", "value")]},
])
def test_invalid_model_inputs(kwargs):
    with pytest.raises(ValueError):
        Node(**kwargs)


@pytest.mark.parametrize("name,value", [("", "ok"), (None, "ok"), ("key", 123), ("key", b"raw")])
def test_invalid_attribute_inputs(name, value):
    with pytest.raises(ValueError):
        Attribute(name, value)


def test_jid_display():
    assert str(JID("123", "example.test")) == "123@example.test"
    assert str(JID("123", "lid", device=7)) == "123:7@lid"
    assert str(JID("123", "interop", device=8, integrator=42)) == "42-123:8@interop"
    assert str(JID(None, "example.test")) == "example.test"


def test_seeded_random_nested_roundtrips(codec):
    rng = random.Random(271828)
    words = ["node", "child", "unknown", "消息", "emoji🙂", "1"]
    values = [None, "", "12345", "12:34", "ABCDEF", "abcdef", "你好", "key", "a@b"]

    def build(depth=0):
        attrs = tuple(Attribute(rng.choice(words), rng.choice(values)) for _ in range(rng.randrange(5)))
        kind = rng.randrange(3 if depth < 4 else 2)
        if kind == 0:
            return Node(rng.choice(words), attrs=attrs)
        if kind == 1:
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(130)))
            return Node(rng.choice(words), attrs=attrs, data=data)
        return Node(rng.choice(words), attrs=attrs, children=tuple(build(depth+1) for _ in range(rng.randrange(1, 4))))

    for _ in range(200):
        node = build()
        for framed, compressed in [(False, False), (True, False), (True, True)]:
            encoded = codec.write(node, framed=framed, compress=compressed)
            assert codec.read(encoded, framed=framed) == node
        assert Node.from_dict(json.loads(json.dumps(node.to_dict()))) == node


def test_codec_is_reusable_concurrently(codec):
    nodes = [Node("node", attrs={"key": str(i)}, data=bytes([i]) * i) for i in range(128)]
    def roundtrip(node):
        return codec.read(codec.write(node, compress=True))
    with ThreadPoolExecutor(max_workers=8) as workers:
        assert list(workers.map(roundtrip, nodes)) == nodes


def test_function_api_requires_explicit_dictionary(dictionary):
    node = Node("node", attrs={"key": "123"})
    for framed in (True, False):
        data = write(node, dictionary=dictionary, framed=framed)
        assert read(data, dictionary=dictionary, framed=framed) == node


@pytest.mark.parametrize("factory", [bytearray, memoryview])
def test_bytes_like_input(codec, factory):
    node = Node("node", data=b"\xff")
    assert codec.read(factory(codec.write(node))) == node


def test_read_empty_children_list(codec):
    node = codec.read(bytes.fromhex("f8020300"), framed=False)
    assert node == Node("node", children=())
    assert codec.write(node, framed=False) == bytes.fromhex("f80103")
