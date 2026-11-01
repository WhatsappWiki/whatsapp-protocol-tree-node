"""Node and JID depth limits can both be reached in the same packet."""
import pytest

from protocol_tree_node import Codec, Limits, ProtocolError


def nested_packet(node_depth, jid_depth, position):
    value = b"\xfc\x01x"
    for _ in range(jid_depth):
        value = b"\xfa" + value + b"\xfc\x01s"
    leaves = {
        "tag": b"\xf8\x01" + value,
        "attribute_name": b"\xf8\x03\x03" + value + b"\x00",
        "attribute_value": b"\xf8\x03\x03\x04" + value,
        "data": b"\xf8\x02\x03" + value,
    }
    return bytes.fromhex("f80203f801") * (node_depth - 1) + leaves[position]


@pytest.mark.parametrize("preserve_wire", [False, True])
@pytest.mark.parametrize("position", ["tag", "attribute_name", "attribute_value", "data"])
def test_maximum_node_and_jid_depths_together(dictionary, preserve_wire, position):
    codec = Codec(dictionary, limits=Limits(max_depth=256))
    packet = nested_packet(256, 256, position)
    node = codec.read(packet, framed=False, preserve_wire=preserve_wire)
    leaf = node
    for _ in range(255):
        assert len(leaf.children) == 1
        leaf = leaf.children[0]
    value = "x" + "@s" * 256
    if position == "tag":
        assert leaf.tag == value
    elif position == "attribute_name":
        assert leaf.attrs[0].name == value
    elif position == "attribute_value":
        assert leaf.attrs[0].value == value
    else:
        assert leaf.data == value.encode()
    # Exercise the writer at the same combined depth, without recursive Node
    # equality or JSON conversion introducing an unrelated stack constraint.
    if preserve_wire:
        assert codec.write(node, framed=False, preserve_wire=True) == packet
    else:
        assert codec.read(codec.write(node, framed=False), framed=False).tag == node.tag


@pytest.mark.parametrize("preserve_wire", [False, True])
@pytest.mark.parametrize("nodes,jids,error", [
    (256, 257, "JID nesting exceeds depth limit"),
    (257, 256, "node depth exceeds limit"),
])
def test_combined_depth_overflow_is_a_protocol_error(dictionary, preserve_wire, nodes, jids, error):
    codec = Codec(dictionary, limits=Limits(max_depth=256))
    packet = nested_packet(nodes, jids, "attribute_value")
    with pytest.raises(ProtocolError, match=error):
        codec.read(packet, framed=False, preserve_wire=preserve_wire)
