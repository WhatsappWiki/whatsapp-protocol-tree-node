import pytest

from protocol_tree_node import Codec, TokenDictionary


@pytest.fixture
def dictionary():
    return TokenDictionary(
        [None, None, None, "node", "key", "child", "example.test"], []
    )


@pytest.fixture
def codec(dictionary):
    return Codec(dictionary)
