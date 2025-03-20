from . import Node, Block, BroadcastNetwork
from time import sleep
from hashlib import sha256
from uuid import uuid4


def test_block_serialization() -> None:
    block = Block(
        (0).to_bytes(32),
        uuid4().bytes,
        99,
        "Transaction Data 54323148594".encode(),
    )
    raw = block.serialize()
    assert block == Block.from_bytes(block.serialize())
    assert raw == Block.from_bytes(raw).serialize()


def test_single_node_mining() -> None:
    node = Node(BroadcastNetwork(), 10)
    node.start()
    sleep(3)
    node.stop()
    assert len(node.blockchain) != 0
    node_ids = set()
    block_idx = 1
    prev_hash = (0).to_bytes(32)
    for raw in node.blockchain:
        block = Block.from_bytes(raw)
        assert block.prev_hash == prev_hash
        block_hash = sha256(raw).digest()
        assert int.from_bytes(block_hash) < node._boundary_bit
        prev_hash = block_hash
        node_ids.add(block.miner_id)
        assert block_idx == int(block.body[17:].decode())
        block_idx += 1
    assert len(node_ids) == 1


def test_multiple_nodes_mining() -> None:
    n_bits = 15
    network = BroadcastNetwork()
    node_1 = Node(network, n_bits)
    node_2 = Node(network, n_bits)
    node_1.start()
    node_2.start()
    sleep(5)
    node_1.stop()
    node_2.stop()
    common_blocks = min(len(node_1.blockchain), len(node_2.blockchain))
    assert node_1.blockchain[:common_blocks] == node_2.blockchain[:common_blocks]
    assert len(node_1.blockchain) != 0
    node_ids = set()
    block_idx = 1
    prev_hash = (0).to_bytes(32)
    for raw in node_1.blockchain[:common_blocks]:
        block = Block.from_bytes(raw)
        assert block.prev_hash == prev_hash
        block_hash = sha256(raw).digest()
        assert int.from_bytes(block_hash) < node_1._boundary_bit
        prev_hash = block_hash
        node_ids.add(block.miner_id)
        assert block_idx == int(block.body[17:].decode())
        block_idx += 1
    assert len(node_ids) == 2
