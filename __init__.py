from __future__ import annotations

from hashlib import sha256
from time import time
from secrets import randbits
from dataclasses import dataclass
from multiprocessing import Process, Manager, Queue
from multiprocessing.managers import SyncManager
from queue import Empty
from enum import Enum, auto
from threading import Thread
from contextlib import suppress
from uuid import uuid4, UUID

### reduce typo risk
# This mapping should be a `StrEnum` inside the `Block` class for encapsulation
# and better type safety but for less verbosity we leave it as global variables.
PREV_HASH = "prev_hash"
TIME_STAMP = "time_stamp"
MINER_ID = "miner_id"
N_BITS = "n_bits"
NONCE = "nonce"
BODY_LENGTH = "body_length"

### block field sizes in bytes
# This map should be inside the `Block` class for encapsulation but for less
# verbosity we leave it as a global variable.
SIZE = {
    PREV_HASH: 32,
    TIME_STAMP: 4,
    MINER_ID: 16,
    N_BITS: 4,
    NONCE: 8,
    BODY_LENGTH: 4,
}

### block field byte offsets
# This map should be inside the `Block` class for encapsulation but for less
# verbosity we leave it as a global variable.
OFFSETS = {}
_offset = 0
for field, size in SIZE.items():
    OFFSETS[field] = _offset
    _offset += size


@dataclass  # nicer repr implementation
class Block:
    # 32 bytes
    prev_hash: bytes
    # 4 bytes
    time_stamp: int
    # 16 bytes
    miner_id: bytes
    # 4 bytes
    n_bits: int
    # 8 bytes
    nonce: int
    # 4 bytes
    body_length: int
    # arbitrary size depending on `block_id`
    body: bytes  # This will be "Transaction Data <block_id>"

    def __init__(
        self, prev_hash: bytes, miner_id: bytes, n_bits: int, body: bytes
    ) -> None:
        self.prev_hash = prev_hash
        self.time_stamp = int(time())
        self.miner_id = miner_id
        self.n_bits = n_bits
        self.nonce = randbits(SIZE[NONCE] * 8)
        self.body_length = len(body)
        self.body = body

    def serialize(self) -> bytes:
        return (
            self.prev_hash
            + self.time_stamp.to_bytes(SIZE[TIME_STAMP])
            + self.miner_id
            + self.n_bits.to_bytes(SIZE[N_BITS])
            + self.nonce.to_bytes(SIZE[NONCE])
            + self.body_length.to_bytes(SIZE[BODY_LENGTH])
            + self.body
        )

    @staticmethod
    def from_bytes(raw: bytes) -> Block:
        prev_hash = raw[OFFSETS[PREV_HASH] : OFFSETS[PREV_HASH] + SIZE[PREV_HASH]]
        time_stamp = int.from_bytes(
            raw[OFFSETS[TIME_STAMP] : OFFSETS[TIME_STAMP] + SIZE[TIME_STAMP]]
        )
        miner_id = raw[OFFSETS[MINER_ID] : OFFSETS[MINER_ID] + SIZE[MINER_ID]]
        n_bits = int.from_bytes(raw[OFFSETS[N_BITS] : OFFSETS[N_BITS] + SIZE[N_BITS]])
        nonce = int.from_bytes(raw[OFFSETS[NONCE] : OFFSETS[NONCE] + SIZE[NONCE]])
        body = raw[OFFSETS[BODY_LENGTH] + SIZE[BODY_LENGTH] :]
        block = Block(prev_hash, miner_id, n_bits, body)
        block.time_stamp = time_stamp
        block.nonce = nonce
        return block


class Node:
    blockchain: list[bytes]
    network: BroadcastNetwork
    id_: UUID
    _mining: Process | None
    _mining_queue: Queue  # type: ignore[type-arg]
    _mining_listener: Thread | None
    _n_bits: int
    _boundary_bit: int
    latest_block_hash: bytes
    latest_block_idx: int
    latest_timestamp: int
    _running: bool

    class _BlockStatus(Enum):
        ACCEPTED = auto()
        REJECTED = auto()

    def __init__(self, network: BroadcastNetwork, n_bits: int) -> None:
        self.blockchain = []
        self.network = network
        self.id_ = uuid4()
        self._mining = None
        self._mining_queue = network.manager.Queue()  # type: ignore[assignment]
        self._mining_listener = None
        self._n_bits = n_bits  # 2 ^ n_bits tries on average
        self._boundary_bit = 1 << (256 - n_bits)  # precompute for faster mining
        self.latest_block_hash = (0).to_bytes(32)
        self.latest_block_idx = 0
        self.latest_timestamp = 0
        self._running = False

    @property
    def n_bits(self) -> int:
        return self._n_bits

    def set_n_bits(self, n_bits: int) -> None:
        self._n_bits = n_bits
        self._boundary_bit = 1 << (256 - n_bits)

    def _validate_and_add_block(self, raw: bytes) -> Node._BlockStatus:
        block_hash = sha256(raw).digest()
        # insufficient proof of work
        if int.from_bytes(block_hash) >= self._boundary_bit:
            return self._BlockStatus.REJECTED
        # invalid serialization
        try:
            block = Block.from_bytes(raw)
        except Exception:
            return self._BlockStatus.REJECTED
        # incorrect predecessor block hash
        if block.prev_hash != self.latest_block_hash:
            return self._BlockStatus.REJECTED
        block_idx = int(block.body.decode().rsplit(maxsplit=1)[-1])
        # incorrect predecessor block id
        if block_idx != self.latest_block_idx + 1:
            return self._BlockStatus.REJECTED
        # impossible timestamp
        if block.time_stamp < self.latest_timestamp:
            return self._BlockStatus.REJECTED
        self.latest_block_hash = block_hash
        self.latest_block_idx = block_idx
        self.latest_timestamp = block.time_stamp
        self.blockchain.append(raw)
        return self._BlockStatus.ACCEPTED

    def _run(self) -> None:
        """simultaneous mining and block handling from the network"""
        self._mining_listener = Thread(
            target=self._listen_for_mined_blocks, args=(), daemon=True
        )
        self._mining_listener.start()
        while self._running:
            if self._mining is None or not self._mining.is_alive():
                self._mine_next()
            with suppress(Empty):
                raw = self.network.get_queue(self.id_).get(timeout=1)
                if (
                    self._validate_and_add_block(raw) == self._BlockStatus.ACCEPTED
                    and self._mining is not None
                    and self._mining.is_alive()
                ):
                    self._mining.terminate()
                    self._mining.join()

    def start(self) -> None:
        if self._running:
            return
        self.network.add_node(self.id_)
        self._running = True
        self._daemon = Thread(target=self._run, daemon=True)
        self._daemon.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._mining is not None and self._mining.is_alive():
            self._mining.terminate()
            self._mining.join()
        if self._mining_listener is not None:
            self._mining_listener.join()
        self._daemon.join()
        self.network.remove_node(self.id_)

    def _mine_next(self) -> None:
        block = Block(
            self.latest_block_hash,
            self.id_.bytes,
            self.n_bits,
            f"Transaction Data {self.latest_block_idx + 1}".encode(),
        )
        self._mining = Process(
            target=_mine,
            args=(block.serialize(), self._boundary_bit, self._mining_queue),
        )
        self._mining.start()

    def _listen_for_mined_blocks(self) -> None:
        while self._running:
            with suppress(Empty):
                raw = self._mining_queue.get(timeout=1)
                self.network.broadcast(raw)


def _mine(raw: bytes, boundary_bit: int, mining_queue: Queue[bytes]) -> None:
    raw = bytearray(raw)
    nonce = int.from_bytes(raw[OFFSETS[NONCE] : OFFSETS[NONCE] + SIZE[NONCE]])
    # Ensure the mined block hash is below the target difficulty threshold.
    while int.from_bytes(sha256(raw).digest()) >= boundary_bit:
        nonce += 1
        raw[OFFSETS[NONCE] : OFFSETS[NONCE] + SIZE[NONCE]] = nonce.to_bytes(8)
    mining_queue.put(bytes(raw))


class BroadcastNetwork:
    manager: SyncManager
    _queues: dict[UUID, Queue[bytes]]

    def __init__(self) -> None:
        self.manager = Manager()
        self._queues = self.manager.dict()  # type: ignore[assignment]

    def add_node(self, node_id: UUID) -> None:
        self._queues[node_id] = self.manager.Queue()  # type: ignore[assignment]

    def remove_node(self, node_id: UUID) -> None:
        if node_id in self._queues:
            del self._queues[node_id]

    def broadcast(self, raw: bytes) -> None:
        for queue in self._queues.values():
            queue.put(raw)

    def get_queue(self, node_id: UUID) -> Queue[bytes]:
        return self._queues[node_id]


if __name__ == "__main__":
    from time import sleep

    n_bits = 20
    network = BroadcastNetwork()
    node_1 = Node(network, n_bits)
    node_2 = Node(network, n_bits)
    node_1.start()
    node_2.start()
    sleep(3)
    node_1.stop()
    node_2.stop()
    print("---------------Block view from node 1:---------------")
    for block in node_1.blockchain:
        print(Block.from_bytes(block), "\n")
    print("---------------Block view from node 2:---------------")
    for block in node_2.blockchain:
        print(Block.from_bytes(block), "\n")
