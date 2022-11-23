import select
import time
from dataclasses import dataclass
import socket
import _pickle as cPickle
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


@dataclass
class Packet:
    src: int
    dest: int
    cid: int
    encrypted: bytes


@dataclass
class PackEncrypted:
    pnum: int
    flags: list
    frames: dict
    data: str


def encrypt(packet: PackEncrypted, key: bytes, nonce: bytes) -> bytes:
    data = cPickle.dumps(packet)
    gcm = AESGCM(key)
    return gcm.encrypt(nonce, data, None)


def decrypt(packet: bytes, key: bytes, nonce: bytes) -> PackEncrypted:
    gcm = AESGCM(key)
    return cPickle.loads(gcm.decrypt(nonce, packet, None))


def send(dest: tuple[str, int], sock: socket.socket, pack: Packet) -> int:
    try:
        sock.sendto(cPickle.dumps(pack), dest)
    except Exception:
        return 1

    return 0


def recv(socks: list[socket.socket]) -> list[(Packet, float)]:
    msgs = select.select(socks, [], [], 0.1)[0]
    packets = []
    for conn in msgs:
        data, addr = conn.recvfrom(1500)
        packets.append((cPickle.loads(data), time.time()))

    return packets
