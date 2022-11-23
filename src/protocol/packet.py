import select
import time
from dataclasses import dataclass
import socket
import _pickle as cPickle
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
    """
    Encrypt the given packet with the given key and nonce using AES-GCM

    :param packet: PackEncrypted packet to be encrypted
    :param key: Diffie-Hellman key to be used
    :param nonce: nonce associated with packet
    :return: the encrypted bytes
    """
    data = cPickle.dumps(packet)
    gcm = AESGCM(key)
    return gcm.encrypt(nonce, data, None)


def decrypt(packet: bytes, key: bytes, nonce: bytes) -> PackEncrypted:
    """
    Decrypts the given bytes using the given key and nonce with AES-GCM

    :param packet: bytes to be decrypted
    :param key: Diffie-Hellman key to be used
    :param nonce: nonce associated with bytes
    :return: the decrypted bytes as a PackEncrypted
    """
    gcm = AESGCM(key)
    return cPickle.loads(gcm.decrypt(nonce, packet, None))


def send(dest: tuple[str, int], sock: socket.socket, pack: Packet) -> int:
    """
    Sends a packet over given UDP socket to the given address

    :param dest: tuple with the destination host and port
    :param sock: udp socket to transmit message
    :param pack: Packet to be sent
    :return: 0 on success and 1 on failure
    """
    try:
        sock.sendto(cPickle.dumps(pack), dest)
    except Exception:
        return 1

    return 0


def recv(socks: list[socket.socket]) -> list[(Packet, float)]:
    """
    Listens for messages on all sockets in the list of provided sockets and returns list of messages

    :param socks: list of sockets to listen on
    :return: list of tuples with the Packet and float of time of reception
    """
    msgs = select.select(socks, [], [], 0.1)[0]
    packets = []
    for conn in msgs:
        data, addr = conn.recvfrom(1500)
        packets.append((cPickle.loads(data), time.time()))

    return packets
