import select
import time
import socket
import _pickle as cPickle
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from enum import Enum


class Flags(Enum):
    HELLO = "hello"
    BYE = "bye"
    ELICIT = "elicit"
    LOGIN = "login"
    REG = "reg"
    CR = "cr"


@dataclass
class Packet:
    src: tuple[str, int]
    dest: tuple[str, int]
    cid: int
    nonce: bytes
    encrypted: bytes


@dataclass
class PackEncrypted:
    pnum: int
    flags: list
    frames: dict
    data: ...
