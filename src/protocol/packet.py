from dataclasses import dataclass
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
    cid: bytes
    nonce: bytes
    encrypted: bytes


@dataclass
class PackEncrypted:
    pnum: int
    flags: list
    frames: dict
    data: ...
