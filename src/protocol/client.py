import socket, string
import random, os
import packet, packet_manager
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat


class Client:
    def __init__(self, name: str, socket: socket, port: int, rsa_key: RSAPrivateKey):
        self.name = name
        self.socket = socket
        self.port = port
        self.key = rsa_key

        self.pm = packet_manager.PacketManager(uid=str, sock=self.socket, port=self.port, rsa_key=self.key)

    
    def run(self):
        while True:
            pass

