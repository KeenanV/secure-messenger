import os
import socket
import packet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class TestClass:
    def __init__(self):
        ss1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ss1.bind(("localhost", 1337))
        ss2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ss2.bind(("localhost", 1340))
        self.socks = [ss1, ss2]

        self.dhk = self.generate_key()

    def run(self):
        pack = packet.Packet(src=0, dest=0, cid=0, encrypted=b'')
        pack.cid = 1313
        pack.src = 1337
        pack.dest = 1340

        data = packet.PackEncrypted(pnum=0, flags=[], frames={}, data="")
        data.flags = ['HELLO']
        data.pnum = 55
        data.frames = {}
        data.data = "hello there"

        # creates 128-bit nonce
        nonce = os.urandom(16)
        pack.encrypted = packet.encrypt(data, self.dhk, nonce)

        while True:
            if packet.send(("localhost", pack.dest), self.socks[0], pack) == 0:
                break

        received = packet.recv(self.socks)

        print(f"Encrypted: {received}")
        print(f"Decrypted: {packet.decrypt(received[0][0].encrypted, self.dhk, nonce)}")
        print(f"Receive Time: {received[0][1]}")

    def generate_key(self):
        """
        Generates an ECDH key from two simulated hosts

        :return: bytes of 256-bit Diffie-Hellman key
        """
        alice_priv = ec.generate_private_key(ec.SECP384R1())
        bob_priv = ec.generate_private_key(ec.SECP384R1())
        shared_key = alice_priv.exchange(ec.ECDH(), bob_priv.public_key())
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake',
        ).derive(shared_key)
        return derived_key


if __name__ == "__main__":
    test = TestClass()
    test.run()
