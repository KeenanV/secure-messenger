import socket, string
import random, os
from sys import stdin, stdout, stderr
from cryptography.hazmat.backends import default_backend
from os.path import exists
import packet, packet_manager
from argparse import ArgumentParser
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat


class Client:
    def __init__(self, name: str, password: str, reg: bool, socket: socket, port: int, rsa_key: str):
        self.name = name
        self.pw = password
        self.socket = socket
        self.port = port
        self.key = get_key(rsa_key)

        self.pm = packet_manager.PacketManager(uid=str, sock=self.socket, port=self.port, rsa_key=self.key)

    
    def run(self):
        while True:
            input = stdin.read().rstrip()
            if not input:
                print("> ", newl=False)
                return
            self.command(input)

    def command(self, input: str):
        command = input.split()
        match command:
            case ["connect", user, msg]:
                self.pm.new_cc_sesh(self.name) # have packet manager set up
            case ["send", msg]:
                self.pm.queue(msg, None) # have packet manager set up
            case ["list"]:
                self.pm.queue(msg, None) # list request flag
            case ["logout"]:
                exit(0)
            case _:
                print("Unrecognized input: ", input)

def main():
    parser = ArgumentParser()
    parser.add_argument("-user", type=str, required=True)
    parser.add_argument("-pw", type=str, required=True)
    parser.add_argument("-ip", type=str, required=True)
    parser.add_argument("-port", type=int, required=True)
    parser.add_argument("-reg", type=str, required=False)
    parser.add_argument("-key", type=lambda x: check_fp(parser, x), required=True)

    args = parser.parse_args()
    client = Client(args.user, args.pw, args.reg, args.ip, args.port, args.key)
    client.run()


def check_fp(pub):
    if not exists(pub):
        return False
    with open(pub, "rb") as pub_key_file:
        if pub.lower().endswith('.der'):
             return True
        elif pub.lower().endswith('.pem'):
            return True
        else: 
            return False
                
def get_key(pub):
    with open(pub, "rb") as pub_key_file:
        if pub.lower().endswith('.der'):
             pub = serialization.load_der_public_key(
                pub_key_file.read(),
                backend=default_backend()
             )
             return pub
        elif pub.lower().endswith('.pem'):
            pub = serialization.load_pem_public_key(
                pub_key_file.read(),
                backend=default_backend()
            )
            return pub


if __name__ == "__main__":
    main()