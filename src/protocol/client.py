import socket
from argparse import ArgumentParser
from os.path import exists

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

import packet_manager


class Client:
    def __init__(self, name: str, password: str, reg: bool, ip: str, port: int):
        self.reg = reg
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ss.bind(('localhost', port))  # localhost for testing
        self.name = name
        self.pw = password
        self.socket = socket
        self.port = port
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
        self.server_pub: RSAPublicKey  # TODO

        self.pm = packet_manager.PacketManager(uid=self.name, sock=self.ss, port=self.port, rsa_key=self.rsa_priv)
    
    def run(self):
        while True:
            usr_in = input("> ")
            # usr_in = stdin.read().rstrip()
            # if not usr_in:
            #     print("> ", end="")
            #     return
            self.command(usr_in)

    def command(self, usr_in: str):
        command = usr_in.split()
        match command:
            case ["connect", user, msg]:
                # This needs to ask the server first to get the addr, rsa, and cid
                # self.pm.new_cc_sesh(self.name)  # have packet manager set up
                pass
            case ["send", user, msg]:
                self.pm.queue(msg, None, user)  # have packet manager set up
            case ["list"]:
                self.pm.queue("list", None, "server")  # list request flag
            case ["logout"]:
                exit(0)
            case _:
                print("Unrecognized input: ", input)


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
            pub = serialization.load_der_public_key(pub_key_file.read(),
                                                    backend=default_backend())
            return pub
        elif pub.lower().endswith('.pem'):
            pub = serialization.load_pem_public_key(pub_key_file.read(),
                                                    backend=default_backend())
            return pub


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-user", type=str, required=True)
    parser.add_argument("-pw", type=str, required=True)
    parser.add_argument("-ip", type=str, required=True)
    parser.add_argument("-port", type=int, required=True)
    parser.add_argument("-reg", type=str, required=False)

    args = parser.parse_args()
    client = Client(args.user, args.pw, args.reg, args.ip, args.port)
    client.run()
