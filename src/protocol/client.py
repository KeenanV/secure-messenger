import os
import socket
import sys
import threading
import time
from argparse import ArgumentParser

import srp
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

import packet_manager
from packet import Flags


class Client:
    def __init__(self, name: str, password: str, reg: bool, ip: str, port: int):
        self.start_time = time.time()
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ss.bind((ip, port))  # localhost for testing
        self.name = name
        self.pw = password
        self.socket = socket
        self.port = port
        self.exit = 0
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
        self.server_pub: RSAPublicKey
        with open("serve_pub.pem", "rb") as ff:
            self.server_pub = serialization.load_pem_public_key(ff.read(),)

        self.pm = packet_manager.PacketManager(uid=self.name, sock=self.ss, port=self.port, rsa_key=self.rsa_priv)
        if reg:
            self.run_reg()
        else:
            self.thread2 = threading.Thread(target=self.usr_in)
            self.thread2.start()
            self.run()

    def run_reg(self):
        self.pm.new_cs_sesh(os.urandom(16), addr=("localhost", 1337),
                            usrp=None, pub_key=self.server_pub, reg=True)
        salt, vkey = srp.create_salted_verification_key(self.name, self.pw)
        pub = self.rsa_priv.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.pm.queue((self.name, salt, vkey, pub), flag=Flags.REG, uid="server")

        while True:
            self.pm.run()

            msg = self.pm.get_reg_msg()
            if msg == "ok":
                print("Congrats you're registered! Now log in")
                break
            elif msg == "bad user":
                print("Username already taken. Try again")
                break

    def run(self):
        usr = srp.User(self.name, self.pw)
        handshakes = []
        self.pm.new_cs_sesh(os.urandom(16), addr=("localhost", 1337),
                            usrp=usr, pub_key=self.server_pub)
        while True:
            if self.exit >= 2:
                raise SystemExit()

            self.pm.run()
            svr = self.pm.get_msgs("server")
            for msg in svr:
                if isinstance(msg, tuple):
                    if "connection" in msg[0]:
                        user = msg[1]
                        cid = msg[2]
                        rand_str = msg[3]
                        conn_addr = msg[4]
                        conn_key = serialization.load_pem_public_key(msg[5],)
                        initiated = False
                        if "connection initialized:" in msg[0]:
                            initiated = True
                        if cid and rand_str and conn_addr and conn_key:
                            self.pm.new_cc_sesh(user, cid, conn_addr, conn_key, initiated)
                            if not initiated:
                                self.pm.queue("ok", None, "server")
                            handshakes.append((user, rand_str, initiated))
                    elif msg[0] == "list":
                        print("List of users: ")
                        print(msg[1])

            for usr in handshakes:
                if self.pm.get_cr_ready(usr[0]):
                    chall = hashes.Hash(hashes.SHA256())
                    chall.update(usr[1])
                    self.pm.queue(chall.finalize(), Flags.CR, usr[0])
                    self.pm.set_cr_ready(usr[0], False)
                cr = self.pm.get_cr_msg(usr[0])
                if cr is not None:
                    base = hashes.Hash(hashes.SHA256())
                    base.update(usr[1])
                    challenge = base.finalize()
                    resp = hashes.Hash(hashes.SHA256())
                    resp.update(usr[1] + b'a')
                    response = resp.finalize()
                    if usr[2]:
                        if response != cr:
                            self.pm.kill(usr[0])
                            handshakes.remove(usr)
                            continue
                        handshakes.remove(usr)
                    else:
                        if challenge != cr:
                            self.pm.kill(usr[0])
                            handshakes.remove(usr)
                            continue
                        self.pm.queue(response, Flags.CR, usr[0])
                        handshakes.remove(usr)

            for msg in self.pm.get_msgs():
                print(f"Message from {msg[0]}:")
                print(f"{msg[1]}\n\n")

            sys.stdout.flush()
            time.sleep(0.01)

    def usr_in(self):
        while True:
            usr_in = input("> ")

            if usr_in == "logout":
                self.exit += 1
                self.command(usr_in.split())
                break
            self.command(usr_in.split())

    def command(self, usr_in: list[str]):
        msg = ''
        if len(usr_in) >= 3:
            msg = ' '.join(usr_in[2:])
            usr_in = [usr_in[0], usr_in[1]]

        match usr_in:
            case ["connect", user]:
                self.pm.queue(("connect",  user), None, "server")
            case ["send", user]:
                if self.pm.hash_session(user):
                    self.pm.queue(msg, None, user)
                
            case ["list"]:
                self.pm.queue("list", None, "server")  # list request flag
            case ["logout"]:
                print("Logging out...")
                self.pm.queue("logout", None, "server")
                self.exit += 1
            case _:
                print("Unrecognized input: ", usr_in)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-usr", type=str, required=True)
    parser.add_argument("-pw", type=str, required=True)
    parser.add_argument("-ip", type=str, required=True)
    parser.add_argument("-port", type=int, required=True)
    parser.add_argument("-reg", action="store_true")

    args = parser.parse_args()
    client = Client(args.usr, args.pw, args.reg, args.ip, args.port)
