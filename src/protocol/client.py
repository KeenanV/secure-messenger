import os
import random
import socket
import sys
import threading
import time
from argparse import ArgumentParser
from os.path import exists
import hashlib

import srp
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

import packet_manager
from packet import Flags


class Client:
    def __init__(self, name: str, password: str, reg: bool, ip: str, port: int):
        self.start_time = time.time()
        self.reg = reg
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ss.bind((ip, port))  # localhost for testing
        self.name = name
        self.pw = password
        self.socket = socket
        self.port = port
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
        self.server_pub: RSAPublicKey
        with open("serve_pub.pem", "rb") as ff:
            self.server_pub = serialization.load_pem_public_key(ff.read(),)

        self.pm = packet_manager.PacketManager(uid=self.name, sock=self.ss, port=self.port, rsa_key=self.rsa_priv)
        # thread1 = threading.Thread(target=self.run)
        # thread2 = threading.Thread(target=self.usr_in)
        # thread1.start()
        # thread2.start()
        # self.run()
        # self.usr_in()
    
    def run(self):
        usr = srp.User(self.name, self.pw)
        handshakes = []
        self.pm.new_cs_sesh(os.urandom(16), addr=("localhost", 1337),
                            usrp=usr, pub_key=self.server_pub)
        while True:
            self.pm.run()
            # print(f"msgs: {self.pm.get_msgs()}")
            svr = self.pm.get_msgs("server")
            for msg in svr:
                if isinstance(msg, tuple) and "connection" in msg[0]:
                    user = msg[1]
                    print(f"USER: {user}")
                    cid = msg[2]
                    rand_str = msg[3]
                    conn_addr = msg[4]
                    conn_key = serialization.load_pem_public_key(msg[5],)
                    initiated = False
                    if "connection initialized:" in msg[0]:
                        initiated = True
                    if cid and rand_str and conn_addr and conn_key:
                        self.pm.new_cc_sesh(user, cid, conn_addr, conn_key, initiated)
                        if initiated:
                            print(f"STARTED: {user}, {conn_addr}")
                        else:
                            self.pm.queue("ok", None, "server")
                        handshakes.append((user, rand_str, initiated))

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
                            print("CR FAIL")
                            continue
                        handshakes.remove(usr)
                        print("CR SUCCESS")
                    else:
                        if challenge != cr:
                            self.pm.kill(usr[0])
                            handshakes.remove(usr)
                            print("CR FAIL")
                            continue
                        self.pm.queue(response, Flags.CR, usr[0])
                        handshakes.remove(usr)
                        print("CR SUCCESS")

            if self.name == "Bob" and self.start_time != 0.0 and time.time() - self.start_time >= 5:
                self.pm.queue(("connect", "Alice",), None, "server")
                self.start_time = 0.0
                print("CONNECTING")

            self.pm.get_msgs()
            sys.stdout.flush()
            time.sleep(0.01)

    def usr_in(self):
        # TEST
        usr = srp.User(self.name, self.pw)
        self.pm.new_cs_sesh(os.urandom(16), addr=("localhost", 1337),
                            usrp=usr, pub_key=self.server_pub)
         # TEST   
        usr_in = input("> ")
        self.command(usr_in.split())

    def command(self, usr_in: str):
        print(usr_in)
        match usr_in:
            case ["connect", user]:
                self.pm.queue(("connect",  user), None, "server")
                
                #else:
                #    self.command(["connect", user])

                # This needs to ask the server first to get the addr, rsa, and cid
                # self.pm.new_cc_sesh(self.name)  # have packet manager set up
            case ["send", user, msg]:
                if self.pm.hash_session(user):
                    self.pm.queue(msg, None, user)
                
            case ["list"]:
                self.pm.queue("list", None, "server")  # list request flag
                for msg in self.pm.get_msgs("server"):
                    if "list" in msg[1]:
                        print("List of users: " + msg[1][1])
            case ["logout"]:
                exit(0)
            case _:
                print("Unrecognized input: ", usr_in)


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
    parser.add_argument("-usr", type=str, required=True)
    parser.add_argument("-pw", type=str, required=True)
    parser.add_argument("-ip", type=str, required=True)
    parser.add_argument("-port", type=int, required=True)
    parser.add_argument("-reg", type=str, required=False)

    args = parser.parse_args()
    client = Client(args.usr, args.pw, args.reg, args.ip, args.port)
    client.run()
