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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

import packet_manager
from protocol.packet import Flags
from protocol.packet_manager import SeshInfo


class Client:
    def __init__(self, name: str, password: str, reg: bool, ip: str, port: int):
        self.reg = reg
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ss.bind((ip, port))  # localhost for testing
        self.name = name
        self.pw = password
        self.socket = socket
        self.port = port
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
        self.server_pub: RSAPublicKey
        with open("serve_pub.txt", "rb") as ff:
            self.server_pub = serialization.load_pem_public_key(ff.read())

        self.pm = packet_manager.PacketManager(uid=self.name, sock=self.ss, port=self.port, rsa_key=self.rsa_priv)
        # thread1 = threading.Thread(target=self.run)
        # thread2 = threading.Thread(target=self.usr_in)
        # thread1.start()
        # thread2.start()
        # self.run()
        self.usr_in()
    
    def run(self):
        usr = srp.User(self.name, self.pw)
        rand = random.SystemRandom()
        self.pm.new_cs_sesh(rand.randint(10000000, 99999999), addr=("localhost", 1337),
                            usrp=usr, pub_key=self.server_pub)
        while True:
            self.pm.run()
            if self.pm.get_msgs():
                print(f"msgs: {self.pm.get_msgs()}")
                if self.pm.get_msgs("server"):
                    response = self.pm.get_msgs("server")
                    cid = None
                    rand_str = None
                    conn_addr = None
                    conn_key = None
                    initiated = None
                    for packet in response:
                        if "connection initialized:" in packet[1]:
                            user = packet[1][1]
                            cid = packet[1][2]
                            rand_str = packet[1][3]
                            conn_addr = packet[1][4]
                            conn_key = packet[1][5]
                            initiated = True
                        if "connection requested:" in packet[1]:
                            user = packet[1][1]
                            cid = packet[1][2]
                            rand_str = packet[1][3]
                            conn_addr = packet[1][4]
                            conn_key = packet[1][5]
                            initiated = False
                    if cid and rand_str and conn_addr and conn_key:
                        self.pm.new_cc_sesh(self.name, cid, conn_addr, conn_key, initiated)
                        if initiated:
                            self.pm.queue(hashlib.sha256(rand_str), Flags.CR, user)
                            if not self.pm.get_cr_msg(user) == hashlib.sha256(rand_str + 'a'):
                                print("Session hash is not the same, your connection is not secure! Killing session.")
                                self.pm.kill(user)
                        else:
                            self.pm.get_msgs(user)
                            if not self.pm.get_cr_msg(user) == hashlib.sha256(rand_str):
                                print("Session hash is not the same, your connection is not secure! Killing session.")
                                self.pm.kill(user)
                            self.pm.queue(hashlib.sha256(rand_str + 'a'))


            sys.stdout.flush()
            time.sleep(0.01)

    def usr_in(self):
        # TEST
        usr = srp.User(self.name, self.pw)
        rand = random.SystemRandom()
        self.pm.new_cs_sesh(rand.randint(10000000, 99999999), addr=("localhost", 1337),
                            usrp=usr, pub_key=self.server_pub)
         # TEST   
        usr_in = input("> ")
        self.command(usr_in.split())

    def command(self, usr_in: str):
        print(usr_in)
        match usr_in:
            case ["connect", user]:
                self.pm.queue("connect " + user, None, "server")
                
                #else:
                #    self.command(["connect", user])

                # This needs to ask the server first to get the addr, rsa, and cid
                # self.pm.new_cc_sesh(self.name)  # have packet manager set up
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
    parser.add_argument("-usr", type=str, required=True)
    parser.add_argument("-pw", type=str, required=True)
    parser.add_argument("-ip", type=str, required=True)
    parser.add_argument("-port", type=int, required=True)
    parser.add_argument("-reg", type=str, required=False)

    args = parser.parse_args()
    client = Client(args.usr, args.pw, args.reg, args.ip, args.port)
    client.run()
