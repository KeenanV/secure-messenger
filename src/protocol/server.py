import os
import socket
import time
import _pickle as cPickle

import srp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

import packet_manager
from packet import Flags


class Server:
    def __init__(self, rsa_key: RSAPrivateKey):
        self.users = {"Bob": {"pub_key": None,
                              "passwd": ...,
                              "addr": ("localhost", 1340),
                              "online": False},
                      "Alice": {"pub_key": None,
                                "passwd": ...,
                                "addr": ("localhost", 1350),
                                "online": False}}
        with open("bobs.txt", "rb") as fp:
            bobs = fp.read()
        with open("bobv.txt", "rb") as fp:
            bobv = fp.read()
        with open("alices.txt", "rb") as fp:
            alices = fp.read()
        with open("alicev.txt", "rb") as fp:
            alicev = fp.read()
        self.users['Bob']['passwd'] = (bobs, bobv)
        self.users['Alice']['passwd'] = (alices, alicev)

        self.connections = {}
        self.rsa_key = rsa_key
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('localhost', 1337))

        self.pm = packet_manager.PacketManager(uid="server", sock=self.socket, port=1337, rsa_key=self.rsa_key)

    def generate_cid(self):
        cid = os.urandom(16)
        if cid not in self.connections:
            return cid
        else:
            return self.generate_cid()

    def run(self): 
        while True:
            reg = self.pm.run()
            if reg is not None:
                uname = reg[1][0]
                salt = reg[1][1]
                vkey = reg[1][2]
                cid = reg[2]
                addr = reg[0]
                if uname not in self.users:
                    self.users[uname] = {"pub_key": None, "passwd": (salt, vkey), "addr": addr, "online": False}
                    self.pm.queue("ok", Flags.REG, uname, addr, cid)
                    print("USER ADDED")
                else:
                    self.pm.queue("bad user", Flags.REG, "", addr, cid)
                    print("USER FAILED")

            # already existing users
            logins = self.pm.get_login_requests()
            for user in logins:
                if user[0] in self.users:
                    passwd = self.users[user[0]]['passwd']
                    svr = srp.Verifier(user[0], passwd[0], passwd[1], user[1])
                    ss, BB = svr.get_challenge()
                    self.pm.set_srp_verifier(user[0], svr)
                    self.pm.queue((ss, BB), Flags.LOGIN, user[0])
                    self.users[user[0]]['pub_key'] = self.pm.get_pub(user[0])

            # for user in self.pm.get_logoff_requests():
            #     if not False in self.users[user[0]]:
            #         self.users[user].update({"online": False, "session_key": None})

            # for user in self.pm.get_list_requests():
            #     self.pm.queue(data=("list", list(self.users.keys)), flag=None, uid=user[0])

            for user in self.pm.get_connection_requests():
                print(f"REQUEST: {user}")
                cid = self.generate_cid()
                rand_str = os.urandom(16)
                self.pm.queue(data=("connection requested:", user[0], cid, rand_str,
                                    self.users[user[0]]["addr"],
                                    self.users[user[0]]["pub_key"]),
                              flag=None,
                              uid=user[1])
                self.connections[cid] = (user[0], user[1], rand_str, cid)

            for kk, conn in self.connections.items():
                # print(f"checking: {conn}")
                for msg in self.pm.get_msgs(conn[1]):
                    print(f"MSG: {msg}")
                    if msg == "ok":
                        print("PART TWO")
                        self.pm.queue(data=("connection initialized:", conn[1], conn[3], conn[2],
                                            self.users[conn[1]]["addr"],
                                            self.users[conn[1]]["pub_key"]),
                                      flag=None,
                                      uid=conn[0])

            for msg in self.pm.get_msgs():
                if msg[1] == "list":
                    data = ("list", "User: " + "\nUser: ".join(self.users.keys()))
                    self.pm.queue(data=data, flag=None, uid=msg[0])

            time.sleep(0.01)


if __name__ == "__main__":
    with open("serve_priv.pem", "rb") as ff:
        rsa_priv = serialization.load_pem_private_key(ff.read(), password=None,)

    server = Server(rsa_priv)
    server.run()
