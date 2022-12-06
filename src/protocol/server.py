import os
import socket
import time

import srp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from packet import Flags
import packet_manager


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
        with open("bobs.txt", "rb") as ff:
            bobs = ff.read()
        with open("bobv.txt", "rb") as ff:
            bobv = ff.read()
        with open("alices.txt", "rb") as ff:
            alices = ff.read()
        with open("alicev.txt", "rb") as ff:
            alicev = ff.read()
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
            self.pm.run()
            # registration for new users
            # for user in self.pm.get_reg_requests():
            #     if user[1][0] not in self.users:
            #         self.users[user[1][0]] = {"public_key": user[1][0], "g_w": user[1][1]}

            # already existing users
            for user in self.pm.get_login_requests():
                if user[0] in self.users:
                    passwd = self.users[user[0]]['passwd']
                    svr = srp.Verifier(user[0], passwd[0], passwd[1], user[1])
                    ss, BB = svr.get_challenge()
                    self.pm.set_srp_verifier(user[0], svr)
                    self.pm.queue((ss, BB), Flags.LOGIN, user[0])
                    self.users[user[0]]['pub_key'] = self.pm.get_pub(user[0])

            print(f"msgs: {self.pm.get_msgs()}")
            time.sleep(0.01)

            # for user in self.pm.get_logoff_requests():
            #     if not False in self.users[user[0]]:
            #         self.users[user].update({"online": False, "session_key": None})

            # for user in self.pm.get_list_requests():
            #     self.pm.queue(data=list(self.users.keys), flag=None, uid=user[0])

            # for user in self.pm.get_connection_requests():
            #     cid = self.generate_cid()
            #     str = os.urandom(16)
            #     self.pm.queue(data=str, flag=None, uid=user[0])
            #     self.pm.queue(data=str, flag=None, uid=user[1])
            #     self.connections[cid] = {cid, (user[0], user[1])}


if __name__ == "__main__":
    with open("serve_priv.txt", "rb") as ff:
        rsa_priv = serialization.load_pem_private_key(ff.read(), password=None,)

    server = Server(rsa_priv)
    server.run()
