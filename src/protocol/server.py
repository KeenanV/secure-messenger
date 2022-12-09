import os
import socket
import time

import srp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

import packet_manager
from packet import Flags


class Server:
    def __init__(self, rsa_key: RSAPrivateKey):
        self.users = {}

        with open("users.txt", "r") as fp:
            unames = fp.readlines()

        for usr in unames:
            with open(usr[:len(usr)-1] + "s.txt", "rb") as fp:
                salt = fp.read()
            with open(usr[:len(usr)-1] + "v.txt", "rb") as fp:
                vkey = fp.read()
            self.users[usr[:len(usr)-1]] = {"pub_key": None,
                                            "passwd": (salt, vkey),
                                            "addr": None,
                                            "online": False}
        self.connections = {}
        self.rsa_key = rsa_key
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('localhost', 1337))

        self.pm = packet_manager.PacketManager(uid="server", sock=self.socket, port=1337, rsa_key=self.rsa_key)

    def run(self): 
        while True:
            reg = self.pm.run()
            if reg is not None:
                uname = reg[1][0]
                salt = reg[1][1]
                vkey = reg[1][2]
                pub_key = reg[1][3]
                cid = reg[2]
                addr = reg[0]
                if uname not in self.users and uname != "server":
                    self.users[uname] = {"pub_key": None, "passwd": (salt, vkey), "addr": addr, "online": False}
                    with open(uname + "s.txt", "wb") as fp:
                        fp.write(salt)
                    with open(uname + "v.txt", "wb") as fp:
                        fp.write(vkey)
                    with open("users.txt", "a") as fp:
                        fp.write(uname + "\n")
                    self.pm.queue(("ok", pub_key), Flags.REG, uname, addr, cid)
                    print("USER ADDED")
                else:
                    self.pm.queue(("bad user", pub_key), Flags.REG, "", addr, cid)
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
                    self.users[user[0]]['online'] = True
                    self.users[user[0]]['addr'] = user[2]

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
                for msg in self.pm.get_msgs(conn[1]):
                    if msg == "ok":
                        self.pm.queue(data=("connection initialized:", conn[1], conn[3], conn[2],
                                            self.users[conn[1]]["addr"],
                                            self.users[conn[1]]["pub_key"]),
                                      flag=None,
                                      uid=conn[0])

            for msg in self.pm.get_msgs():
                if msg[1] == "list":
                    self.pm.queue(data=self.sort_online(), flag=None, uid=msg[0])
                elif msg[1] == "logout":
                    self.users[msg[0]]['online'] = False

            time.sleep(0.01)

    def generate_cid(self):
        cid = os.urandom(16)
        if cid not in self.connections:
            return cid
        else:
            return self.generate_cid()

    def sort_online(self):
        online = []
        for user in self.users:
            if self.users[user]['online']:
                online.append(user)
        data = ("list", "User: " + "\nUser: ".join(online))
        return data


if __name__ == "__main__":
    with open("serve_priv.pem", "rb") as ff:
        rsa_priv = serialization.load_pem_private_key(ff.read(), password=None,)

    server = Server(rsa_priv)
    server.run()
