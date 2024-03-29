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


class Server:
    def __init__(self, rsa_key: RSAPrivateKey):
        self.users = {}
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
            # registration for new users
            for user in self.pm.get_reg_requests():
                if user[1][0] not in self.users:
                    self.users[user[1][0]] = {"public_key": user[1][0], "g_w": user[1][1]}

            # already existing users
            for user in self.pm.get_login_requests():

                self.pm.complete_handshake(user[1][0], user[1][1])
                # if not True in self.users[user[0]]:

                #      self.users[user].update({"online": True, "session_key": user[1][0]})
                # else:
                #     pass # preventing multiple sessions?

            for user in self.pm.get_logoff_requests():
                if not False in self.users[user[0]]:
                    self.users[user].update({"online": False, "session_key": None})

            for user in self.pm.get_list_requests():
                self.pm.queue(data=list(self.users.keys), flag=None, uid=user[0])

            for user in self.pm.get_connection_requests():
                cid = self.generate_cid()
                str = os.urandom(16)
                self.pm.queue(data=str, flag=None, uid=user[0])
                self.pm.queue(data=str, flag=None, uid=user[1])
                self.connections[cid] = {cid, (user[0], user[1])}

    

# use a message to a queue when it's going to send

# two users connecting, server needs to create and store connection id
# store shared secret between two users

# upon registration message would be tuple username, key
# get_messages -> requires uid
# get_unknown_messages -> any without id
# would return list of tuples, each tuple would be (connection_id, list of messages(message contains (username, shared key)))
# needs username and shared key, pull from get_unknown_messages 
# assume index[0] in messages

# provide said information about connections
# list function

# if server's spamming registration, drop
        
# dictionary 1: {username, {pass, online, session_key, public_key}}
# dictionary 2: {conn_id, (user1, user2)}

# registration
# ECDH to establish session key, encrypted with server's public key

# login
# SRP with asymmetric encryption to establish sesison key
# server will be receiving connection 

