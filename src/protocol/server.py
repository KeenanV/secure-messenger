import socket
import string
import random
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
        self.key = rsa_key
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind()

        self.pm = packet_manager.PacketManager(uid="server", sock=self.socket, port=1111, rsa_key=self.key)

    def generate_cid(self):
        cid = ''.join(random.choice(string.ascii_letters) for i in range(15))
        if not self.connections.has_key(cid):
            return cid
        else:
            self.generate_cid()
        

    def run(self): 
        while True:   
            self.pm.recv()

            # registration for new users
            for user in self.pm.get_unknown_messages():
                if not self.users.has_key(user[1][0]):
                    self.users[user[1][0]] = {"shared_key": user[1][1]}
                    # need to get address from somewhere
                    self.pm.new_sesh(uid=user[1][0], cid=user[0], addr=[str, int], pub_key=self.key)

            # already existing users
            for user in self.users:
                # login
                if user.has_login_request():
                    self.users[user].update({"online": True, "session_key": user.get_session_key()})
                # logoff
                if user.has_logoff_request():
                    self.users[user].update({"online": False, "session_key": None})
                # list
                if user.has_list_request():
                    self.pm.queue(data=list(self.users.keys), uid=user)

                # connection between two users
                if user.has_conn_request():
                    cid = self.generate_cid()
                    str = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(15))
                    self.pm.queue(data=str, uid=user)
                    self.pm.queue(data=str, uid=user2)
                    self.connections[cid] = {cid, (user, user2)}



    

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

