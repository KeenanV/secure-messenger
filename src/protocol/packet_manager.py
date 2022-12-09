import os
import random
import select
import socket
import srp
import time
import _pickle as cPickle
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat

from packet import Packet
from packet import PackEncrypted
from packet import Flags


@dataclass
class PackInfo:
    sent: list[tuple[int, Packet, float]]
    recvd: list[tuple[int, bool]]
    unsent: list[tuple[int, Packet]]
    time_recvd: float
    pnum: int


@dataclass
class SeshInfo:
    uid: str
    cid: bytes
    addr: tuple[str, int]
    shared_key: bytes | srp.User | srp.Verifier | None
    pub_key: RSAPublicKey
    packs: PackInfo | None
    msgs: list
    nonces: list[bytes]
    handshook: bool
    initiator: bool
    cr_ready: bool


class PacketManager:
    def __init__(self, uid: str, sock: socket.socket, port: int, rsa_key: RSAPrivateKey):
        self.sessions: list[SeshInfo] = []
        self.ss = sock
        self.port = port
        self.ip = "localhost"
        self.rsa_key = rsa_key
        self.uid = uid

    def run(self):
        reg = self.__recv()

        for sesh in self.sessions:
            for msg in sesh.packs.unsent:
                self.__send(msg[1].cid, msg[1])
                time.sleep(0.001)
            sesh.packs.unsent.clear()
        return reg

    def new_cc_sesh(self, uid: str, cid: bytes, addr: tuple[str, int], pub_key: RSAPublicKey, initiator: bool):
        """
        Creates a new client-client session over ECDH with the handshake being conducted
        with hybrid encryption with RSA and AES.

        :param uid: UID of user to connect to
        :param cid: Connection ID for session
        :param addr: Tuple of ip/port to connect to
        :param pub_key: Public RSA key of other user
        :param initiator: True if session initiated by this user
        :return:
        """
        priv = ec.generate_private_key(ec.SECP384R1())
        pb = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, serialization.NoEncryption())
        packs = PackInfo(sent=[], recvd=[], unsent=[], time_recvd=0.0, pnum=0)
        sesh = SeshInfo(uid=uid, cid=cid, addr=addr, shared_key=pb, pub_key=pub_key,
                        packs=packs, msgs=[], nonces=[], handshook=False, initiator=initiator, cr_ready=False)
        self.sessions.append(sesh)

        if initiator:
            data = (self.uid, priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
            self.queue(data=data,
                       flag=Flags.HELLO,
                       uid=uid)

    def new_cs_sesh(self, cid: bytes, addr: tuple[str, int], usrp: srp.User | None, pub_key: RSAPublicKey, reg=False):
        """
        Creates a new client-server session over SRP with the handshake being conducted
        with hybrid encryption with RSA and AES.

        :param cid: Connection ID for session
        :param addr: Tuple of ip/port to connect to
        :param usrp: User's SRP identifier
        :param pub_key: Server's public RSA key
        :param reg: True if this is a registration session
        :return:
        """
        packs = PackInfo(sent=[], recvd=[], unsent=[], time_recvd=0.0, pnum=0)
        sesh = SeshInfo(uid="server", cid=cid, addr=addr, shared_key=usrp, pub_key=pub_key,
                        packs=packs, msgs=[], nonces=[], handshook=False, initiator=True, cr_ready=False)
        if reg:
            sesh.shared_key = None
            self.sessions.append(sesh)
        else:
            self.sessions.append(sesh)
            uname, C = usrp.start_authentication()
            data = (uname, C, self.rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))
            self.queue(data=data,
                       flag=Flags.LOGIN,
                       uid="server")

    def queue(self, data, flag: Flags | None, uid: str, addr=None, cid=None):
        """
        Queues a message to be sent to the given uid with the given data and flags

        :param data: Data to be sent
        :param flag: Flag to be used or None
        :param uid: UID of recipient
        :param addr:
        :param cid:
        :return:
        """
        if self.uid == "server" and isinstance(data, tuple) and (data[0] == "bad user" or data[0] == "ok"):
            rand = random.SystemRandom()
            contents = PackEncrypted(pnum=rand.randint(1000, 9999), flags=[flag], frames={}, data=data[0])
            pickled = cPickle.dumps(contents)
            nonce = os.urandom(12)
            pack = Packet(src=(self.ip, self.port), dest=addr, cid=cid, nonce=nonce, encrypted=pickled)
            self.__send(cid, pack, serialization.load_pem_public_key(data[1], ))
        for sesh in self.sessions:
            if sesh.uid == uid:
                rand = random.SystemRandom()
                contents = PackEncrypted(pnum=0, flags=[flag], frames={}, data=data)
                if sesh.packs.pnum == 0:
                    contents.pnum = rand.randint(1000, 9999)
                    sesh.packs.pnum = contents.pnum
                else:
                    contents.pnum = sesh.packs.pnum

                pickled = cPickle.dumps(contents)
                nonce = os.urandom(12)
                pack = Packet(src=(self.ip, self.port), dest=sesh.addr, cid=sesh.cid, nonce=nonce, encrypted=pickled)

                sesh.packs.unsent.append((contents.pnum, pack))
                break

    def __send(self, cid: bytes, pack: Packet, pub_key=None):
        """
        Sends packet over the session associated with the given CID

        :param cid: Connection ID of session to send packet over
        :param pack: Packet to be sent
        :return:
        """
        frames = {'acks_recvd': [], 'acks_lost': [], 'ack_delay': 0.0}
        contents: PackEncrypted = cPickle.loads(pack.encrypted)
        if self.uid == "server" and Flags.REG in contents.flags:
            contents.frames = frames
            temp_key = AESGCM.generate_key(128)
            aesgcm = AESGCM(temp_key)
            ct = aesgcm.encrypt(pack.nonce, cPickle.dumps(contents), None)
            ct_nonce = pub_key.encrypt(pack.nonce, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                algorithm=hashes.SHA256(),
                                                                label=None))
            encrypted_key = pub_key.encrypt(temp_key,
                                            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                         algorithm=hashes.SHA256(),
                                                         label=None))
            encrypted = cPickle.dumps((encrypted_key, ct))
            pack.nonce = ct_nonce
            pack.encrypted = encrypted
            self.ss.sendto(cPickle.dumps(pack), pack.dest)

        for sesh in self.sessions:
            if sesh.cid == cid:
                if sesh.packs.time_recvd != 0:
                    frames['ack_delay'] = time.time() - sesh.packs.time_recvd
                if sesh.packs.recvd:
                    recvd = []
                    lost = []
                    for rp in sesh.packs.recvd:
                        if rp[1]:
                            lost.append(rp[0])
                        else:
                            recvd.append(rp[0])
                    frames['acks_recvd'] = recvd
                    frames['acks_lost'] = lost

                contents.frames = frames
                ct_nonce = sesh.pub_key.encrypt(pack.nonce, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                         algorithm=hashes.SHA256(),
                                                                         label=None))
                if Flags.HELLO in contents.flags or Flags.LOGIN in contents.flags or Flags.REG in contents.flags:
                    if Flags.CR in contents.flags:
                        sesh.cr_ready = False
                    temp_key = AESGCM.generate_key(128)
                    aesgcm = AESGCM(temp_key)
                    ct = aesgcm.encrypt(pack.nonce, cPickle.dumps(contents), None)
                    encrypted_key = sesh.pub_key.encrypt(temp_key,
                                                         padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                      algorithm=hashes.SHA256(),
                                                                      label=None))
                    encrypted = cPickle.dumps((encrypted_key, ct))
                else:
                    aesgcm = AESGCM(sesh.shared_key)
                    encrypted = aesgcm.encrypt(pack.nonce, cPickle.dumps(contents), None)

                pack.nonce = ct_nonce
                pack.encrypted = encrypted
                # print(f"sending: {contents}")
                self.ss.sendto(cPickle.dumps(pack), sesh.addr)
                sesh.packs.sent.append((contents.pnum, pack, time.time()))
                # sesh.packs.unsent.remove((contents.pnum, pack))
                sesh.packs.pnum += 1
                # print(f"{self.uid} + {sesh.packs.unsent}")

    def __recv(self):
        """
        Listens for messages on the client's socket and handles them accordingly.

        :return:
        """
        msgs = select.select([self.ss], [], [], 0.1)[0]
        for conn in msgs:
            data, addr = conn.recvfrom(4096)
            pack: Packet = cPickle.loads(data)
            exists = False
            for sesh in self.sessions:
                if pack.cid == sesh.cid:
                    exists = True
                    if sesh.handshook:
                        nonce = self.rsa_key.decrypt(pack.nonce,
                                                     padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(),
                                                                  label=None))
                        if nonce in sesh.nonces:
                            break
                        aesgcm = AESGCM(sesh.shared_key)
                        contents: PackEncrypted = cPickle.loads(aesgcm.decrypt(nonce, pack.encrypted, None))
                        sesh.nonces.append(nonce)
                    else:
                        tup: tuple[bytes, bytes] = cPickle.loads(pack.encrypted)
                        contents = self.__complete_handshake(pack, tup, sesh.initiator)

                    if contents.pnum in dict(sesh.packs.recvd):
                        for ii in range(0, len(sesh.packs.recvd)):
                            if sesh.packs.recvd[ii][0] == contents.pnum:
                                sesh.packs.recvd[ii] = (contents.pnum, False)
                    else:
                        sesh.packs.recvd.append((contents.pnum, False))

                    if contents.frames['acks_recvd']:
                        for pnum in contents.frames['acks_recvd']:
                            for sent_pack in sesh.packs.sent:
                                if sent_pack[0] == pnum:
                                    sesh.packs.sent.remove(sent_pack)

                    if contents.frames['acks_lost']:
                        for pnum in contents.frames['acks_lost']:
                            for sent_pack in sesh.packs.sent:
                                if sent_pack[0] == pnum:
                                    sesh.packs.unsent.append((pnum, sent_pack[1]))
                                    sesh.packs.sent.remove(sent_pack)

                    if Flags.ELICIT in contents.flags:
                        self.__elicit(sesh.cid)
                    if Flags.BYE in contents.flags:
                        self.sessions.remove(sesh)
                        break
                    if Flags.CR in contents.flags:
                        sesh.msgs.append((Flags.CR, contents.data))
                    if Flags.REG in contents.flags:
                        sesh.msgs.append((Flags.REG, contents.data))

                    if contents.flags[0] is None:
                        sesh.msgs.append((contents.pnum, contents.data))
                    break

            if not exists:
                contents: tuple[bytes, bytes] = cPickle.loads(pack.encrypted)
                msg = self.__complete_handshake(pack, contents, False)
                if Flags.REG in msg.flags:
                    return addr, msg.data, pack.cid
        return None

    def __elicit(self, cid: bytes):
        # TODO
        pass

    def __complete_handshake(self, pack: Packet, encrypted: tuple[bytes, bytes], initiator: bool) -> PackEncrypted:
        """
        Manages and completes ECDH or SRP exchange and handshake

        :param pack: Received packet
        :param encrypted: Encrypted section of packet
        :param initiator: True if current user initiated the session
        :return:
        """
        nonce = self.rsa_key.decrypt(pack.nonce,
                                     padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                  algorithm=hashes.SHA256(),
                                                  label=None))
        temp_key = self.rsa_key.decrypt(encrypted[0],
                                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(),
                                                     label=None))
        aesgcm = AESGCM(temp_key)
        contents: PackEncrypted = cPickle.loads(aesgcm.decrypt(nonce, encrypted[1], None))
        keys = contents.data
        exists = False
        for sesh in self.sessions:
            if pack.cid == sesh.cid:
                exists = True
                if Flags.LOGIN in contents.flags:
                    if initiator:
                        if len(contents.frames['acks_recvd']) == 1:
                            M = sesh.shared_key.process_challenge(keys[0], keys[1])
                            if M is None:
                                self.sessions.remove(sesh)
                                return contents
                            self.queue(M, Flags.LOGIN, uid="server")
                        elif len(contents.frames['acks_recvd']) == 2:
                            sesh.shared_key.verify_session(keys)
                            if sesh.shared_key.authenticated():
                                sk = sesh.shared_key.get_session_key()
                                sesh.shared_key = HKDF(
                                    algorithm=hashes.SHA256(),
                                    length=32,
                                    salt=None,
                                    info=b'handshake',
                                ).derive(sk)
                                if sesh.shared_key is None:
                                    print("FAILED")
                                sesh.handshook = True
                                self.queue(str(os.urandom(12)), Flags.CR, uid="server")
                            else:
                                self.sessions.remove(sesh)
                                return contents
                    else:
                        if len(contents.frames['acks_recvd']) == 1:
                            svr: srp.Verifier = sesh.shared_key
                            HAMK = svr.verify_session(keys)
                            if HAMK is None:
                                self.sessions.remove(sesh)
                                return contents
                            if svr.authenticated():
                                sk = svr.get_session_key()
                                sesh.shared_key = HKDF(
                                    algorithm=hashes.SHA256(),
                                    length=32,
                                    salt=None,
                                    info=b'handshake',
                                ).derive(sk)
                                sesh.handshook = True
                                self.queue(HAMK, Flags.LOGIN, uid=sesh.uid)
                elif Flags.REG in contents.flags:
                    return contents
                else:
                    if initiator:
                        priv: ec.EllipticCurvePrivateKey = serialization.load_der_private_key(sesh.shared_key, None)
                        pub: ec.EllipticCurvePublicKey = serialization.load_der_public_key(keys[1], None)
                        shared_key = priv.exchange(ec.ECDH(), pub)
                        derived_key = HKDF(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=None,
                            info=b'handshake',
                        ).derive(shared_key)
                        sesh.shared_key = derived_key
                        sesh.handshook = True
                        sesh.cr_ready = True
                        self.queue(f"Hello {keys[0]}, I'm {self.uid}.", flag=None, uid=sesh.uid)
                    else:
                        packs, derived_key, pub = self.__incoming_conn(keys, contents.pnum)
                        sesh.handshook = True
                        sesh.shared_key = derived_key
                        sesh.packs = packs
                        data = (self.uid,
                                pub,
                                self.rsa_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
                        self.queue(data=data, flag=Flags.HELLO, uid=keys[0])

        if not exists:
            if Flags.LOGIN in contents.flags:
                packs = PackInfo(sent=[], recvd=[(contents.pnum, False)], unsent=[], time_recvd=time.time(), pnum=0)
                sesh = SeshInfo(uid=keys[0], cid=pack.cid, addr=pack.src, shared_key=b'',
                                pub_key=serialization.load_pem_public_key(keys[2], ), packs=packs,
                                msgs=[(Flags.LOGIN, keys[1])], nonces=[], handshook=False, initiator=False,
                                cr_ready=False)
                rand = random.SystemRandom()
                contents.pnum = rand.randint(1000, 9999)
                sesh.packs.pnum = contents.pnum
                self.sessions.append(sesh)
            if Flags.REG in contents.flags:
                return contents

        return contents

    def __incoming_conn(self, keys: tuple, pnum: int) -> tuple[PackInfo, bytes, bytes]:
        pub: ec.EllipticCurvePublicKey = serialization.load_der_public_key(keys[1], None)
        priv = ec.generate_private_key(ec.SECP384R1())
        shared_key = priv.exchange(ec.ECDH(), pub)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake',
        ).derive(shared_key)

        packs = PackInfo(sent=[], recvd=[(pnum, False)], unsent=[],
                         time_recvd=time.time(), pnum=pnum)

        return packs, derived_key, priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def __organize(self):
        # TODO
        pass

    def get_msgs(self, uid=None) -> list:
        """
        Returns a list of messages from a session or sessions.

        :param uid: The uid of the user whose messages are wanted. Can be None for
                    messages from all users
        :return: If uid is specified, a list of all messages from users is returned.
                 If uid is not specified, a list of tuples containing (<uid>, <data>)
                 is returned
        """
        msgs = []
        if uid is None:
            for sesh in self.sessions:
                for mm in sesh.msgs:
                    if isinstance(mm[0], int) and isinstance(mm[1], str):
                        msgs.append((sesh.uid, mm[1]))
                sesh.msgs.clear()
        else:
            for sesh in self.sessions:
                if sesh.uid == uid:
                    for mm in sesh.msgs:
                        msgs.append(mm[1])
                    sesh.msgs.clear()

        return msgs

    def get_login_requests(self) -> list:
        msgs = []
        for sesh in self.sessions:
            for msg in sesh.msgs:
                if isinstance(msg, tuple):
                    if msg[0] == Flags.LOGIN:
                        msgs.append((sesh.uid, msg[1], sesh.addr))
        return msgs

    def get_connection_requests(self):
        msgs = []
        for sesh in self.sessions:
            for msg in sesh.msgs:
                if isinstance(msg[1], tuple):
                    if "connect" == msg[1][0]:
                        msgs.append((sesh.uid, msg[1][1]))
        return msgs

    def get_cr_msg(self, uid: str):
        for sesh in self.sessions:
            if uid == sesh.uid:
                for msg in sesh.msgs:
                    if msg[0] == Flags.CR:
                        sesh.msgs.remove(msg)
                        return msg[1]
        return None

    def get_reg_msg(self):
        for sesh in self.sessions:
            if sesh.uid == "server":
                for msg in sesh.msgs:
                    if msg[0] == Flags.REG:
                        return msg[1]
        return ""

    def get_pub(self, uid: str) -> bytes | None:
        for sesh in self.sessions:
            if uid == sesh.uid:
                return sesh.pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return None

    def get_cr_ready(self, uid: str) -> bool:
        for sesh in self.sessions:
            if uid == sesh.uid:
                return sesh.cr_ready
        return False

    def set_cr_ready(self, uid: str, ready: bool):
        for sesh in self.sessions:
            if uid == sesh.uid:
                sesh.cr_ready = ready

    def hash_session(self, uid: str) -> bool:
        for sesh in self.sessions:
            if uid == sesh.uid:
                return True
        return False

    def kill(self, uid: str):
        for sesh in self.sessions:
            if uid == sesh.uid:
                self.sessions.remove(sesh)
                return

    def set_srp_verifier(self, uid: str, svr: srp.Verifier):
        for sesh in self.sessions:
            if sesh.uid == uid:
                sesh.shared_key = svr
                return
