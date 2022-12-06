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
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat

from packet import Packet
from packet import PackEncrypted
from packet import Flags
from protocol import packet


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
    cid: int
    addr: tuple[str, int]
    shared_key: bytes | srp.User
    pub_key: RSAPublicKey
    packs: PackInfo | None
    msgs: list
    nonces: list[bytes]
    handshook: bool
    initiator: bool


class PacketManager:
    def __init__(self, uid: str, sock: socket.socket, port: int, rsa_key: RSAPrivateKey):
        self.sessions: list[SeshInfo] = []
        self.ss = sock
        self.port = port
        self.rsa_key = rsa_key
        self.uid = uid

    def new_cc_sesh(self, uid: str, cid: int, addr: tuple[str, int], pub_key: RSAPublicKey, initiator: bool):
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
                        packs=packs, msgs=[], nonces=[], handshook=False, initiator=initiator)
        self.sessions.append(sesh)

        if initiator:
            data = (self.uid, priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
            self.queue(data=cPickle.dumps(data),
                       flag=Flags.HELLO,
                       uid=uid)

    def new_cs_sesh(self, cid: int, addr: tuple[str, int], usrp: srp.User, pub_key: RSAPublicKey):
        """
        Creates a new client-server session over SRP with the handshake being conducted
        with hybrid encryption with RSA and AES.

        :param cid: Connection ID for session
        :param addr: Tuple of ip/port to connect to
        :param usrp: User's SRP identifier
        :param pub_key: Server's public RSA key
        :return:
        """
        packs = PackInfo(sent=[], recvd=[], unsent=[], time_recvd=0.0, pnum=0)
        sesh = SeshInfo(uid="server", cid=cid, addr=addr, shared_key=usrp, pub_key=pub_key,
                        packs=packs, msgs=[], nonces=[], handshook=False, initiator=True)
        self.sessions.append(sesh)
        uname, C = usrp.start_authentication()
        data = (uname, C)
        self.queue(data=cPickle.dumps(data),
                   flag=Flags.LOGIN,
                   uid="server")

    def queue(self, data, flag: packet.Flags | None, uid: str):
        """
        Queues a message to be sent to the given uid with the given data and flags

        :param data: Data to be sent
        :param flag: Flag to be used or None
        :param uid: UID of recipient
        :return:
        """
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
                pack = Packet(src=self.port, dest=sesh.addr[1], cid=sesh.cid, nonce=nonce, encrypted=pickled)

                sesh.packs.unsent.append((contents.pnum, pack))
                break

    def send(self, cid: int, pack: Packet):
        """
        Sends packet over the session associated with the given CID

        :param cid: Connection ID of session to send packet over
        :param pack: Packet to be sent
        :return:
        """
        frames = {'acks_recvd': [], 'acks_lost': [], 'ack_delay': 0.0}
        contents: PackEncrypted = cPickle.loads(pack.encrypted)
        for sesh in self.sessions:
            if sesh.cid == cid:
                if sesh.packs.time_recvd != 0:
                    frames['ack_delay'] = time.time() - sesh.packs.time_recvd
                if not sesh.packs.recvd:
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
                sesh.packs.unsent.remove((contents.pnum, pack))
                sesh.packs.pnum += 1
                # print(f"{self.uid} + {sesh.packs.unsent}")

    def recv(self):
        """
        Listens for messages on the client's socket and handles them accordingly.

        :return:
        """
        msgs = select.select([self.ss], [], [], 0.1)[0]
        for conn in msgs:
            data, addr = conn.recvfrom(1500)
            pack: Packet = cPickle.loads(data)
            for sesh in self.sessions:
                # print(pack)
                if pack.cid == sesh.cid:
                    try:
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
                            contents: tuple[bytes, bytes] = cPickle.loads(pack.encrypted)
                            self.complete_handshake(pack, contents, sesh.initiator)
                            return
                    except Exception:
                        print("Unable to decrypt")
                        break

                    if contents.pnum in dict(sesh.packs.recvd):
                        for ii in range(0, len(sesh.packs.recvd)):
                            if sesh.packs.recvd[ii][0] == contents.pnum:
                                sesh.packs.recvd[ii] = (contents.pnum, False)
                    else:
                        sesh.packs.recvd.append((contents.pnum, False))

                    # print(contents)
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
                        self.elicit(sesh.cid)
                    if Flags.BYE in contents.flags:
                        self.sessions.remove(sesh)
                        break

                    sesh.msgs.append((contents.pnum, contents.data))
                    break

    def elicit(self, cid: int):
        # TODO
        pass

    def complete_handshake(self, pack: Packet, encrypted: tuple[bytes, bytes], initiator: bool):
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
        keys: tuple[str, bytes] = cPickle.loads(contents.data)

        for sesh in self.sessions:
            if pack.cid == sesh.cid:
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
                    # print(f"Message: Hello {keys[0]}, I'm {self.uid}.")
                    self.queue(f"Hello {keys[0]}, I'm {self.uid}.", flag=None, uid=sesh.uid)
                else:
                    pub: ec.EllipticCurvePublicKey = serialization.load_der_public_key(keys[1], None)
                    priv = ec.generate_private_key(ec.SECP384R1())
                    shared_key = priv.exchange(ec.ECDH(), pub)
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake',
                    ).derive(shared_key)

                    packs = PackInfo(sent=[], recvd=[(contents.pnum, False)], unsent=[],
                                     time_recvd=time.time(), pnum=contents.pnum)
                    sesh.handshook = True
                    sesh.shared_key = derived_key
                    sesh.packs = packs
                    data = (self.uid,
                            priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
                            self.rsa_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
                    self.queue(data=cPickle.dumps(data), flag=Flags.HELLO, uid=keys[0])

    def organize(self):
        # TODO
        pass
