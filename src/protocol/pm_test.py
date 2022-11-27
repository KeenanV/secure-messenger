import socket
import threading

from cryptography.hazmat.primitives.asymmetric import rsa
import packet_manager


class PMTest:
    def __init__(self):
        self.ss1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ss1.bind(("localhost", 1337))
        self.rsa1 = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
        self.u1 = packet_manager.PacketManager(uid="Alice",
                                               sock=self.ss1,
                                               port=1337,
                                               rsa_key=self.rsa1)
        self.ss2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ss2.bind(("localhost", 1340))
        self.rsa2 = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
        self.u2 = packet_manager.PacketManager(uid="Bob",
                                               sock=self.ss2,
                                               port=1340,
                                               rsa_key=self.rsa2)
        self.msg = "Hello"
        thread1 = threading.Thread(target=self.run)
        thread2 = threading.Thread(target=self.usr_in)
        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()

    def run(self):
        self.u1.new_sesh("Bob", 3345, ("localhost", 1340), self.rsa2.public_key())
        if self.u1.sessions[0].packs.unsent:
            self.u1.send(self.u1.sessions[0].cid, self.u1.sessions[0].packs.unsent[0][1])
        while self.msg != "exit":
            self.u2.recv()
            self.u1.recv()
            if self.u1.sessions[0].msgs:
                for msg in self.u1.sessions[0].msgs:
                    print(f"u1 msg: {msg}")
                self.u1.sessions[0].msgs.clear()
            if self.u2.sessions and self.u2.sessions[0].msgs:
                for msg in self.u2.sessions[0].msgs:
                    print(f"u2 msg: {msg}")
                self.u2.sessions[0].msgs.clear()
            if self.u1.sessions and self.u1.sessions[0].packs.unsent:
                self.u1.send(self.u1.sessions[0].cid, self.u1.sessions[0].packs.unsent[0][1])
            if self.u2.sessions and self.u2.sessions[0].packs.unsent:
                self.u2.send(self.u2.sessions[0].cid, self.u2.sessions[0].packs.unsent[0][1])
            if self.msg != "":
                self.u1.queue(self.msg, None, self.u2.uid)
                self.msg = ""

    def usr_in(self):
        while self.msg != "exit":
            msg = input("Input: ")
            self.msg = msg


if __name__ == "__main__":
    test = PMTest()
    test.run()
