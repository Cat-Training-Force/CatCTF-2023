import socketserver
from Crypto.Util.number import *
from random import getrandbits
from Crypto.Cipher import AES
from sympy import nextprime
import binascii
from secret import flag

menu=b'''1. gethint
2. getflag
'''

def enc(data,key,iv):
    cipher = AES.new(key,AES.MODE_CBC,iv)
    encrypt = cipher.encrypt(data)
    return encrypt

def dec(data,key,iv):
    cipher = AES.new(key,AES.MODE_CBC,iv)
    encrypt = cipher.decrypt(data)
    return encrypt


class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        if newline:
            msg += b'\n'
        self.request.sendall(msg)

    def recv(self, prompt):
        self.send(prompt,False)
        return self._recvall()

    def task(self):
        for i in range(40):
            choice = self.recv(menu)
            if(choice == b"1"):
                temp = getrandbits(16*8)
                key = (temp<<128)+temp
                iv = getrandbits(16*8)
                m = getrandbits(32*8)
                self.send(b"gift =",False)
                self.send(str(key^iv).encode())
                c = enc(long_to_bytes(m),long_to_bytes(key),long_to_bytes(iv))
                self.send(b"c =",False)
                self.send(str(bytes_to_long(c)).encode())
                self.send(b'\n',False)
            elif(choice == b"2"):
                plist = [nextprime(getrandbits(512)) for i in range(3)]
                n = 1
                for i in range(3):
                    n *= plist[i]
                m = bytes_to_long(flag)
                e = 65537
                c = pow(m,e,n)
                self.send(b"n =",False)
                self.send(str(n).encode())
                self.send(b"c =",False)
                self.send(str(c).encode())
                exit()
            else:
                self.send(b"What are u doing?")
                exit()


    def handle(self):
        self.task()


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 80
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    print(HOST, PORT)
    server.serve_forever()
