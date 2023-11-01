import hashlib
import os
import random
from secret import flag
from Crypto.Util.number import *

def myhash(m):
    blocks = [m[i*16:i*16+16] for i in range(8)]
    temp = 0
    for i in range(8):
        temp += ((i%4)*bytes_to_long(blocks[i]))
    return hashlib.sha256(long_to_bytes(temp)).hexdigest()

def task1():
    m = os.urandom(128)
    print("m =",bytes_to_long(m))
    fake_m = long_to_bytes(int(input("give me a valid value:")))
    if(fake_m == m):
        print("Hacker!")
        exit()
    if(myhash(fake_m) == myhash(m)):
        return
    else:
        print("Try again!")
        exit()

def task2():
    table = "0123456789abcdef"
    prefix = "".join([random.choice(table) for i in range(6)])
    print(prefix)
    m = input("give me a valid message:")
    fake_prefix = str(hashlib.md5(m.encode()).hexdigest())[:6]
    if(fake_prefix == prefix):
        print("Congratulations!The flag is :",flag)
    else:
        print("Try again!")

task1()
task2()