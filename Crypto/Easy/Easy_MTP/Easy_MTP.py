from secret import flag
from Crypto.Util.number import *
from random import *

length = len(bin(bytes_to_long(flag))[2:])
assert(length == 343)

p = getPrime(256)
def genbit():
    return str(randint(0,p)*randint(0,p) & 1)

def genkey():
    s = ""
    for i in range(length):
        s += genbit()
    return int(s,2)

m = bytes_to_long(flag)
with open("cipher.txt","w") as f:
    for i in range(100):
        f.write(str(m^genkey()))
        f.write("\n")