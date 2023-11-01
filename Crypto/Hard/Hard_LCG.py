from Crypto.Util.number import *
from gmpy2 import *
from secret import flag

def pad(data):
    if(len(data) % 8):
        data += b"\x00"*(8-len(data) % 8)
        return data

def LCG(a,m,b,n):
    m = (a*m + b) % n
    return m

m = pad(flag)*2
a = bytes_to_long(m[0:8])
seed = getPrime(64)
n = getPrime(96)

out = []
for i in range(len(m) // 8):
    b = bytes_to_long(m[8*i:8*i+8])
    seed = LCG(a,seed,b,n)
    out.append(seed)
print(out)

'''
[11306816523806448359968744947, 36825731210294893531878483479, 34541243376991313199431099859, 20354966593817263503588124934, 37588861068580029710084832784, 46973656140717560123345808645, 41524739592939159728594635383, 146800497033274580640567704, 50488771112485302710340410522, 12385224224599902891523452952, 61520982263029439442401885206, 31363021932740609933463915946]
'''