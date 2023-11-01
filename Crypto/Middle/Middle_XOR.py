from Crypto.Util.number import *
import string
from secret import flag

dic = string.ascii_uppercase + string.ascii_lowercase + "{}_"
for i in flag:
    assert(i in dic)

XOR_net = [[1,2,3,5,6],
           [1,2,3,4,5,6],
           [2,4],
           [2,7,9,10],
           [7,10],
           [2,9,15],
           [0,4,15],
           [4,9,13],
           [8,9,15],
           [14,15],
           [0,9,12,14],
           [11,12,15],
           [2,5],
           [6,12,14],
           [7,8,9],
           [0,2,10]
           ]

def encrypt(block):
    assert(len(block) == 16)

    list_block = list(block)
    for i in range(len(list_block)):
        list_block[i] = int(list_block[i])
    
    enc_block = [0 for i in range(16)]
    for i in range(len(XOR_net)):
        for j in XOR_net[i]:
            enc_block[i] ^= list_block[j]
    
    for i in range(len(enc_block)):
        enc_block[i] = str(enc_block[i])

    enc_block = "".join(enc_block)
    return enc_block

flag = flag.encode()
m = bytes_to_long(flag)
mbin = str(bin(m)[2:])

if(len(mbin) % 16 != 0):
    pad = "0"*(16-(len(mbin) % 16))
    mbin = pad + mbin

cipher = ""
for i in range(len(mbin) // 16):
    block = mbin[16*i:16*i+16]
    cipher += encrypt(block)

print(cipher)
#1110011101111100001111110001011000111000110001100100001111111100010000111011010001110110100110010010000111011100111001100011001100111110001000100011111101000010010110111010011001110111100110010100010100010000010001000001110001110001001011010010011000110111111000011110000010011101001010100011111001011010