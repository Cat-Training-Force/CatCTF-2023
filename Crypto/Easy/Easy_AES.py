from Cryptodome.Cipher import AES
import os
from Cryptodome.Util.number import *
from secret import flag

def pad(text):
    if len(text.encode()) % 16:
       add = 16 - (len(text.encode()) % 16)
    else:
       add = 0
    text = text + ('\0' * add)
    return text.encode()

def encrypt(flag):
    key=os.urandom(4)*8
    iv=os.urandom(16)
    print("gift :" , bytes_to_long(key)^bytes_to_long(iv))
    aes=AES.new(key,AES.MODE_CBC,iv)
    enc_flag = aes.encrypt(pad(flag))
    print(enc_flag)

encrypt(flag)

#gift : 63318252562251464307452832207215838563457134165318957002450688189243132668670
#b'\xbc\x87\xa21\x0bK\x05!\xeeHcx\xc5\x921\x01\xea\xe6\xa1\t\x1eN\x01\xe5@t\xa4Ih\xc9\x89\xa8\xa6+5\x01\xd5\r\xea\xc2\x99\xa5Fr\x8b\x04\xc3\x81'