from secret import flag
import random
import time

dic_enc = [chr(i) for i in range(32,127)]
dic_dec = [chr(i) for i in range(32,127)]
random.shuffle(dic_dec)

def enc(m):
    c = ""
    for i in m:
        c += dic_dec[dic_enc.index(i)]
    return c

print("flag_enc =",enc(flag))
time_start = time.time()

while(1):
    time_end = time.time()
    if(time_end-time_start > 180):
        print("You're under arrest,hacker!")
        exit()
    m = input("message :")
    print("cipher :",enc(m))