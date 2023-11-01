from Crypto.Util.number import *

with open("cipher.txt","r") as f:
    c = f.readlines()
    f.close()
t = []
for i in range(len(c)):
    t.append(bin(int(c[i]))[2:].zfill(343))

m = ""
for i in range(343):
    count0 = 0
    count1 = 0
    for j in range(len(t)):
        if(t[j][i] == "0"):
            count0 += 1
        else:
            count1 += 1
    if(count0 > count1):
        m += "0"
    else:
        m += "1"
print(long_to_bytes(int(m,2)))