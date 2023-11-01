from secret import flag
import random
import string

MENU = '''1.Encrypt
2.Submit
'''

table = string.digits
temp = random.choices(table,k=30)
passwd = "".join(temp)
print(passwd)

test = [{str(i):0 for i in range(10)} for j in range(30)]

for round in range(30):
    if(1):
        enckey = [random.getrandbits(3) for i in range(30)]
        s = ""
        for i in range(len(passwd)):
            s += str((int(passwd[i])+enckey[i]) % 10)
            test[i][str((int(passwd[i])+enckey[i]) % 10)] = 1

for i in test:
    for j in range(10):
        if(i[str(j)] == 0):
            print(j,end = " ")
    print()