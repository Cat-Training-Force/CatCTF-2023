from secret import flag
import random
import string

MENU = '''1.Encrypt
2.Submit
'''

table = string.digits
temp = random.choices(table,k=30)
passwd = "".join(temp)

for round in range(30):
    choice = input(MENU)
    if(choice == "1"):
        enckey = [random.getrandbits(3) for i in range(30)]
        s = ""
        for i in range(len(passwd)):
            s += str((int(passwd[i])+enckey[i]) % 10)
        print(s)
    elif(choice == "2"):
        passwd_1 = input("Give me the password :")
        if(passwd == passwd_1):
            print("You must be admin and here is your flag :")
            print(flag)
        else:
            print("Hacker!")
        break
    else:
        print("What are you doing?")
        break
