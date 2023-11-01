from Crypto.Util.number import *
from secret import flag,fakeflag
from random import *

menu = '''1.getnum
2.guessnum
'''

secret = getRandomNBitInteger(512)
while(1):
    choice = input(menu)
    if(choice == "1"):
        try:
            a = int(input("a = "))
            assert(a > 0)
            b = int(input("b = "))
            assert(b > 0)
            print(GCD(secret+a,b))
        except:
            print("Something goes wrong...")
            break
    elif(choice == "2"):
        my_secret = int(input("Check your secret :"))
        if(my_secret == secret):
            print("Congratulations!")
            print(flag)
        else:
            print("Try again!")
            print(fakeflag)
        break
    else:
        print("What are you doing?")
        break