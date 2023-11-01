from Crypto.Util.number import *
from secret import flag

m1 = bytes_to_long(flag[:len(flag)//2])
m2 = bytes_to_long(flag[len(flag)//2:])

def task1():
    p = getPrime(512)
    q = getPrime(512)
    n = p*q
    e = getPrime(48)
    print("Task1:")
    c = pow(m1,e,n)
    print("n =",n)
    print("c =",c)
    temp = int(input("Now you have a chance to decrypt a cipher:"))
    if(temp % n == c):
        print("Hacker!")
        exit()
    else:
        phi = (p-1)*(q-1)
        d = inverse(e,phi)
        temp_dec = pow(temp,d,n)
        print("The message is:",temp_dec)

def task2():
    p = getPrime(512)
    q = getPrime(512)
    n = p*q
    e = 65537
    print("Task2")
    c = pow(m2,e,n)
    print("n =",n)
    print("c =",c)
    while(1):
        temp = int(input("Now you can decrypt any cipher but something lost:"))
        phi = (p-1)*(q-1)
        d = inverse(e,phi)
        temp_dec = pow(temp,d,n)
        print("The message is:",temp_dec & 1)

task1()
task2()