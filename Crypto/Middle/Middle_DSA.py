from Crypto.Util.number import *
from random import randint
from hashlib import sha256
from secret import flag

def getkey():
    x = bytes_to_long(flag[7:-1])
    q = getPrime(160)
    while True:
        t = 2*getPrime(1024-160) * q
        if isPrime(t+1):
            p = t+1
            break
    h = randint(1, p-2)
    g = pow(h, (p-1)//q, p)
    y = pow(g, x, p)
    return(x,(p,q,g,y))

pri_key,pub_key = getkey()
p,q,g,y = pub_key

m1 = b"I don't know much about DSA..."
m2 = b"But I can learn!!!"
h1 = bytes_to_long(sha256(m1).digest())
h2 = bytes_to_long(sha256(m2).digest())

k1 = getPrime(64)
k2 = k1**3 + k1 + randint(10,20)

r1 = pow(g, k1, p) % q
s1 = (h1 + pri_key*r1) * inverse(k1, q) % q
r2 = pow(g, k2, p) % q
s2 = (h2 + pri_key*r2) * inverse(k2, q) % q

print(pub_key)
print(f'(r1, s1) = {r1}, {s1}')
print(f'(r2, s2) = {r2}, {s2}')

'''
(329466618499261020048099756611587145404143744653351180336272711255920939333879618450299119449698608131120341832164819003494462044377397933259473873479544981129520716301547870347536316969557671226790609927049677795021322420364038997267210779523952466080934821495513358902014332078422005001763379935698989021107, 1348061579207087009838296193732079850287318389779, 257770881619574176520208203704245179330594957391976994619084377852591734867005999118010927921580353543603773732763824407045880545644903991068415498096711678600493155201963398581556108027668725149349354054718585325009991715550079052667715568359371255509666273500002194305492249720063712414923552380092261715706, 150342085930880938215574113969667105871121625791739541501623278623666799509331357162993064532660792772744969891506357478273134847248887611225455853281754270566903999330078733444655840263327190783676366583879206927556859616194414635400073995732715776299242379741788129952886642591635243888614430356177755217059)
(r1, s1) = 916053866561856680020253391889758448915469093378, 1230191144384297307551839931519918456403444949778
(r2, s2) = 277634558371960064162549113571028444063934104845, 996064415849024341126238021393257770915779481404 
'''