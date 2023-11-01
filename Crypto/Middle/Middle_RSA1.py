from Crypto.Util.number import *
from gmpy2 import *
from secret import flag

m = bytes_to_long(flag)
e = 65537
p = getPrime(512)
q = getPrime(512)
n = p*q
gift1 = p&q
gift2 = p|q
c = pow(m,e,n)

print("n =",n)
print("c =",c)
print("gift1 =",gift1)
print("gift2 =",gift2)

'''
n = 115758730903839231823308555023714273591262651953911464283691720682664067350659400229707324160416746737775152746540207269803723796112497613061444101549572010369152801721195466754812876024359382659819081656172178127705969863089520259632319651215562872714420716904811329771842631415638356673867277569822446803287
c = 19993786236074237416134051906776387829349963850589489205001299400759214964614448732778917755878755728112565862722087433518362198317288759668299909895051226156644144998537549027687028684679223294371070403997272268856960556217605288582520017581689226335673569525979910948834860530832532964626446046416916617492
gift1 = 8406236654915833058263189508088619389228000772047641065805757790945213218484636311118252420306043470365101220415601073756801274407085389643701225294932417
gift2 = 13289555469528986889780394438366670193095841373662649462874247561169726714549417684835966455008219356338846495528222454629822321224370056043079721679634431
'''