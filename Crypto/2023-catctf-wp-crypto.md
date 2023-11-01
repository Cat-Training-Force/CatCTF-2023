## Baby

该分类用于热身。

<br/>

### Baby_Classical

题目描述：

```
暂无
```

题目：

```
Hvhj ucmg i ynmr ramwj wnq t abjeg jbbyqe tgkt. Jaeewhvj bhb qte mjr ygdmi mee, znb rtsg my iqq hrp zzfsdzmmpjw, wum wqi sog igwb bhnr mw lnvr ram hmiyb gmcy. Oaax amj gntx pjw a ygmbqj cnn fiij os pxl ajlicm. Jjhahqx qy xuvrxl mjr fm pmqq, aab lpj baarxl yt wryk qy fly ram ynmr, qam hfmr rh jj pnbug ix Qigrem Wjd Egwqsl Hbmw. Wsj dnw amw rogfxz xfiq rh pjw: "Cbkx Tnytyc Kmi Wiqggo Mtoq. Fxzj ns n nbmhj os atsj fnq y uwyylr my ense. Gydm ymez rh gtzr tptvirogfxz. Xme vq lqhp aab pmfp, aab mpjd wvje lt mee uxtq. Riab rwzw mnlgmwx aab zqaj hrp fg lwerrbvlx. Brftdj dohplmqk oa ram bfy, nlw lt sog jxiaj tuc iiym, oe whc rngur yiqq dbug isi bects yme tjtax, fnq rams yhrpx enql oc gwymiae yww dohp lqhp geyglrttuck.
Pfma, Amp gtz kamp emft vq Oqljnrpx isi hrpx qx dohp ytfl cnrvbkHlnqlqhflPgipjwifDnvsd!
```

最简单快速的方法当然是用Vigenere在线爆破网站：

[Vigenere Solver | guballa.de](https://www.guballa.de/vigenere-solver)

但是，对维吉尼亚密码的分析是很有趣也很有价值的，想进一步了解的同学可以自己搜索一下，也可以看我写的一篇题解：

[Crypto趣题-古典密码 | 糖醋小鸡块的blog (tangcuxiaojikuai.xyz)](https://tangcuxiaojikuai.xyz/post/165cec8c.html#more)

exp：

```
flag:catctf{ClassicalCipherisFunny}

Key : Tiffany

message : Once upon a time there was a sweet little girl. Everyone who saw her liked her, but most of all her grandmother, who did not know what to give the child next. Once she gave her a little cap made of red velvet. Because it suited her so well, and she wanted to wear it all the time, she came to be known as Little Red Riding Hood. One day her mother said to her: "Come Little Red Riding Hood. Here is a piece of cake and a bottle of wine. Take them to your grandmother. She is sick and weak, and they will do her well. Mind your manners and give her my greetings. Behave yourself on the way, and do not leave the path, or you might fall down and break the glass, and then there will be nothing for your sick grandmother.
Haha, Now you know what is Vigenere and here is your flag catctfClassicalCipherisFunny!
```

<br/>

<br/>

<br/>

## Easy

该分类难度较低，适合入门新手了解各种加密基础概念以及crypto方向赛题的形式。

<br/>

### Easy_AES

题目描述：

```
“没有密钥还想解AES？”
```

题目：

```python
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
```

题目传达的意思很明显，通过gift恢复出AES的key与iv向量，然后进行AES解密得到flag。

很自然地会有两种解题思路:

+ 爆破。由于key是由相同的四个字节拼接八次形成，那么实际需要爆破的只有四个字节，计算下来复杂度为$2^{32}$，虽然仍然比较大，但并非完全不可行。
+ 直接恢复key。观察可知，key长度为32字节，而iv仅有16字节，那么二者相异或后，高位正好就是key的高位，而key是重复的字节拼接成的，就可以直接得到key，得到key后将key与gift异或即可得到iv向量，从而可以进行AES解密。

exp：

```python
from Cryptodome.Cipher import AES
import os
from Cryptodome.Util.number import *

gift = 63318252562251464307452832207215838563457134165318957002450688189243132668670
c = b'\xbc\x87\xa21\x0bK\x05!\xeeHcx\xc5\x921\x01\xea\xe6\xa1\t\x1eN\x01\xe5@t\xa4Ih\xc9\x89\xa8\xa6+5\x01\xd5\r\xea\xc2\x99\xa5Fr\x8b\x04\xc3\x81'

key_low = (gift >> 128)
key_num = key_low + (key_low << 128)
iv_num = key_num ^ gift

key = long_to_bytes(key_num)
iv = long_to_bytes(iv_num)

aes=AES.new(key,AES.MODE_CBC,iv)
flag = aes.decrypt(c)
print(flag)

#flag = "catctf{5d02b1a6-39f7-2bca-3807-4978f2dab90c}"
```

<br/>

<br/>

### Easy_ECC

题目描述：

```
暂无
```

题目：

```python
from Crypto.Util.number import *
from secret import flag

p = getPrime(256)
a = getPrime(256)
b = getPrime(256)
E = EllipticCurve(GF(p),[a,b])
m = E.random_point()
G = E.random_point()
k = getPrime(16)
K = k * G
r = getPrime(256)
c1 = m + r * K
c2 = r * G
c = bytes_to_long(flag) * int(m[0])

print(f"p = {p}")
print(f"a = {a}")
print(f"b = {b}")
print(f"c1 = {c1}")
print(f"c2 = {c2}")
print(f"c = {c}")

'''
p = 87092522748098669829992285868403106182336017704139443077383531853456435622471
a = 101299657691551386965604314830539394563059305182047573016174562953680113433483
b = 103515188195423215634716325708078231771637293454864925173213911439839009583929
c1 = (32318985932447513653239654085604766474975548799844355660840553348774266479326 : 67713618814819066413787229141414188948309715152902332753488481625841113997553 : 1)
c2 = (10230302454001221645915592721533577303668058584124979714911091958630449119684 : 14068985325436327334711052593723601048735307838059332297359146101024917589355 : 1)
c = 243352246360343414630771057155785496615231620377377147256856445931803440018017495259165864356164563380145135780231169307023180916540178875184090012260135703488882798862757944415926551
'''
```

简单的椭圆曲线加密，在完成本题前需要大致了解一下椭圆曲线加密的基本方式。

在本题中，椭圆曲线由下列代码段生成：

```python
p = getPrime(256)
a = getPrime(256)
b = getPrime(256)
E = EllipticCurve(GF(p),[a,b])
```

其生成的椭圆曲线为下列形式(也是最常用的形式)：
$$
y^2 = x^3 + a*x + b \quad (mod\;p)
$$
mod p的含义，就是指这条曲线被部署在了模p的有限域上，那么这条曲线的相关运算均在模p下进行。

接下来的代码段则是进行椭圆曲线上的加密过程：

```python
m = E.random_point()
G = E.random_point()
k = getPrime(16)
K = k * G
r = getPrime(256)
c1 = m + r * K
c2 = r * G
c = bytes_to_long(flag) * int(m[0])
```

逐步解释一下：

+ m和G为椭圆曲线上随机取的两个点
+ 生成16比特的随机素数密钥k，取k倍的点G作为点K(关于椭圆曲线上的点如何数乘可以自行查阅)
+ 再生成256比特的随机素数r，并使用r生成c1，c2两个点
+ 用随机生成的m点的横坐标乘上flag，并给出密文

目标很明确，要求出flag就需要m的坐标，因此要利用给定的c1、c2两个点以及椭圆曲线来求出m点。由于：
$$
c1 = m + r*K=m+r*k*G
$$

$$
c2 = r*G
$$

所以有：
$$
m = c1 - k*c2
$$
而本题中产生的随机密钥k仅有16比特，因此可以爆破求解。同时请注意，关于椭圆曲线相关点的操作需要用到sage中的一些内置函数，可以自行查阅相关用法。

exp：

```python
from Crypto.Util.number import *

p = 87092522748098669829992285868403106182336017704139443077383531853456435622471
a = 101299657691551386965604314830539394563059305182047573016174562953680113433483
b = 103515188195423215634716325708078231771637293454864925173213911439839009583929
E = EllipticCurve(GF(p),[a,b])
c1 = E(32318985932447513653239654085604766474975548799844355660840553348774266479326 , 67713618814819066413787229141414188948309715152902332753488481625841113997553)
c2 = E(10230302454001221645915592721533577303668058584124979714911091958630449119684 , 14068985325436327334711052593723601048735307838059332297359146101024917589355)
c = 243352246360343414630771057155785496615231620377377147256856445931803440018017495259165864356164563380145135780231169307023180916540178875184090012260135703488882798862757944415926551

klist = [i for i in range(2**15,2**16) if isPrime(i)]
for k in klist:
    m = int((c1 - k*c2)[0])
    if(c % m == 0):
        print(long_to_bytes(c//m))
        break

#flag = b"catctf{896534a9-9498-23ea-cb65-d95693fb9a3a}"
```

<br/>

<br/>

### Easy_LFSR

题目描述：

```
暂无
```

题目：

```python
from Crypto.Util.number import *
from secret import flag

flag = list(bin(bytes_to_long(flag))[2:])
assert(len(flag) == 351)

for i in range(len(flag)):
    flag[i] = int(flag[i])

for i in range(2000):
    flag.append(flag[i] ^ flag[i+100] ^ flag[i+200] ^ flag[i+300] ^ flag[-1])
    print(flag[-1],end = "")

#00011010011110001011101000100100111100110010011000100010000010000001011000010110110101111111110000111110011011100100001111010110100101110110111111101101000111101100011011110111110010100100000110100010111011001111110001101111000000110011110100101110011100001000000001011101101110010010010101100111111000111110101110001111010100000000111100100011011110000110100100100000001011001110100011100110111111000000110101001000011101111101001011011110100101111011101000101001111011000001101000001000101101000001110100101100101011010000001111000000101001110111110000010010111101111010110101101100001001010101110111101100001100010001110110100100100000101001110101111110110000011011000101001110011001110000111001100000010011001100011100110001000001111010000000001000010010110101010100011100110110000110111101010010000000110100011101001000111010111001101111011001111110100011010000010100100010000100100111000100010100000011011010100001011011010011011001110110011011101001111011000000010000011110111111110000011110010110001001101110101111111100110011001011101000011111011101100001010111000110100011110001001111010111011111111110111111010011101110101111110000011010001111010010011011111011100011101001000110111111000100100010001010100100101101000001001101110000001001111010111011111100010000101000111101110101001010110010001100001111011101010011111101100001001101001111110100011000111100111000000111110111110111101100111011011011111000111111000101001000000000010111110111000100101100010011100100111111100110000101101101110110001001101101010110110000100111100100100100100010011001010010110011101101100011100000100111110101110100100011111000010011010010110100000000000101011100100100111101010110011010101110010010011000110011111100011110100010001000111001011111011011111111100011010100011001110110111011101011011111001100110100010101010011101011111011011110111101100101010011111000110101100100001101000100001000111001010010000111001010001000110010110111100111110000111101111101001010010011011001000000100101010100000011
```

线性移位反馈寄存器的特征很明显，由于给了flag的二进制串长度为定长343，所以该LFSR的流密码产生形式就可以表述为：(加为模二加法，即异或)
$$
x[i+351]\;=\;x[i]\;+\; x[i+100]\;+\;x[i+200]\;+\;x[i+300]\;+\;x[i+350]
$$
而根据异或的可逆特点，左右同时进行如下处理：
$$
(x[i]\;+\;x[i+351])+\;x[i+351]\;=\;x[i]\;+\; x[i+100]\;+\;x[i+200]\;+\;x[i+300]\;+\;x[i+350]\;+(x[i]\;+\;x[i+351])
$$
即：
$$
x[i]\;=\; x[i+100]\;+\;x[i+200]\;+\;x[i+300]\;+\;x[i+350]\;+ \;x[i+351]
$$
也就是说，已知等式右侧五个二进制位的值，就可以轻松还原出等式左侧$\;x[i]\;$的值，而题目信息虽然将flag二进制串全部隐去，却产生了充足位数的流密码，因此可以还原出flag值。

exp:

```python
from Crypto.Util.number import *

clist = list("00011010011110001011101000100100111100110010011000100010000010000001011000010110110101111111110000111110011011100100001111010110100101110110111111101101000111101100011011110111110010100100000110100010111011001111110001101111000000110011110100101110011100001000000001011101101110010010010101100111111000111110101110001111010100000000111100100011011110000110100100100000001011001110100011100110111111000000110101001000011101111101001011011110100101111011101000101001111011000001101000001000101101000001110100101100101011010000001111000000101001110111110000010010111101111010110101101100001001010101110111101100001100010001110110100100100000101001110101111110110000011011000101001110011001110000111001100000010011001100011100110001000001111010000000001000010010110101010100011100110110000110111101010010000000110100011101001000111010111001101111011001111110100011010000010100100010000100100111000100010100000011011010100001011011010011011001110110011011101001111011000000010000011110111111110000011110010110001001101110101111111100110011001011101000011111011101100001010111000110100011110001001111010111011111111110111111010011101110101111110000011010001111010010011011111011100011101001000110111111000100100010001010100100101101000001001101110000001001111010111011111100010000101000111101110101001010110010001100001111011101010011111101100001001101001111110100011000111100111000000111110111110111101100111011011011111000111111000101001000000000010111110111000100101100010011100100111111100110000101101101110110001001101101010110110000100111100100100100100010011001010010110011101101100011100000100111110101110100100011111000010011010010110100000000000101011100100100111101010110011010101110010010011000110011111100011110100010001000111001011111011011111111100011010100011001110110111011101011011111001100110100010101010011101011111011011110111101100101010011111000110101100100001101000100001000111001010010000111001010001000110010110111100111110000111101111101001010010011011001000000100101010100000011")
for i in range(len(clist)):
    clist[i] = int(clist[i])

for i in range(351):
    clist.insert(0,clist[100-1] ^ clist[200-1] ^ clist[300-1] ^ clist[349] ^ clist[350])

temp = clist[:351]
for i in range(len(temp)):
    temp[i] = str(temp[i])
print(long_to_bytes(int("".join(temp),2)))

#flag = b"catctf{ea92eafe-10eb-2937-3681-ef760ea9f111}"
```

<br/>

<br/>

### Easy_hash

题目描述：

```
啊哈哈哈哈哈嘻嘻嘻嘻
```

题目：

```python
import hashlib
import os
import random
from secret import flag
from Crypto.Util.number import *

def myhash(m):
    blocks = [m[i*16:i*16+16] for i in range(8)]
    temp = 0
    for i in range(8):
        temp += ((i%4)*bytes_to_long(blocks[i]))
    return hashlib.sha256(long_to_bytes(temp)).hexdigest()

def task1():
    m = os.urandom(128)
    print("m =",bytes_to_long(m))
    fake_m = long_to_bytes(int(input("give me a valid value:")))
    if(fake_m == m):
        print("Hacker!")
        exit()
    if(myhash(fake_m) == myhash(m)):
        return
    else:
        print("Try again!")
        exit()

def task2():
    table = "0123456789abcdef"
    prefix = "".join([random.choice(table) for i in range(6)])
    print(prefix)
    m = input("give me a valid message:")
    fake_prefix = str(hashlib.md5(m.encode()).hexdigest())[:6]
    if(fake_prefix == prefix):
        print("Congratulations!The flag is :",flag)
    else:
        print("Try again!")

task1()
task2()
```

题目分为两个task，均要求给出一个指定条件的哈希碰撞，分别是：

+ 给出一个自定义的哈希函数的碰撞
+ 给出一个md5的前缀的碰撞

题目分析也就分两个task展开。

#### task1

观察自定义的哈希函数：

```python
def myhash(m):
    blocks = [m[i*16:i*16+16] for i in range(8)]
    temp = 0
    for i in range(8):
        temp += ((i%4)*bytes_to_long(blocks[i]))
    return hashlib.sha256(long_to_bytes(temp)).hexdigest()
```

可以看到，首先，他只使用了明文的前128个字节进行哈希，所以第一种做法就是：直接在给出的m串加上后缀，就能实现绕过，并成功哈希碰撞。

那么如果限制了输入长度也必须为128字节呢？同样可以进行碰撞。首先明白，该哈希函数把传递进来的参数，即字节串m按16字节分割成8块，并以这些块为单位进行哈希。观察到：

```python
for i in range(8):
    temp += ((i%4)*bytes_to_long(blocks[i]))
```

8个字节，但是仅仅对4取模，说明位置模4相等的块，前面的乘数是一样的，因此任取一组位置模4下相同的块进行位置调换即可实现哈希碰撞，如下：

```python
from Crypto.Util.number import *

m = 
m = long_to_bytes(m)
blocks = [m[i*16:i*16+16] for i in range(8)]
t = blocks[0]
blocks[0] = blocks[4]
blocks[4] = t
b = b""
for i in range(8):
    b += blocks[i]
print(bytes_to_long(b))
```

#### task2

第二部分要求给出一个任意字符串，其md5的前六位16进制字符与给定的前缀相等。

如果受思维定势影响，可能会去查阅md5的算法细节，研究如何成功实现md5的前缀碰撞，但是那样做就会非常复杂。实际上，如果将md5的前6个字符当成一个6位的完全随机的十六进制串，那么他一共存在16^6种可能性，也就是2^24种可能性。

也就是说，我们非常随意的生成一个字符串，如果将md5的过程近似看作完全随机的话，那么这个字符串前六位与给定的前六位相等的概率就是1/(2^24),看上去非常低。而运用概率论的相关知识，我们随机生成n个字符串，至少有一组与给定的前缀相等的概率就是：
$$
1-(1-\frac{1}{2^{24}})^n
$$
而可以计算出，当随机生成2^24个字符串，成功的概率就超过了60%，这也是生日攻击的理论基础。

而如何生成随机字符串就看个人喜好了。

flag：**catctf{HHhhHHhhHHhHa4a44a4a__5s5s55ssHHhhHH!}**

<br/>

<br/>

### bear的密码机

题目描述：

```
你偷偷潜入了Nemo的办公室，Nemo正在睡午觉。于是你获得了Nemo的密码机的临时加密权限。现在情况紧急，你只有三分钟的时间获得flag！
```

没有题目附件，仅仅给了一个交互实例，出这题目的目的也就是让大家体验一下选择明文攻击。按照提示输入几个相同字符，就会发现同一字符都会被加密成相同字符，也就是说这就是一个单表代换密码。那么把flag所有可能的字符集合都输入进去，就能得到对应的所有加密字符集合，用这些加密字符集合对flag密文进行解密就好。

加密源码：

```python
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
```

secret：

```
flag = "catctf{Tot4l1y_A_Cryp70_m45t3r!}"
```

<br/>

<br/>

### bear的超级数字口令

题目描述：

```
之前的密码机导致flag失窃了！Nemo很生气，于是重新设计了一个自己都通不过的数字口令，这下flag肯定安全了！
```

题目：

```python
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
```

题目会生成一个30位的由数字组成的随机passwd串，并且提供30次交互机会：

+ 输入1，可以对这个字符串进行随机加密，并返回密文
+ 输入2，可以检查passwd，若输入的数字串与passwd相等，则得到flag

完成本题需要捕捉到加密方式的漏洞，仔细观察加密方式：

```python
enckey = [random.getrandbits(3) for i in range(30)]
s = ""
for i in range(len(passwd)):
    s += str((int(passwd[i])+enckey[i]) % 10)
```

他的加密逻辑是，随机生成30个加数，并依次与passwd中的每个数字分别相加并模10，给出这个加密后的串。

那么这么做会有什么问题呢？可以看到，30个加数是由该方式产生的：

```python
random.getrandbits(3)
```

加数是三个随机比特位组成的整数，那么随机生成的加数范围仅为0-7，也就是说，每个数字+8，+9的结果，在密文中是不会出现的。因此，我们可以多次输入1，加密passwd串，统计每个位置没有出现过的数字，就能概率性获取passwd中的所有数字。

exp：

```python
from pwn import *
from Crypto.Util.number import *

#context.log_level = 'debug'

for i in range(10):
    try:
        r=remote("10.10.175.100",36337)
        test = [{str(i):0 for i in range(10)} for j in range(30)]

        #getmsg
        for i in range(29):
            r.recvuntil(b'2.Submit')
            r.sendline(b"1")
            r.recvline()
            s = r.recvline().strip().decode()
            for j in range(len(s)):
                test[j][str(int(s[j]))] = 1

        passwd = ""
        for i in test:
            for j in range(10):
                if(i[str(j)] == 0):
                    if(j != 0):
                        passwd += str((j + 2) % 10)
                    else:
                        if(i[str(9)] == 0):
                            passwd += "1"
                        else:
                            passwd += "2"
                    break

        #getflag
        r.recvuntil(b'2.Submit')
        r.sendline(b"2")
        r.recvuntil(b"Give me the password :")
        r.sendline(passwd.encode())
        temp = r.recvline()
        print(temp)
        temp = r.recvline()
        print(temp)
        r.close()
    except:
        r.close()
        
#catctf{EnCrypt10n_n0t_5ecUR3_eNoUgh!}
```

<br/>

<br/>

### Easy_MTP

题目描述：

```python
from secret import flag
from Crypto.Util.number import *
from random import *

length = len(bin(bytes_to_long(flag))[2:])
assert(length == 343)

p = getPrime(256)
def genbit():
    return str(randint(0,p)*randint(0,p) & 1)

def genkey():
    s = ""
    for i in range(length):
        s += genbit()
    return int(s,2)

m = bytes_to_long(flag)
with open("cipher.txt","w") as f:
    for i in range(100):
        f.write(str(m^genkey()))
        f.write("\n")
```

题目将flag串转化为整数，并用genkey方式生成100个随机整数，分别与flag串进行异或得到密文，这个采用的方式就是多次一密(Many-Time-Pad)。

而突破这道题的关键也就是发现genkey的漏洞，可以看到，genkey方式就是调用343次genbit函数，而genbit函数实现如下：

```python
p = getPrime(256)
def genbit():
    return str(randint(0,p)*randint(0,p) & 1)
```

也就是随机生成两个数，并取其乘积的最低位作为生成比特。似乎没问题，但是仔细一想就会发现，genbit生成0和1的概率有巨大差别。这是因为，只有奇数乘奇数才能得到奇数，也就是最低比特为1。因此genbit方式生成0、1的概率之比为3：1。

因此对任一比特位进行分析，在100条密文中，出现次数更多的就很大概率是flag串的对应比特位(因为异或0等于本身)。如此就可以进行统计从而还原flag。

exp：

```python
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

#catctf{Th3_Pr0b4biI1ty_i5_n0T_th3_54meHhH!}
```

<br/>

<br/>

<br/>

## Middle

该分类难度适中，存在一定思维量，适合接触crypto不久的选手进行初进阶练习。

<br/>

### Middle_XOR

题目描述：

```
异或了什么？
```

题目：

```python
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
```

先理顺本题目的加密逻辑：

+ 首先，将明文转化为二进制串。
+ 在该二进制串头部进行0的填充，使其长度为16的整数倍。
+ 将二进制串划分为长度为16的若干组，并分别进行encrypt函数的加密。
+ 将加密结果拼接为新字符串后，给出密文二进制串。

那么核心就在于encrypt函数的具体实现。不难发现，encrypt函数虽然较长，但是大部分篇幅都是在进行列表与字符串、整型与字符型的转换。而真正有用的只有下面这一小段：

```python
enc_block = [0 for i in range(16)]
for i in range(len(XOR_net)):
    for j in XOR_net[i]:
        enc_block[i] ^= list_block[j]
```

其实也很简单，16位密文初始均为0，按照XOR_net这个异或表对明文串进行异或，得到16位密文，也就是：(以下加法均为模二加，也就是异或)
$$
c[0] = m[1]+m[2]+m[3]+m[5]+m[6]
$$

$$
c[1] = m[1]+m[2]+m[3]+m[4]+m[5]+m[6]
$$


$$
...
$$

$$
c[15] = m[0]+m[2]+m[10]
$$

所以现在的任务就是根据这样的加密过程找出加密过程的漏洞，从而根据密文的比特位还原出明文。而很明显，这个XOR_net存在很多明文比特位的泄漏，就拿$\;c[0]\;$和$\;c[1]\;$的产生过程来举例，因为：
$$
c[0] = m[1]+m[2]+m[3]+m[5]+m[6]
$$

$$
c[1] = m[1]+m[2]+m[3]+m[4]+m[5]+m[6]
$$

两式相加：
$$
c[0] +c[1] = (m[1]+m[2]+m[3]+m[4]+m[5]+m[6])+(m[1]+m[2]+m[3]+m[4]+m[5]+m[6])\\
=(m[1]+m[1])+(m[2]+m[2])+(m[3]+m[3])+(m[5]+m[5])+(m[6]+m[6])+m[4]\\
=m[4]
$$
所以$\quad m[4]=c[0]+c[1]\quad$，明文的该比特位也就因为密文的这两个比特位泄漏了。

继续往下看，又注意到一点重要信息：明文泄漏出的比特位也可以对还原密文产生帮助。就比如，由于：
$$
c[2]=m[2]+m[4]
$$
而我们刚才才解出了$\quad m[4]\quad$的值，那么也就能获得泄漏的$\quad m[2]\quad$，这是因为：
$$
c[2]+m[4]=m[2]+m[4]+m[4]
$$
所以：
$$
m[2]=c[2]+m[4]
$$
以此类推，我们能使用这个漏洞百出的异或表，最终获得14个完全确定的比特位，而剩下的两位比特位虽然并不确定，但经推理其异或值是确定的，同时结合题目信息：flag的字符均为给定字典中的字符，所以可以采取爆破手段进行处理，从而得到最终flag字符串。

#### 非预期解

由于块加密的block设置的较小，仅有16位，所以可以分别对每一块进行爆破得到flag。

exp:

```python
from Crypto.Util.number import *
import string

dic = string.ascii_uppercase + string.ascii_lowercase + "{}_"

def decrypt(cipher):
    for i in range(len(cipher) // 16):
        block = cipher[16*i:16*i+16]

        list_block = list(block)
        for i in range(len(list_block)):
            list_block[i] = int(list_block[i])
    
        plain = [0 for i in range(16)]

        #按顺序逆推即可
        plain[4] = list_block[0] ^ list_block[1]
        plain[2] = list_block[2] ^ plain[4]
        plain[9] = list_block[3] ^ list_block[4] ^ plain[2]
        plain[15] = list_block[5] ^ plain[2] ^ plain[9]
        plain[0] = list_block[6] ^ plain[4] ^ plain[15]
        plain[13] = list_block[7] ^ plain[4] ^ plain[9]
        plain[8] = list_block[8] ^ plain[9] ^ plain[15]
        plain[14] = list_block[9] ^ plain[15]
        plain[12] = list_block[10] ^ plain[0]  ^ plain[9] ^ plain[14]
        plain[11] = list_block[11] ^ plain[12] ^ plain[15]
        plain[5] = list_block[12] ^ plain[2]
        plain[6] = list_block[13] ^ plain[12] ^ plain[14]
        plain[7] = list_block[14] ^ plain[8] ^ plain[9]
        plain[10] = list_block[15] ^ plain[0] ^ plain[2]

        #第1位与第3位仍不确定,采用爆破处理,此处注意1与3虽不确定，但其异或值是确定的,利用这一点可以显著降低爆破复杂度
        #最后在打印出的字符中，依据flag字符均在字典中这一点确定flag值
        xor13 = list_block[0] ^ plain[2] ^ plain[5] ^ plain[6]
        unsurelist0 = [[0,0],[1,1]]
        unsurelist1 = [[0,1],[1,0]]

        if(xor13 == 0):
            for i in range(2):
                plain[1] = unsurelist0[i][0]
                plain[3] = unsurelist0[i][1]

                temp = ["" for i in range(8)]
                for i in range(8):
                    temp[i] = str(plain[i])
                m = "".join(temp)
                if(chr(int(m,2)) in dic):
                    print(chr(int(m,2)),end = "")
    
        else:
            for i in range(2):
                plain[1] = unsurelist1[i][0]
                plain[3] = unsurelist1[i][1]

                temp = ["" for i in range(8)]
                for i in range(8):
                    temp[i] = str(plain[i])
                m = "".join(temp)
                if(chr(int(m,2)) in dic):
                    print(chr(int(m,2)),end = "")

        for i in range(8,16):
            temp[i-8] = str(plain[i])
        m = "".join(temp)
        print(chr(int(m,2)),end = "")


cipher = "1110011101111100001111110001011000111000110001100100001111111100010000111011010001110110100110010010000111011100111001100011001100111110001000100011111101000010010110111010011001110111100110010100010100010000010001000001110001110001001011010010011000110111111000011110000010011101001010100011111001011010"
decrypt(cipher)

#flag = "catctf{not_hard_tofind_logic_of_ezxor}"
```

即使得到了flag，这一题仍然有很多值得思考的地方。回顾一下刚才的推理过程，本质上其实是在解一个16元的线性方程组。而由于这道题的XOR_net故意设计的过于简易，所以我们才能以逐步推理的方式，就能够获得这个方程组的解。而大部分这个类型的题目，其实是需要将加密过程与矩阵、方程组等线性代数知识结合在一起解决的，所以遇到这类问题，需要有意识地将他们在思路上联系起来。

<br/>

<br/>

### Middle_RSA1

题目描述：

```
看似可能性很多。。。真的很多吗？
```

题目：

```python
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
```

不论怎么出RSA，一个基本不变的共同特点就是：**目标都是由题目给的gift、hint以及其他额外信息，去找到模数n的因子p、q，从而实现n的分解。**这一题也是一样，给出了两个关于n的因子p、q的额外信息gift1、gift2，那么任务就是利用这两个信息还原出p、q。

而gift1、gift2均是p、q经过位运算的结果。所以我们就要以比特位为单位来分析p、q的可能取值。

拿gift1作为例子，已知$\quad gift1 = p\&q\quad$，而对于 & 运算，我们知道他的重要特性是：**如果 & 运算结果为1，则参与 & 运算的两个比特位一定均为1。**因此，将gift1转为比特串，其中为1的比特位，在p、q的二进制表示中也均为1。同理，对于gift2，由于 | 运算符的重要特性：**如果 | 运算结果为0，则参与 | 运算的两个比特位一定均为0，**由此，对于gift2中为0的比特位，我们也能相应的确定出p、q在当前位置的比特位均为0。

经过这样的分析，可以发现一个事实：当且仅当gift1某比特位为0，而gift2某比特位为1时，才存在两种可能：该位p为1、q为0或该位p为0、q为1。自然而然地就会想到：接下来的内容可以通过爆破求解。可是实际操作却不行，这是因为：刚才说的gift1某比特位为0，而gift2某比特位为1这种情况并不少见，测试一下可知一共有252位满足这个情况，也就是说直接爆破数量级达到$\;2^{252}\;$，这是显然实施不了的。那么该怎么办？

这种时候，一定不能忽视掉一个很重要的值：n。$\quad n=p*q\quad$这一个在RSA中像公理一样存在的式子，其实对于解决题目往往有重要作用。在这个题目中，我们就可以利用深度优先搜索替代爆破，来显著降低复杂度。具体实现思路如下：

+ 同时将gift1、gift2的二进制串从高位向低位检索，其中：

+ ```
  1、如果均为1或均为0，则可确定p、q在该位的值。
  2、如果该位在gift1为0，而在gift2为1，则产生分支。
  ```

+ 如果不满足以下条件，则结束本次向后的搜索：

  ```
  1、将p、q当前确定的二进制位后方全部填充0，直至填满512位，此时p、q乘积应小于n。
  2、将p、q当前确定的二进制位后方全部填充1，直至填满512位，此时p、q乘积应大于n。
  ```

显然，对于正确的p、q，他会一直满足上述条件直至搜索至512位；而如果对p、q某比特判断错误，很快就会由于不满足上述条件而结束本次向后搜索。同时，由于p、q大小关系未知，所以一定能找出对称的p>q、p<q两组解，但是谁大谁小并不重要，因此也可以设置p>q这一条件来节省一半搜索时间。

搜索完毕后，本题迎刃而解。

当然，如果对位运算敏锐一点的话，很容易可以看出其实gift1+gift2=p+q，细致一点解释其原因的话其实也就是枚举每一比特位对应的四种情况：

+ 若均为0，显然等价于0+0
+ 若一个0一个1，等价于0+1
+ 若均为1，等价于1+1进位

因此可以直接联立方程组求出p、q进而解密。

exp：

```python
from Crypto.Util.number import *
from gmpy2 import *

e = 65537
n = 115758730903839231823308555023714273591262651953911464283691720682664067350659400229707324160416746737775152746540207269803723796112497613061444101549572010369152801721195466754812876024359382659819081656172178127705969863089520259632319651215562872714420716904811329771842631415638356673867277569822446803287
c = 19993786236074237416134051906776387829349963850589489205001299400759214964614448732778917755878755728112565862722087433518362198317288759668299909895051226156644144998537549027687028684679223294371070403997272268856960556217605288582520017581689226335673569525979910948834860530832532964626446046416916617492
gift1 = 8406236654915833058263189508088619389228000772047641065805757790945213218484636311118252420306043470365101220415601073756801274407085389643701225294932417
gift2 = 13289555469528986889780394438366670193095841373662649462874247561169726714549417684835966455008219356338846495528222454629822321224370056043079721679634431
bingift1 = bin(gift1)[2:]
bingift2 = bin(gift2)[2:]

def find(p,q):
    l = len(p)
    tmp0 = p + (512-l)*"0"
    tmp1 = p + (512-l)*"1"
    tmq0 = q + (512-l)*"0"
    tmq1 = q + (512-l)*"1"
    if(int(tmp0,2)*int(tmq0,2) > n):
        return 
    elif(int(tmp1,2)*int(tmq1,2) < n):
        return

    if(l == 512):
        p = int(tmp0,2)
        q = int(tmq0,2)
        if(p*q == n):
            phi = (p-1)*(q-1)
            d = inverse(e,phi)
            m = pow(c,d,n)
            print(long_to_bytes(m))
            exit()
      
    else:
        if(bingift1[l] == "1"):
            find(p+"1",q+"1")
        elif(bingift2[l] == "0"):
            find(p+"0",q+"0")
        else:
            find(p+"0",q+"1")
            find(p+"1",q+"0")


tempp = ""
tempq = ""

find(tempp,tempq)

#flag = b"catctf{1c93c635-c605-9079-53c2-1adbb1e7cfa5}"
```

<br/>

<br/>

### Middle_RSA2

题目描述：

```
Nemo学习了基本的RSA共模攻击后，信心满满地开始做这个题目，可是好像哪里不太一样。。。
```

题目：

```python
from Crypto.Util.number import *
from sympy import *
from secret import flag

m = getPrime(256)
n = nextprime((bytes_to_long(flag)) << 300)

e = [71,73,79,83,89]
c = []
for i in e:
    c.append(pow(m,i,n))
print("c =",c)

'''
c = [3584993665370794823538971526684020381334229506708133596895968409536999204984079790376149008440551028410578855094728886834755619619372578110783580710219803462890112213584230949057016656060118630104, 4989759276535357997528849922251020799165891301912783617877490602437969017607809593934852516575460413478605329176238636946693383565094312064286926114923643920846311211742857004745169805814074701829, 6642053461023663832524339460701405831900998203213451191972438266657726625218871972692446250954239707699495372072147429575168741548017508191044712022951983914898737345726236637602619748509541858367, 4193052693033474280001068591734478498106299089126282985098601018650036258306395170093507468070466042626395892208399682844273571796555401881696541571776607704920006607253483889750046907957450103890, 3947754756036180841352847778991940293340330235762075197248449949161868864279363865098593351636279205570062610031251872012378674221346372945053094003675053291245574344814943777453973251717985508145]
'''
```

首先建议想要解决本题的同学先去了解一下RSA中的经典共模攻击，对本题的思路有很大帮助。

梳理一下题目的加密流程：

+ 将flag转为大整数，并左移300位
+ 用nextprime()函数取得最接近上面那个数的下一个质数，作为后续加密的模数n
+ 取五个不同的小素数作为加密指数e，分别对明文进行模幂运算，并给出对应的密文列表。

这一题并不像常规的RSA，将flag作为明文m，而是将flag参加一定运算后形成模数n，让我们求解n的值。同时，n并非两个大素数之积，而是本身就是个素数，所以难点也并不在于如何分解n了。

如果你了解了一下共模攻击，你就会发现与本题的情境有很大共性：

+ 进行了两次及以上的RSA加密。
+ 不同次加密的加密指数e互素。
+ 不同次加密的明文m、模数n相同。

所以仅需要将共模攻击的思路略作调整，就能轻松解决本题，推导过程如下：

取前两次的加密指数e1、e2，已知：
$$
c1 \equiv m^{e1} \quad(mod\;n)\\
c2 \equiv m^{e2} \quad(mod\;n)
$$
对模等式两边略作处理：
$$
c1^{-e2} \equiv m^{e1*(-e2)} \quad(mod\;n)\\
c2^{e1} \equiv m^{e2*e1} \quad(mod\;n)
$$
由于$e1*(-e2) + e2*e1 = 0$，所以将两式相乘可得：
$$
c1^{-e2}*c2^{e1} \equiv m^{e1*(-e2)+e2*e1} \quad(mod\;n)\\
\equiv m^{0} \quad(mod\;n)\\
\equiv1 \quad(mod\;n)
$$
将$\quad c1^{-e2}\quad$移动至右侧，并且根据同余性质，有：
$$
c2^{e1} \equiv c1^{e2}\quad (mod\;n)\\
c2^{e1} - c1^{e2} = k1*n
$$
同理，对于剩下的几组加密指数，我们两两组合同样可以得到这种形式的等式：
$$
ci^{ej} - cj^{ei} = k*n
$$
求解其gcd即可得到n(给出多组数据也是方便去除$\;ki$、$kj$之间可能存在的小公因子)，之后右移即可得到flag。

然后就是，这个题目其实对应了一个升级版的Hard_RSA2，但是由于题量设计未放出，可能会在校赛和大家见面。

exp：

```python
from Crypto.Util.number import *
from gmpy2 import gcd

e = [71,73,79,83,89]
c = [3584993665370794823538971526684020381334229506708133596895968409536999204984079790376149008440551028410578855094728886834755619619372578110783580710219803462890112213584230949057016656060118630104, 4989759276535357997528849922251020799165891301912783617877490602437969017607809593934852516575460413478605329176238636946693383565094312064286926114923643920846311211742857004745169805814074701829, 6642053461023663832524339460701405831900998203213451191972438266657726625218871972692446250954239707699495372072147429575168741548017508191044712022951983914898737345726236637602619748509541858367, 4193052693033474280001068591734478498106299089126282985098601018650036258306395170093507468070466042626395892208399682844273571796555401881696541571776607704920006607253483889750046907957450103890, 3947754756036180841352847778991940293340330235762075197248449949161868864279363865098593351636279205570062610031251872012378674221346372945053094003675053291245574344814943777453973251717985508145]
knlist = []
for i in range(4):
    knlist.append(c[i]**e[i+1] - c[i+1]**e[i])

for i in range(3):
    kn = gcd(knlist[i],knlist[i+1])
n = kn

print(long_to_bytes(n>>300))

#flag  = b"catctf{5720ce27-0932-e2c4-6a90-612238272266}"
```

<br/>

<br/>

### Middle_RSA3

题目描述：

```
Nemo心想：这题p、q都给好了，这不是很简单吗！
```

题目：

```python
from Crypto.Util.number import *
import random
from secret import flag

def pad(data,bit):
    temp = len(bin(data)[2:])
    pad_length = bit - temp
    pad_data = (data << pad_length) + random.getrandbits(pad_length)
    return pad_data

m = pad(bytes_to_long(flag),1024)

def get_prime(bit):
    while(1):
        p = 2 * 7 * getPrime(bit) + 1
        if(isPrime(p)):
            return p

p = get_prime(512)
q = getPrime(512)
n = p*q
e = 7*7*7*7*7

c = pow(m,e,n)
print("p =",p)
print("q =",q)
print("n =",n)
print("c =",c)

'''
p = 137460191971421903248734970282666456357052936236325309267826027261381607494787596364694185586900461678150506751336121050696416964505449095599803784023985063
q = 9860721418259980339851718535071432928232322161057043402218644294712077358246223606787338321930806481006806109681825057554152150498652811208803589672460349
n = 1355456659130728552703937440927051368575216792075884459266902567401047511994291080770227026844213980786588891821312665440235699130632691677530305463565393918323447959981861748590308588816836911994225199705766424946089035985434128364857177612203476579345863459242384467183079400230542115729453173080726835766987
c = 793623164043246070506550788596269184419105110303948024833215670415616888488541554681716159677641475357836697213816252101550186962854788046446099017273353937153186950442792341410723820865012183730208352789289190229327937550770892606142831977859348889398082454412733823877464089108978899912318518292672709432297
'''
```

本题要关注两个数的生成过程，

+ p：p由自定义的get_prime生成，满足p-1是7的倍数。
+ m：由flag串转成的大整数拼接随机比特串，最终形成1024比特的数字。

看到给了p、q，第一反应肯定是直接求解私钥进行RSA解密，可是这么做会直接出现报错提示：逆元不存在。这是因为求解逆元需要：
$$
gcd(e,(p-1)*(q-1))  = 1
$$
然而在本题中：
$$
gcd(e,p-1)=7
$$
因此逆元不存在，无法进行RSA解密。而且根据m的生成过程，m的数量级显然是接近于n，而远大于p、q的，因此也无法根据同余性质转化到模q的意义下直接求解。

在网上搜索此类e与phi_n不互素的问题，可以发现很多文章都提到了AMM算法，这是一种当$e\mid p-1$时，可以进行的有限域开根算法。而网络上也有很多AMM算法脚本，显然这就是本题解密的关键。AMM算法实现原理暂且不论，先将其当作一个黑盒函数调用即可，下面就使用AMM算法来解决本题：

首先，将题目等式分别拆成模p和模q下的模等式：
$$
m^e\equiv c\quad (mod\;p)\\
m^e\equiv c\quad (mod\;q)
$$
对于模q下的模等式，由于$gcd(e,q-1)=1$，因此可以直接求解逆元，当作RSA解密得到$m\equiv mq\quad (mod\;q)$

对于模p下的模等式，需要使用AMM算法，那么如何调用呢？前面提到过，AMM算法解决的是$e\mid p-1$时开e次方根的问题，而本题中，虽然$gcd(e,p-1)!=1$，但同时$e\nmid p-1$，所以不能直接使用AMM开e次方根，但是，我们可以将明文在模p下的加密看作以下形式：
$$
((((m^7)^7)^7)^7)^7\equiv c\quad (mod\;p)
$$
而由于$7\mid p-1$，因此我们就可以进行一次AMM算法，将c在模p的有限域下开七次方根得到：
$$
(((m^7)^7)^7)^7\equiv c1\quad (mod\;p)
$$
此时你应该明白了，之后的工作也就是再调用4次AMM算法，并在最后一次整理出全部7个根(为什么只有最后一次需要整理出全部七个根，而前四次不需要，这个问题要弄懂AMM具体原理)，即可得到：
$$
m\equiv mp\quad (mod\;p)
$$
将这七个根依次与$m\equiv mq\quad (mod\;q)$作中国剩余定理，即可得到m的七个可能值。

当然，实际上可以使用sage集成的nth_root函数，会方便很多，这也是我最近才知道的。

exp：

```python
import random
from Crypto.Util.number import *
from sympy.ntheory.modular import crt

p = 137460191971421903248734970282666456357052936236325309267826027261381607494787596364694185586900461678150506751336121050696416964505449095599803784023985063
q = 9860721418259980339851718535071432928232322161057043402218644294712077358246223606787338321930806481006806109681825057554152150498652811208803589672460349
n = 1355456659130728552703937440927051368575216792075884459266902567401047511994291080770227026844213980786588891821312665440235699130632691677530305463565393918323447959981861748590308588816836911994225199705766424946089035985434128364857177612203476579345863459242384467183079400230542115729453173080726835766987
c = 793623164043246070506550788596269184419105110303948024833215670415616888488541554681716159677641475357836697213816252101550186962854788046446099017273353937153186950442792341410723820865012183730208352789289190229327937550770892606142831977859348889398082454412733823877464089108978899912318518292672709432297
e = 7*7*7*7*7

def onemod(e, q):
    p = random.randint(1, q-1)
    while(pow(p, (q-1)//e, q) == 1):  # (r,s)=1
        p = random.randint(1, q)
    return p

def AMM_rth(o, r, q):  # r|(q-1
    assert((q-1) % r == 0)
    p = onemod(r, q)

    t = 0
    s = q-1
    while(s % r == 0):
        s = s//r
        t += 1
    k = 1
    while((s*k+1) % r != 0):
        k += 1
    alp = (s*k+1)//r

    a = pow(p, r**(t-1)*s, q)
    b = pow(o, r*a-1, q)
    c = pow(p, s, q)
    h = 1

    for i in range(1, t-1):
        d = pow(int(b), r**(t-1-i), q)
        if d == 1:
            j = 0
        else:
            j = (-math.log(d, a)) % r
        b = (b*(c**(r*j))) % q
        h = (h*c**j) % q
        c = (c*r) % q
    result = (pow(o, alp, q)*h)
    return result

def ALL_Solution(m, q, rt, cq, e):
    mp = []
    for pr in rt:
        r = (pr*m) % q
        # assert(pow(r, e, q) == cq)
        mp.append(r)
    return mp


def ALL_ROOT2(r, q):  # use function set() and .add() ensure that the generated elements are not repeated
    li = set()
    while(len(li) < r):
        p = pow(random.randint(1, q-1), (q-1)//r, q)
        li.add(p)
    return li

amq = [pow(c,inverse(e,q-1),q)]
cp = c % p
cq = c % q

mp = AMM_rth(cp, 7, p)
for i in range(4):
    mp = AMM_rth(mp, 7, p)
rt1 = ALL_ROOT2(7, p)
amp = ALL_Solution(mp, p, rt1, cp, 7)

modlist = [p,q]
for i in amp:
    for j in amq:
        c = [int(i),int(j)]
        m = crt(modlist,c)[0]
        temp = long_to_bytes(m>>1)
        if(b"catctf" in temp):
            print(temp)
            
#flag = b"catctf{fa755bce-071e-4f1d-8cfa-37766c226065}"
```

<br/>

<br/>

### RSAES

题目描述：

```
“19937年，我学会了开汽车。。。好像多了一个3？”
```

题目：

```python
import socketserver
from Crypto.Util.number import *
from random import getrandbits
from Crypto.Cipher import AES
from sympy import nextprime
import binascii
from secret import flag

menu=b'''1. gethint
2. getflag
'''

def enc(data,key,iv):
    cipher = AES.new(key,AES.MODE_CBC,iv)
    encrypt = cipher.encrypt(data)
    return encrypt

def dec(data,key,iv):
    cipher = AES.new(key,AES.MODE_CBC,iv)
    encrypt = cipher.decrypt(data)
    return encrypt


class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        if newline:
            msg += b'\n'
        self.request.sendall(msg)

    def recv(self, prompt):
        self.send(prompt,False)
        return self._recvall()

    def task(self):
        for i in range(40):
            choice = self.recv(menu)
            if(choice == b"1"):
                temp = getrandbits(16*8)
                key = (temp<<128)+temp
                iv = getrandbits(16*8)
                m = getrandbits(32*8)
                self.send(b"gift =",False)
                self.send(str(key^iv).encode())
                c = enc(long_to_bytes(m),long_to_bytes(key),long_to_bytes(iv))
                self.send(b"c =",False)
                self.send(str(bytes_to_long(c)).encode())
                self.send(b'\n',False)
            elif(choice == b"2"):
                plist = [nextprime(getrandbits(32)) for i in range(16)]
                n = 1
                for i in range(16):
                    n *= plist[i]
                m = bytes_to_long(flag)
                e = 65537
                c = pow(m,e,n)
                self.send(b"n =",False)
                self.send(str(n).encode())
                self.send(b"c =",False)
                self.send(str(c).encode())
                exit()
            else:
                self.send(b"What are u doing?")
                exit()


    def handle(self):
        self.task()


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10001
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    print(HOST, PORT)
    server.serve_forever()
```

这是一道交互题，需要使用pwntools工具与远程反复交互得到数据，最终解决题目。关于pwntools的具体使用可自行查阅，此处仅阐述解题思路。

观察题目，一共给了40次交互机会，每一次交互可以输入1或2以获取不同数据。输入1，则给出一个关于key与iv的gift，以及对随机明文m的AES加密数据；输入2，则给出RSA的n，以及对明文flag的加密数据，同时结束交互。

因此，想要解密明文，就需要得到n的分解，也就是16个以getrandbits()函数得到的32位素数。然而getrandbits()产生的是随机数，如何确定其取值呢？通过上网查阅，可以知道这样的伪随机数产生方式是基于MT19937算法的，因此当产生的随机数序列足够长，有充足位数时，就可以用randcrack模块中的相关工具进行预测。

所以思路就是：前39次交互用于拿取数据，解密出iv、key与m并依次提交这些随机数，就可以预测出最终用于RSA加密的n的素因子。而前39次解密的方法与Easy分类的baby_AES可以说完全相同，并不困难。

exp：

```python
from pwn import *
from Crypto.Util.number import *
from randcrack import RandCrack
from random import getrandbits
from Crypto.Cipher import AES
from sympy import nextprime

def enc(data,key,iv):
    cipher = AES.new(key,AES.MODE_CBC,iv)
    encrypt = cipher.encrypt(data)
    return encrypt

def dec(data,key,iv):
    cipher = AES.new(key,AES.MODE_CBC,iv)
    encrypt = cipher.decrypt(data)
    return encrypt

r=remote("10.10.175.100",36341)
rc = RandCrack()

for i in range(39):
    r.sendline(b'1')
    temp = r.recvline()
    temp = r.recvline()
    gift = int(str(r.recvline().decode().strip()[6:]))
    key = (gift >> 128 << 128) + (gift >> 128)
    iv = key ^ gift
    c = int(str(r.recvline().decode().strip()[3:]))
    m = bytes_to_long(dec(long_to_bytes(c),long_to_bytes(key),long_to_bytes(iv)))

    #提交伪随机数
    for j in range(128//32):
        t = key&0xffffffff
        rc.submit(t)
        key=key>>32
    for j in range(128//32):
        t = iv&0xffffffff
        rc.submit(t)
        iv = iv>>32
    for j in range(256//32):
        t = m&0xffffffff
        rc.submit(t)
        m = m>>32

#第40次，预测伪随机数从而得到plist，进而解密
r.sendline(b'2')
temp = r.recvline()
temp = r.recvline()
n = int(str(r.recvline().decode().strip()[3:]))
c = int(str(r.recvline().decode().strip()[3:]))
e = 65537
plist = [nextprime(rc.predict_getrandbits(512)) for i in range(3)]
phi_n = 1
for i in range(3):
    phi_n *= (plist[i] - 1)
d = inverse(e,phi_n)
m = pow(c,d,n)
print(long_to_bytes(m))

#flag = b"catctf{c1aa4128-87a8-bf31-85f6-ee36000e4057}"
```

本题主要也是想让大家体验一下crypto中交互题目的流程。密码学中很多知识点，比如选择明文攻击、选择密文攻击以及各种谕示机模型等出现在crypto赛题中时，基本是以交互题的模式出现。所以熟悉pwntools的使用也是很有必要的。

<br/>

<br/>

### Middle_DSA

题目描述：

```
做本题目前可以先学习一下DSA签名的基本流程。
```

题目：

```python
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
```

完成本题需要了解DSA签名的基本流程。了解之后再来阅读本题，发现题目泄露的信息是两次签名用的k存在一定关系，我们需要利用这个关系来求出k的值，进而恢复私钥flag。

具体求解过程如下：

由于：
$$
k2 = k1^3 + k1 +i\\
s1 \equiv(h1+r1*x)*k1^{-1}\quad (mod \;q)\\
s2 \equiv(h2+r2*x)*k2^{-1}\quad (mod \;q)
$$
将k1、k2移动至模等式左侧，有：
$$
s1*k1 \equiv h1+r1*x\quad (mod \;q)\\
s2*k2 \equiv h2+r2*x\quad (mod \;q)
$$
上下式分别乘r2、r1，作差消去x：
$$
s1*k1*r2-s2*k2*r1\equiv h1*r2-h2*r1\quad (mod\;q)
$$
代入k2，得：
$$
s1*k1*r2-s2*(k1^3+k1+i)*r1\equiv h1*r2-h2*r1\quad (mod\;q)
$$
又由于k1已知为64比特，因此可在模q的多项式环上求根，求出符合要求的k后，随意取一个等式即可求解flag：
$$
x \equiv (s1*k - h1) * r1^{-1} \quad (mod\;q)
$$
又因为在DSA密钥选取中，私钥的取值范围在(0,q)，因此解出来的模q下的根，按常理来说即是flag的原本值。本题目中flag也因此设计的较小。

exp：

```python
from Crypto.Util.number import *
from hashlib import sha256

p, q, g, y = (329466618499261020048099756611587145404143744653351180336272711255920939333879618450299119449698608131120341832164819003494462044377397933259473873479544981129520716301547870347536316969557671226790609927049677795021322420364038997267210779523952466080934821495513358902014332078422005001763379935698989021107, 1348061579207087009838296193732079850287318389779, 257770881619574176520208203704245179330594957391976994619084377852591734867005999118010927921580353543603773732763824407045880545644903991068415498096711678600493155201963398581556108027668725149349354054718585325009991715550079052667715568359371255509666273500002194305492249720063712414923552380092261715706, 150342085930880938215574113969667105871121625791739541501623278623666799509331357162993064532660792772744969891506357478273134847248887611225455853281754270566903999330078733444655840263327190783676366583879206927556859616194414635400073995732715776299242379741788129952886642591635243888614430356177755217059)
(r1, s1) = 916053866561856680020253391889758448915469093378, 1230191144384297307551839931519918456403444949778
(r2, s2) = 277634558371960064162549113571028444063934104845, 996064415849024341126238021393257770915779481404 

m1 = b"I don't know much about DSA..."
m2 = b"But I can learn!!!"
h1 = bytes_to_long(sha256(m1).digest())
h2 = bytes_to_long(sha256(m2).digest())

#2 转化为k模多项式
PR.<k> = PolynomialRing(GF(q))
for i in range(10,20):
    f = s2*(k^3+k+i)*r1 - s1*k*r2 - h2*r1 + h1*r2
    root = f.roots()

    if(root):
        for j in root:
            if(len(bin(j[0])[2:]) == 64):
                k = int(j[0])
                flag = (s1*k - h1) * inverse(r1, q) % q
                print("catctf{"+str(long_to_bytes(flag))[2:-1]+"}")
                break
                
#flag = b'catctf{f1nd_x_0f_DSA}'
```

<br/>

<br/>

### Middle_oracle

题目描述：

```
不能解密文的也能叫解密机？
```

题目：

```python
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
```

仍然是一个分为两个task的交互题，接下来也分为两部分展开。

#### task1

任务1将flag的前半段作为明文，进行RSA加密后返回公钥n和密文c，而靶机端可以提供一次解密操作，但是解密的不能是c+kn。

那么如何不直接解密c+kn，又能通过解密得到的值求解明文呢？这里主要介绍三种方法。 

##### 方法一

(该方法在没有公钥e时无法使用)

传入：
$$
a^e*c
$$
其中，a可以是自己选定的任何数，一般选择2，这样解密得到的值为：
$$
a*m
$$
将该值乘上a模n下的逆元就能得到m

##### 方法二

传入：
$$
n-c
$$
在模n意义下，这其实就是-c，因此解密得到的值为：
$$
n-m
$$
再用n减去该值得到m

##### 方法三

传入：
$$
c^{-1}
$$
这等价于：
$$
m^{-d}
$$
因此解密得到的值为：
$$
m^{-1}
$$
求解该值在模n下的逆元即为m

#### 方法四

由于明文仅有前半段，故较小，所以可以传入密文的小指数加密结果如：
$$
c^2
$$
那么解密得到m^2实际小于n，可以开根得到m

#### task2

这个问题为Parity Oracle Attack中的LSB Oracle Attack(Least Significant Bit Oracle Attack)，是一个经典的RSA选择密文攻击谕示机模型。

在这个谕示机中，你可以输入任意密文，并且获得其解密后明文的最低比特位，那么怎么对这个性质加以利用呢？

首先，我们考虑传入：
$$
2^e*c \quad (mod\;n)
$$
解密出来的明文值为：
$$
2*m \quad (mod\;n)
$$
但是我们只能获得2m的最低比特，这有什么用呢？注意到n是由两个大素数p、q相乘得到，因此n一定为奇数，而由于：
$$
0<m<n
$$
所以：
$$
0<2m<2n
$$
那么思考一下，最低比特位会暴露什么？首先，2m一定是一个偶数，那么如果0<2m<n，靶机端反馈的结果就应该是0，因为他相当于没有模n；而如果n<2m<2n，那么靶机端就会反馈1，因为这实际上是一个偶数减去一个奇数，所以最低比特位就是个奇数。

也就是说，这一次返回的密文信息，能直接帮我们缩小一半m的取值范围，也就是我们能够根据结果确定m是处于(0,n/2)，还是(n/2,n)。

那么拓展一下思维，下一步该怎么做呢？自然是继续缩小m的范围，因此我们第二次考虑传入：
$$
4^e*c \quad (mod\;n)
$$
那么这一次解密会得到：
$$
4*m \quad (mod\;n)
$$
的最低比特位，而由前一次的结果，我们能确定4m是在(0,2n)之间还是在(2n,4n)之间，那么同理，我们能根据结果将m缩小到(0,n/4),(n/4,n/2),(n/2,3n/4),(3n/4,n)的其中一个区间内。

那么之后的操作也不需多说，就是一直传入2的ie次方乘c，并由此缩小区间范围，最终就能确定m的一个非常小的区间。此处要注意，由于区间//2是整除，因此会在末几位产生一定误差，不过对得到flag串没有大影响。

exp：

```python
from pwn import *
from Crypto.Util.number import *

#context.log_level = 'debug'

r=remote("10.10.175.100",35520)
#task1
temp = r.recvline()
n = int(str(r.recvline().decode().strip()[3:]))
c = int(str(r.recvline().decode().strip()[3:]))

r.sendline(str(n-c).encode())
m1 = n-int(str(r.recvline().decode().strip()[57:]))
print(str(long_to_bytes(m1))[2:-1],end = "")

#task2
temp = r.recvline()
n = int(str(r.recvline().decode().strip()[3:]))
c = int(str(r.recvline().decode().strip()[3:]))
e = 65537

left = 0
right = n

for i in range(1,1024):
    r.recvuntil(b"lost:")
    r.sendline(str(pow(2,(e*i),n)*c).encode())
    lastbit = int(str(r.recvline().decode().strip()[15:]))
    if(lastbit == 0):
        right = (left+right)//2
    else:
        left = (left+right)//2
    if(left == right):
        break
print(str(long_to_bytes(left))[2:-1])

#catctf{N0w_Y0w_kNoW_wh4t_15_0racl3!}
```

<br/>

<br/>

### Middle_oracle2

题目描述：

```
又是一个谕示机，但是这个要怎么使用呢？
```

题目：

```python
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
```

题目生成一个512bit的随机数作为secret，之后，我们可以选择进行如下操作：

+ 输入1，可以再提供一个a，b，靶机端会返回(secret+a,b)的最大公约数，注意a、b均为正数
+ 输入2，可以核验secret，如果输入值与secret值相等，就能得到flag。

如何进行利用呢？首先要明白，求解一个数与2的最大公约数，就能确定该数是奇数还是偶数。也就是说，令a=0，b=2，我们就能根据返回结果得到secret的最低比特位。然而，题目限制了a、b均为正，但是影响不大，我们只需要取a=1，b=2，依然可以确定最低比特位，只是结果要取个反而已。

那么第二次该传入什么呢？很容易就能想到，如果能将已知的比特位减去，那么第二次求与4的gcd就能得到secret的倒数第二位，而仍然因为a，b均需大于0，所以把减的操作改成加对应比特位的逆就能把已知位全部修改为0，而求解的结果继续取反就好。

在之后，就重复该操作，依次求与8、16、32......的gcd就能得到所有比特位，然后得到secret后进行核验就能得到flag。

#### 非预期解

而赛后看参赛选手们的wp，发现有一个非预期解也很有意思：

我们取任意一个素数p作为b，并将所有小于p的正数作为a，依次发送给服务器。而在模p意义下，一定有且仅有一个a满足下式：
$$
secret + a \equiv 0 \quad (mod\;p)
$$
而当a满足上面这个式子的时候，靶机返回的结果是gcd(secret+a,p)=p，而不满足上式时会返回1。而由于交互不限次数，因此我们可以搜集到足够多的式子如：
$$
secret  \equiv -a_i \quad (mod\;p_i)
$$
只要发送的素数乘积大于secret，我们就能CRT得到secret的值了。

当然如果限制交互次数，比如最多进行512次，这个方法可能就用不了了。当然这个思路确实很有意思。

exp：

```python
from pwn import *
from Crypto.Util.number import *
from tqdm import *

#context.log_level = 'debug'

r=remote("10.10.175.100",36338)

#getLSB
num = ""
for i in trange(512):
    r.recvuntil(b"2.guessnum")
    r.sendline(b"1")
    if(i != 0):
        tempa = 2**i - int(num[::-1],2)
    else:
        tempa = 1
    tempb = 2**(i+1)
    r.recvuntil(b"a = ")
    r.sendline(str(tempa).encode())
    r.recvuntil(b"b = ")
    r.sendline(str(tempb).encode())
    thegcd = int(r.recvline().strip().decode())
    if(thegcd == tempb):
        num += "1"
    else:
        num += "0"

#getflag
num = int(num[::-1],2)
r.recvuntil(b"2.guessnum")
r.sendline(b"2")
r.recvuntil(b"Check your secret :")
r.sendline(str(num).encode())
temp = r.recvline()
print(temp)
temp = r.recvline()
print(temp)

#catctf{Ju4t_An0th3r_LSB_attACk!!}
```

<br/>

<br/>

<br/>

## Hard

该分类存在一定难度，需要同时具有灵活的思维以及一定量的知识储备，适合想要进一步提升自己的cryptoer尝试。

<br/>

### Hard_RSA

题目描述：

```
Nemo也想过成为一名铜匠，奈何数论太难学了。
*hint1对你的解题有一定帮助，但是不解出hint1仍然可以解题。
```

题目：

```python
from Crypto.Util.number import *
from sympy import *
from secret import flag,hint1

def getn():
    while(1):
        p = getPrime(128)
        error = getPrime(40)
        q = 2*p + error
        r = 2*q + error
        if(isPrime(q) and isPrime(r)):
            n = p*q*r
            break
    return (p,n)

e = 65537

#step 1
p1,n1 = getn()
hint1_enc = pow(bytes_to_long(hint1),e,n1)
print("hint1_enc =",hint1_enc)
print("p1 =",p1)
print("n1 =",n1)


#step_2
p = getPrime(512)
q = getPrime(512)
n = p*q

a = getPrime(512)
b = getPrime(16)
m = bytes_to_long(flag)
hint2 = pow((a*p + b),q,n)
c = pow(m,e,n)
print("hint2 =",hint2)
print("n =",n)
print("c =",c)

'''
hint1_enc = 81410455638978409164259444919301919004039168105498097066894873200032325739015513072857302922621201132563677863689691
p1 = 262726397885004821911124269672266219817
n1 = 145077853507975436750834997262072948658867600956220420571072608726655109502006223745168041173033352252243905006874073
hint2 = 76365961284206788846337118586080088152618427584031945902089660388319933927923116270501939183895761439446801300651172452036828117326634075602939230046403952964582219445745421072754817834269688283542670097365551320401087865123678477038236635371384773086853444993428846209267595537649428971235394440131039392625
n = 110209520206742741948506756493191161913926109540508718881123685741911222474420697491281731367887008521387736563780864849109401713213647085815879126117587521279674073324987130883917954090177227594558649375661722804112176864417280291159808392760730415028629655809584763163285199014692393327204538254936430590899
c = 84345299633297789297352837849279001204443711590121337540969236692610027337278928626589856468208700831865337971235547581848958840387276084420274713889748413312878922978315147540373062163315353337156724430913048750658116980983932277459029396584928058181491602354057215920794976679755061517240435678912670575892
'''
```

题目分为两个模块：第一部分是对hint1加密，第二部分是对flag加密。两部分除了加密指数e均为65537这一共同点外，基本没有联系。所以跳过第一部分直接做第二部分也是可以的。

但我们依然按顺序解题，因为hint1可能包含第二部分如何解密的提示。

第一部分相较于常规RSA，略有不同：

+ 模数n由三个素数组成
+ 三个素数之间由明确的关系式联系起来，并且隐藏了20位的小素数error，error在这里可以理解为“轻微扰动”

所以只要能解出error的取值，就能得到三个素数的值，而多素数RSA的解密其实与常规RSA并没有区别，只是计算$\phi(n)$时略有不同。

（然后这里出题失误了，没有注意到其实就是一个普通一元二次方程。。接下来还是按预期的讲）

把error看作未知数，实际上要求解的就是在模n意义下的一个方程。而对于解出error这种相对于模数n来说较小的根，coppersmith定理给出了有力的工具：

```python
#step 1
PR.<x> = PolynomialRing(Zmod(n1//p1))
f = (2*p1 + x)*(4*p1 + 3*x)
f = f.monic()
roots = f.small_roots(X=2^41,beta=0.4)
if roots:
    error = int(roots[0])
```

具体原理可以自行查阅相关资料，此处不再进行展开。解得error后就可以进行RSA解密，得到hint1：

```
try to use ilgnidoaixamief(?)
```

倒着看其实就是feimaxiaodingli(费马小定理)，而之所以要倒着写，是提示第二部分需要倒着利用费马小定理。

有了提示后接着看第二部分，第二部分加密流程如下：

+ 随机生成素数p，q，a，b，其中b是16位的小素数。
+ 将p、q用于普通RSA加密。
+ 给出hint2，hint2是一个由a、b、p、q、n共同组成的提示。

结合hint1，目标明确：倒着利用费马小定理，从而由hint2给出n的分解。

接下来就是如何倒着利用费马小定理：
$$
hint2 \equiv (a*p+b)^q\quad (mod\;n)
$$
利用同余性质，可以将其拆成以下两个模等式：
$$
hint2 \equiv (a*p+b)^q\quad (mod\;p)\\
hint2 \equiv (a*p+b)^q\quad (mod\;q)
$$
对于第一个模等式进行二项式定理展开：
$$
hint2 \equiv b^q\quad (mod\;p)
$$
这样一来就完全消除了a的影响，接着做如下处理：
$$
(hint2)^p \equiv b^{q*p}\quad (mod\;p)
$$
此时利用费马小定理：
$$
hint2 \equiv b^{n}\quad (mod\;p)\\
hint2-b^n = k*p
$$
因此，将$hint2-b^n$与$n$求gcd即可得到p，最后进行RSA常规解密即可。

至于为什么我把他称作倒着利用费马小定理，是因为在crypto中，一般利用费马小定理是为了去除指数，而在本题我们先进行了模数的扩大，最后才消除指数。

exp：

```python
from Crypto.Util.number import *
from gmpy2 import *

e = 65537
hint1_enc = 81410455638978409164259444919301919004039168105498097066894873200032325739015513072857302922621201132563677863689691
p1 = 262726397885004821911124269672266219817
n1 = 145077853507975436750834997262072948658867600956220420571072608726655109502006223745168041173033352252243905006874073
hint2 = 76365961284206788846337118586080088152618427584031945902089660388319933927923116270501939183895761439446801300651172452036828117326634075602939230046403952964582219445745421072754817834269688283542670097365551320401087865123678477038236635371384773086853444993428846209267595537649428971235394440131039392625
n = 110209520206742741948506756493191161913926109540508718881123685741911222474420697491281731367887008521387736563780864849109401713213647085815879126117587521279674073324987130883917954090177227594558649375661722804112176864417280291159808392760730415028629655809584763163285199014692393327204538254936430590899
c = 84345299633297789297352837849279001204443711590121337540969236692610027337278928626589856468208700831865337971235547581848958840387276084420274713889748413312878922978315147540373062163315353337156724430913048750658116980983932277459029396584928058181491602354057215920794976679755061517240435678912670575892

#step 1
PR.<x> = PolynomialRing(Zmod(n1//p1))
f = (2*p1 + x)*(4*p1 + 3*x)
f = f.monic()
roots = f.small_roots(X=2^41,beta=0.4)
if roots:
    error = int(roots[0])

q1 = 2*p1 + error
r1 = 2*q1 + error
phi_n1 = (p1-1)*(q1-1)*(r1-1)
d1 = inverse(e,phi_n1)
hint1 = int(pow(hint1_enc,d1,n1))
print(long_to_bytes(hint1))

#step 2
for b in range(2**16):
    h2 = pow(b,n,n)
    p = GCD(n,hint2-h2)
    if(p == 1):
        continue
    q = n//p
    phi = (p-1)*(q-1)
    d = inverse(e,phi)
    m = int(pow(c,d,n))
    flag = long_to_bytes(m)
    print(flag)
    
#flag = b"catctf{35b4488a-596a-5ff0-dbdb-e4ec8673b55e}"
#hint1 = b"try to use ilgnidoaixamief(?)"
```

<br/>

<br/>

### Hard_LCG

题目描述：

```
“这个LCG怎么什么参数都没有？”Nemo非常抓狂。
```

题目：

```python
from Crypto.Util.number import *
from gmpy2 import *
from secret import flag

def pad(data):
    if(len(data) % 8):
        data += b"\x00"*(8-len(data) % 8)
        return data

def LCG(a,m,b,n):
    m = (a*m + b) % n
    return m

m = pad(flag)*2
a = bytes_to_long(m[0:8])
seed = getPrime(64)
n = getPrime(96)

out = []
for i in range(len(m) // 8):
    b = bytes_to_long(m[8*i:8*i+8])
    seed = LCG(a,seed,b,n)
    out.append(seed)
print(out)

'''
[11306816523806448359968744947, 36825731210294893531878483479, 34541243376991313199431099859, 20354966593817263503588124934, 37588861068580029710084832784, 46973656140717560123345808645, 41524739592939159728594635383, 146800497033274580640567704, 50488771112485302710340410522, 12385224224599902891523452952, 61520982263029439442401885206, 31363021932740609933463915946]
'''
```

梳理一下题目的加密流程：

+ 将flag填充0直至长度满足是8的倍数，并进行复制后作为m。
+ 将m的首八个字符作为LCG的乘数a。
+ 随机生成LCG的seed及模数n。
+ 将m中每八个字符依次作为LCG的参数b，并进行加密，打印出密文列表。

可以看出，要求得flag，就是要恢复出每次LCG的参数b。可是这道题目除了密文列表，a、b、n三个参数都没有给出，而这几个参数对于求解LCG基本是必不可少的，所以要找到加密过程中可能泄漏这几个参数的步骤，从而恢复参数，求解flag。

再看一看加密流程，能看出两个突破口：

+ 将flag填充0直至长度满足是8的倍数，**并进行复制后作为m。**
+ 将m的**首八个字符作为LCG的乘数a。**
+ 随机生成LCG的seed及模数n。
+ 将m中每八个字符依次作为LCG的参数b，并进行加密，打印出密文列表。

这两点分别说明了什么？第一点说明，在LCG的完整12次加密中，**每个b都使用了两次，例如，第一次和第七次加密均使用了相同的b，第二次和第八次均使用了相同的b，以此类推**；而第二点则为爆破a提供了可能，这是因为flag开头一定是"catctf{"这七个字符，因此仅需要爆破1个可见字符的范围，就一定存在正确的乘数a。

因此，我们可以暂时把a当作已知量，按照如下方式求解n：(其中，以b代指m转为整数后的列表)

由于有：
$$
out[1] \equiv a*out[0] +b[1]\quad(mod\;n)\\
out[7] \equiv a*out[6] +b[1]\quad(mod\;n)
$$
作差，得：
$$
out[7]-out[1]\equiv a*(out[6]-out[0]) \quad (mod\;n)
$$
所以：
$$
out[7]-out[1]- a*(out[6]-out[0]) =k1*n
$$
同理，

$$
out[8]-out[2]- a*(out[7]-out[1]) =k2*n
$$
求解gcd，即可得到模数n。

得到模数n后，又因为已经拥有了a，就可以逐步求解出每个b，最终就得到flag。

```python
from Crypto.Util.number import *

out = [11306816523806448359968744947, 36825731210294893531878483479, 34541243376991313199431099859, 20354966593817263503588124934, 37588861068580029710084832784, 46973656140717560123345808645, 41524739592939159728594635383, 146800497033274580640567704, 50488771112485302710340410522, 12385224224599902891523452952, 61520982263029439442401885206, 31363021932740609933463915946]
ahigh = bytes_to_long(b"catctf{")<<8
for i in range(2**8):
    m = []
    a = ahigh + i
    n = GCD(a*(out[6] - out[0])-(out[7] - out[1]),a*(out[7] - out[1])-(out[8] - out[2]))
    if(len(bin(n)[2:]) != 96):
        continue
    for j in range(len(out)//2 - 1):
        temp = (out[j+1] - a*out[j]) % n
        m.append(str(long_to_bytes(temp))[2:-1])
    m.insert(0,str(long_to_bytes(a))[2:-1])
    print("".join(m))
    
#flag = b"catctf{41f3f1ae-040f-aa60-ae0c-d6a74472c9f4}"
```

<br/>

<br/>

## 总结

至此，CatCTF2023新生赛crypto部分就全部讲解完毕啦！希望大家踊跃投入到crypto方向中来，我们校赛的时候再见！