import requests
from bs4 import BeautifulSoup
from time import sleep
import re
import base64
import hashlib


url = "http://10.10.175.100:37124"
times = 0
sess = ""
data = {
    "answer":""
}
r = ""
while True:
    print("times=",times)
    if(times == 0):
        r = requests.get(url=url,)
        sess = r.headers['set-Cookie'].split(';')[0]
        sess = sess.split('=')[1]
        print(r.text)
    else:
        print(r.text)
    pattern = re.compile(r'(base64|md5|sha1|sha256)\(\"([0-9|a-z|A-Z]{10,20})\"\)')
    
    try:
        s = re.findall(pattern, r.text)[0]
        if(s[0] == 'base64'):
            data['answer'] = base64.b64encode(s[1].encode('utf-8')).decode('utf-8')
        elif(s[0] == 'sha256'):
            data['answer'] = hashlib.sha256(s[1].encode('utf-8')).hexdigest()
        elif(s[0]=='sha1'):
            data['answer'] = hashlib.sha1(s[1].encode('utf-8')).hexdigest()
        elif(s[0]=='md5'):
            data['answer'] = hashlib.md5(s[1].encode('utf-8')).hexdigest()
        print(s)
        print(data['answer'])
    except:
        print(s)
        print(r.text)
    
    sleep(1.1)
    r = requests.post(url=url,
                    cookies={
                        "PHPSESSID":sess},
                    data=data,
                    )
    print("--------------------------------------------------------------------")
    times += 1
    if('ctf' in r.text):
        print(r.text)
        break


