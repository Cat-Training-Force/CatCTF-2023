# 注释

## 题面

*by Nemo.*

阁下固然知道写代码可以有注释，但当🐻老师说他给比赛平台的域名也加了注释时，你又该如何应对？

与解题不一定有关的事：使用学校的网络基础架构尝试解这个可能会遇到意想不到的后果（指出不了想要的东西）。

## WP

搜索、应用/运用工具的能力和基础的计算机网络知识

~~看了一眼 WP，好像本次的第一名觉得这个是最难的~~

0. 本次比赛域名是 `catctf.anzupop.com`
1. 什么是域名的注释？直接搜索似乎没有想要的结果，这时候就需要去了解域名。
2. 经过一番搜索~~这个是不是就是最困难的部分~~，你了解到了一个域名有多种记录，其中有一个不起到实际功能性的是 TXT 记录。`TXT records are a type of Domain Name System (DNS) record in text format, which contain information about your domain. TXT records also have information that helps external network servers and services handle outgoing email from your domain.`
3. 查找工具，使用工具来获取该记录。

示例：

```
# nemo @ nemo-workstation in ~ [20:10:53]
$ doggo catctf.anzupop.com -t TXT @tcp://114.114.114.114
NAME                    TYPE    CLASS   TTL     ADDRESS                         NAMESERVER
catctf.anzupop.com.     TXT     IN      300s    "catctf{COmM#Nt_oF_The_d0M@In}" 114.114.114.114:53
```