# 不要扫码

## 题面

*by Nemo.*

每次都要来的那个

## 分发的文件

目录下的这个 zip

## WP

~~什么？你们每次都要来的那个是什么？扫了就知道了~~

搜索和运用工具的能力

1. 看到了一个 bin 一个 patch，file 一下那个 bin 发现是一张图。~~然后改成图片格式后扫一下~~
2. 观察 patch 文件，看到了如下内容：
    ```
    diff --git a/flag.bin b/flag.bin
    index 0f09cc0d32724c2efdbd6d1d7987baaf9386e109..5017c26c146f9be0504648cff96fed8d76471c9d 100644
    GIT binary patch
    ```
3. 搜索一下，发现是个 git patch，可以使用 git 打上去。
4. `git apply ./flag.patch`

## 啥？你问源码？

1. 首先生成两个二维码图片
2. 初始化一个空的 git 目录，然后将第一个 commit。
3. 将第二个图片 add，然后 `git diff --staged --binary > flag.patch`

你会了！