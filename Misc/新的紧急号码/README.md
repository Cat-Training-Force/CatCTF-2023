# 新的紧急号码

## 题面

*by Nemo.*

Moss：新的紧急号码好像有点长？

## 分发的文件

目录下的 `output.mp4`

## WP

~~第一名甚至是直接猜出来的~~

联想

1. 听到了拨号声？
2. 手工或者人工解码，得到了一串分离的数字。
3. ASCII 解码

## 啥？你问源码？

```ffmpeg.exe \
    -i video.mp4 \
    -i merged.wav \
    -c:v copy \
    -filter_complex '[1:a] volume=0.1; [1:a] adelay=36500|36500 [delayed]; [0:a] [delayed] amix [out]' \
    -map 0:v \
    -map '[out]' \
    output.mp4
```