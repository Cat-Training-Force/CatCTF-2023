# bear hunt catno

## 题面

*idea by John, description by Nemo.*

在 `xdlddw` 中有一位姓姜的队员，你知道他曾用的手机号码是什么吗?

flag: 手机号 sha1 后包上 `catctf{}` 提交。

## WP

基础社工（OSINT）。

1. `xdlddw` 在当前的情景下应该是一个队伍名称吧？
2. ~~其实我直接查 "xdlddw" 就找到了 https://m.freebuf.com/articles/network/373439.html~~ 搜索以找出谁姓姜。
3. ~~在此 WP 编写的时候本人在百度中打 xdlddw，结果第一个候选词就是 xdlddw战队姓姜的，而且还一步直达答案，这下我们 CatCTF 也是能左右搜索候选词的大比赛辣~~找出姓名，然后在各个页面中进行搜索就能找到手机号码。
4. ~~本事件的始作俑者已经对被害人表示了真挚的歉意~~ sha1 以后提交就行。