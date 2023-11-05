# TongjiCode

## 题面

*by Nemo.*

连一刻都没有为 `CEC-IDE` 的死哀悼，立刻来到战场的是，`TongjiCode`！

`TongjiCode` 以“做好数字同济创新应用的孵化器和技术管理的总抓手”为使命，由 `TongjiCTF` 新生赛（`CatCTF`）组委会自主研发，提供多种主流语言的开发环境，是同济校内首款同时支持`麒麟`、`统信 UOS`、`Windows`、`macOS` 等多环境的 IDE 工具。`TongjiCode` 提供了代码编写、智能辅助、编译调试、版本控制等功能，同时自建插件市场，除了提供 1600 余种技术插件服务，还提供一系列的数字同济公共服务能力插件，提升研发效率。

~~什么？你问为什么只提供了 `Windows` 的附件？因为出题人懒了~~

注意：即使不使用 `Windows` 操作系统也可以拿到 flag。  
注意：自备上网工具。

提示：虽然不能直接拆出源码，但是有某个文件指示了哪里有源码。
提示：访问凭证可能就在眼前……？
提示：去 GitHub 上研究一下大家都是如何克隆仓库的吧！
提示：你可能会想了解如何使用找到的凭证访问远程 git 仓库。

## 分发的文件

目录下的这个 zip

## WP

1. 一解包就看到了大大的 `id_ed25519`，这个是密钥。
2. `\resources\app` 下有个 `product.json`，里面指示了 repo。
3. `GIT_SSH_COMMAND='ssh -i <这里填密钥所在位置，记得确定好权限>' git clone git@github.com:Cat-Training-Force/tongji-code.git`
4. flag 就在 `README.md` 里。

## 啥？你问源码？

GitHub 上自己找咯。