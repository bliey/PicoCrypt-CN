# PicoCrypt-CN

基于 [Picocrypt](https://github.com/Picocrypt/Picocrypt) 使用 Wails 3 重制的桌面版加密工具。

加密核心从原版 Picocrypt v1.49 逐行移植，生成的加密文件与原版 **100% 兼容**。

## 主要特性

- 完整兼容原版加解密功能
- 中文 / 英文界面切换
- 支持拖放文件 / 文件夹
- 偏执模式、Reed-Solomon、弱化文件特征、递归加密等高级选项
- 设置功能：记住上次选项、默认输出目录
- 轻量界面，操作简单

## 下载

请到 [Releases](https://github.com/bliey/PicoCrypt-CN/releases) 页面下载最新版本的 `PicoCrypt-CN.exe`。

## 使用方法

1. 下载并运行 `PicoCrypt-CN.exe`
2. 将文件或文件夹拖入窗口
3. 输入密码（可选密钥文件）
4. 点击开始进行加密或解密

## 开发

```sh
# 安装前端依赖
cd frontend && npm install && cd ..

# 开发模式
wails3 dev

# 构建
wails3 build
