# PicoCrypt-CN

用 Wails 3 重写的 Picocrypt 桌面版（当前版本 v1.0.0）。加密核心 (`internal/core`) 从原版
Picocrypt v1.49 (`Picocrypt-main/src/Picocrypt.go`) 逐行移植，生成的加密卷
与原版 100% 兼容（相同的卷头格式、Argon2id/HKDF/XChaCha20/Serpent 参数与
Reed-Solomon 编码）。界面支持中文与 English。

## 运行

```sh
wails3 dev        # 开发模式（前端热更新）
wails3 build      # 构建到 bin/PicoCrypt-CN.exe
```

首次运行前需 `cd frontend && npm install`。

## 测试

```sh
go test ./internal/core/ -count=1
```

覆盖：普通/偏执/Reed-Solomon/密钥文件（有序与无序）/否认性/注释/多文件压缩/
分卷重组 round-trip，卷头布局逐字段校验，以及损坏修复与强制解密路径。

## 结构

- `main.go` — 应用入口：窗口、原生拖放事件、关窗拦截、命令行参数
- `service.go` — CryptoService 结构体、构造函数、任务生命周期
- `bindings.go` — 前端绑定：选项与会话控制（密码/注释/选项/开始）
- `bindings_files.go` — 前端绑定：文件与输入（拖放/选择/密钥文件/输出路径）
- `state.go` — 状态管理与事件推送（state/progress，含进度节流）
- `i18n.go` — 多语言翻译（中英状态/进度/输入提示文案）
- `settings.go` — 设置结构与持久化、设置绑定
- `internal/core/` — 加密核心（逐行移植自原版，不含任何 UI 代码）
- `frontend/` — 界面（Vite + TypeScript，无框架）

## 功能

与原版一致：拖放加解密、密码强度/生成器、密钥文件（可要求顺序）、注释、
偏执模式、压缩、Reed-Solomon、弱化文件特征、递归加密、分卷与重组、强制解密、
自动解压、删除原文件/卷、命令行参数拖放。

另有设置页（右下角 ⚙）：记住上次的选项状态、默认输出目录、中英文界面切换，
配置持久化于 `%APPDATA%\picocrypt-wails\settings.json`。
