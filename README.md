# dsh-reverse-proxy-gateway

把 [DSH（DeepSeek Harness）](https://github.com/deepseek-ai) 桌面版的本地 Web 服务安全地反代到公网 —— 一个插件搞定监听、认证、会话注入和端口跟随。

装好后用自己的域名从手机或任意电脑访问，**看到的是同一台机器上的同一个会话**，不是另开一个实例。

## 功能

- 在 DSH 进程内另起固定端口，不动宿主原本的随机回环端口
- 内置 Basic Auth 与固定 token 登录，通过后下发长期 cookie（默认 30 天）
- 自动跟随 DSH 重启后的随机端口，不用手动同步
- 转发时重写 Host 并注入宿主会话 cookie —— **不需要改 `trustedHosts`，也不需要拉长 `cookieMaxAgeDays`**
- 支持 WebSocket upgrade 与流式响应
- 设置页一级标签、插件详情页卡片、输入框下方图标，三处都能配和开关

## 技术栈

| 项目 | 说明 |
|---|---|
| 语言 | JavaScript（纯 ESM，无构建步骤） |
| 运行时 | Node.js `^22.19.0 \|\| >=24.0.0` |
| 宿主 | DSH `^0.2.0-rc.1 \|\| ^0.2.1-rc.1 \|\| ^0.2.2-rc.1` |
| 运行时依赖 | **无**（只用 `node:http`、`node:net`、`node:crypto`、`node:fs` 等内置模块） |
| 服务端 | 自建 HTTP server + 手写转发，`node:net` 对接 upgrade |
| 客户端 | 宿主 `slots` 槽位 + `React.createElement`（无 JSX、无打包） |
| 配置 | `schemastery` schema，运行期覆盖文件 `~/.dsh/.dsh-reverse-proxy-gateway.json` |

## 安装

**桌面版（推荐）**：设置 → 插件 → 安装，填下面这个 git 地址。

```
git+https://github.com/xiongking/dsh-reverse-proxy-gateway.git
```

**命令行**（`web` 等非托管 profile）：

```bash
dsh plugin --profile web add "git+https://github.com/xiongking/dsh-reverse-proxy-gateway.git"
```

安装后重启 DSH。`desktop` profile 由桌面应用独占，命令行无法管理，请用图形界面。

## 快速开始

### 1. 设置登录凭据

打开 **设置 → 远程访问**（或插件详情页的卡片），填用户名和密码，点保存。密码至少 8 位。

> 密码与固定 token 至少要有一项，否则网关不会监听（这是防止无认证暴露）。

### 2. 确认监听地址

默认监听 `0.0.0.0:3080`，即本机所有网卡的 3080 端口。查本机内网 IP：

```bash
ifconfig | grep "inet " | grep -v 127.0.0.1
```

### 3. 在反向代理软件里指向本机

路由器、nginx、Caddy、Cloudflare Tunnel 都可以。目标地址填 `本机IP:3080`，例如 `192.168.1.10:3080`。

关键要求只有一条：**保留原始 Host 头**（不要改写成 `127.0.0.1`），否则插件的地址校验会拒绝。TLS 建议在这一层终止。

### 4. 填回对外地址

在**设置 → 远程访问**的「对外地址」填入你的域名，例如 `https://dsh.example.com`。它只用于拼接免密链接和状态展示。

### 5. 登录

浏览器打开你的域名，输入第 1 步设的用户名密码。登录一次后凭 cookie 直通，手机刷新、切后台都不用再登。

## 配置项

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enabled` | boolean | `true` | 总开关，关掉即停止监听 |
| `listen` | string | `"0.0.0.0"` | 监听地址。`0.0.0.0` = 所有网卡；只让本机反代连入填 `127.0.0.1` |
| `port` | number | `3080` | 监听端口，反代指向这里 |
| `publicUrl` | string | `""` | 对外地址，仅用于拼接免密链接与状态展示 |
| `username` | string | `"dsh"` | Basic Auth 用户名 |
| `password` | string | `""` | Basic Auth 密码，至少 8 位 |
| `accessToken` | string | `""` | 固定登录 token，访问 `publicUrl?token=该值` 免密登录 |
| `cookieDays` | number | `30` | 网关 cookie 有效期（天） |
| `switchMode` | `"local"` \| `"always"` \| `"never"` | `"local"` | 输入框下方图标的显示范围，见下节 |
| `confirmToggle` | boolean | `true` | 点一下只是待确认，再点一下才真正切换 |

`port` 与 `listen` 改动需要重启 DSH；其余改动保存即生效。

界面上的改动写到 `~/.dsh/.dsh-reverse-proxy-gateway.json`（权限 600），优先级高于 profile 里的静态配置。

## 输入框下方那行的图标

对话界面里，输入框卡片下方那一行的最右端有一个地球图标，**颜色就是状态**：

| 颜色 | 含义 |
|---|---|
| 绿 | 已开启且正在监听 |
| 灰 | 已关闭 |
| 橙 | 已开启但没监听（端口被占用，或没设密码与固定 token） |

**点一下即启停**，不需要重启 DSH。悬停显示「远程访问已开启」或「远程访问已关闭」。

### 显示范围（`switchMode`）

默认 `local`：只有从 `127.0.0.1` / `localhost` 打开 DSH 时才显示这个图标，用手机、平板、别的机器经域名访问时**不显示**。这样做是因为远程那端点一下就把网关关了，等于当场切断自己这条连接，触屏上很容易误触。

| 值 | 行为 |
|---|---|
| `local` | 仅本机（回环地址）访问时显示 |
| `always` | 始终显示，远程设备上也能开关 |
| `never` | 不显示（仍可在设置页「远程访问」里开关） |

### 二次确认（`confirmToggle`）

默认开启。开启后点第一下只进入待确认：图标变成琥珀色，提示变成「再点一次确认关闭远程访问」，**4 秒内**再点一下才真正切换，超时自动撤销。

关掉后即恢复成"点一下立刻切换"。

这两个选项都在设置页「远程访问」→「输入框开关」里改，保存即生效。

## 安全须知

- DSH 拥有**整机 shell 与全盘读写权限**。这层网关失守，等同于交出这台机器。
- 不要把 `0.0.0.0:3080` 直接暴露到公网。至少：由路由器/隧道终止 TLS，并尽量在那一层再加一层认证。
- 固定 token 与密码等价于长期凭据，泄露后请立刻在界面上改掉。
- 配置文件接口要求已登录的界面会话或 Basic Auth，不接受匿名读写。
- 出站只连回环地址，不构成开放代理。

## 排错

| 现象 | 原因与处理 |
|---|---|
| 外部访问 502 / 连不上 | 插件没在监听。看设置页里 `enabled` 是否开启、`password` 是否为空；端口被占用时日志有 `EADDRINUSE` |
| 外部访问 403 | 反向代理改写了 Host 头。设成「保留原始 Host」或透传 Host |
| 登录后又跳回登录页 | 浏览器没保存 cookie，或 `cookieDays` 太小。检查是否在隐私模式、cookie 是否被拦 |
| 改了 `port` 不生效 | 端口与监听地址需重启 DSH |
| 图标是橙色 | 开着但没监听：端口被占用，或密码与 token 都为空 |
| 插件页卡片不出现 | 宿主路由未就绪，重启 DSH |

## 卸载

1. 在插件列表里停用或移除 `dsh-reverse-proxy-gateway`
2. 删掉 `~/.dsh/.dsh-reverse-proxy-gateway.json`

## 许可

MIT
