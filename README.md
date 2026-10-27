# VPN Gate SSTP 家宽节点 🚀

自动抓取 [VPN Gate](https://www.vpngate.net/) 的 SSTP 家宽/机房节点，逐个验证可用性，按国家分组、标注住宅/机房，再由 VPS 上的 SSTP 客户端连接这些节点，以 VLESS 订阅的形式提供给客户端。**每 30 分钟自动更新一次。**

> VPN Gate 的 SSTP 节点更新快，手动测试筛选太痛苦。本仓库把它全自动了：客户端只需添加一次订阅，之后刷新订阅就能拿到最新的可用节点。

本项目基于 [hezhanleiok/gate](https://github.com/hezhanleiok/gate) 修改。

---

## 项目优势：减少对 Cloudflare 的依赖

原项目的节点检测要部署一个 Cloudflare Worker，在 Worker 里拨 SSTP 隧道、读出口 IP。这条路有几个硬伤：

- **账号风险**：用 Worker 批量建立 VPN 隧道、转发流量，容易触发 Cloudflare 的滥用检测，Worker 被停用乃至账号受限的情况并不少见；检测一挂，整条流水线就停了
- **免费额度限制**：每轮要并发检测上百个节点，免费版 Workers 的请求数、子请求数和 CPU 时间限制很容易碰到
- **部署和维护麻烦**：要单独部署 Worker，在仓库里配 `CHECK_WORKER` Secret，还要防 Worker 地址泄露被别人盗用额度

现在检测器直接内置在仓库里（[`sstp_check.mjs`](./sstp_check.mjs)），自己实现了 SSTP + PPP + TCP，零依赖，随 GitHub Actions 一起运行：

| | 旧方案：检测 Worker | 现方案：内置检测器 |
| :--- | :--- | :--- |
| 检测在哪里跑 | Cloudflare Workers | GitHub Actions 运行器 |
| 要部署的外部服务 | 一个 Worker | 无 |
| 要配置的 Secret | `CHECK_WORKER` | 无 |
| Cloudflare 账号风险 | Worker 拨 VPN 隧道，可能被判定滥用 | 检测不经过 Cloudflare 账号 |
| 检测方式 | Worker 拨通隧道并读出口 IP | 一样：真实拨通 SSTP 隧道，经隧道访问 iplocate.io 读出口 IP / ASN / 机房属性 |

Cloudflare 现在只用于**入口**：域名解析、Cloudflare Tunnel，以及可选的 WARP 槽位（`GATE_WARP=0` 可关闭）。这些都是 Cloudflare 的常规用法，不涉及在 Cloudflare 上跑代理代码。

---

## 架构

~~~text
VPN Gate 官方源
      │  GitHub Actions 每 30 分钟定时抓取
      ▼
筛选 SSTP 节点 → 去重
      │
      ▼
内置 SSTP 检测器（Node.js，随 Actions 运行）
      │  真实拨通 SSTP 隧道 → 是否可用 + 出口 IP（住宅/机房判定）
      ▼
保留可用节点 → 按国家分组 → 住宅/机房标注 → 延迟排序
      │
      ▼
生成 nodes.txt + 节点网页（GitHub Pages 发布，公开、不含任何密钥）
      │
      ▼
VPS（本仓库 vps/ 目录）
      │  gate-manager 每分钟检查 N 个槽位，失效的从 nodes.txt 换新节点
      │  每个槽位 = 一条 SSTP 隧道（pppK）= 订阅里的一个节点
      ▼
客户端订阅 → 使用 VPN Gate 家宽节点
~~~

使用时的流量路径：

~~~text
客户端 —VLESS/WS/TLS→ Cloudflare Tunnel → VPS nginx → xray ─┬─ slot1 → ppp1 —SSTP→ VPN Gate 节点 A → 目标网站
                                                             ├─ slot2 → ppp2 —SSTP→ VPN Gate 节点 B
                                                             ├─ …
                                                             └─ warp —WireGuard→ Cloudflare WARP
~~~

WARP 槽位由 xray 内置的 WireGuard 直接连接 Cloudflare WARP，出口是 Cloudflare 的 IP（机房，不是住宅）。安装时会自动注册一个免费的 WARP 设备，凭据保存在 VPS 的 `/etc/gate/warp.json`。VPS 会定期重建时，建议把这个文件的 base64（`base64 -w0 /etc/gate/warp.json`）存起来，下次安装时通过 `GATE_WARP_B64` 传入，复用同一个设备，不必每次都注册新设备。

---

## 部署教程

### 前置条件

- 一个 Cloudflare 账号（免费即可，只用于域名和 Tunnel，不需要部署 Worker）
- 一个 GitHub 账号
- 一个已接入 Cloudflare 的域名
- 一台能跑 PPP 的 Linux VPS（KVM 等完整虚拟机，Ubuntu/Debian；OpenVZ/LXC 一般没有 `/dev/ppp`），并已用 Cloudflare Tunnel（cloudflared）接入；没有这样的 VPS 时，可以用下面的 [Docker 部署](#docker-部署可替代第-34-步)，它在 Northflank 等不给特权的容器平台上也能跑

### 第 1 步：Fork 本仓库

在 GitHub 上打开本仓库，点 **Fork**，复制到你的账号下。

> 节点检测已内置在仓库里（`sstp_check.mjs`，Node.js 实现的 SSTP 客户端，随 GitHub Actions 一起运行）：**不需要部署检测 Worker，也不需要配置任何 Secret**，Fork 之后直接进入第 2 步。

### 第 2 步：开启 GitHub Pages 与 Actions

1. 仓库 → **Settings → Pages**，**Source** 选 **GitHub Actions**（选中即生效，没有保存按钮；不要点下方推荐工作流的 Configure）
2. 进 **Actions** 页，若提示启用 Actions 就点启用
3. 手动运行一次：**Actions → VPN Gate Node Check → Run workflow**
4. 跑完看到绿色 ✓ 即成功，之后每 30 分钟自动运行

运行记录最后一步 **Show site URL** 会显示实际地址，一般是：

~~~text
https://你的GitHub用户名.github.io/仓库名/            ← 节点网页
https://你的GitHub用户名.github.io/仓库名/nodes.txt   ← 节点清单
~~~

### 第 3 步：在 VPS 上安装

把 [`vps/`](./vps/) 目录复制到 VPS，以 root 运行：

~~~bash
GATE_UUID=$(cat /proc/sys/kernel/random/uuid)   # 主 UUID，记下来，订阅地址要用
GATE_UUID=$GATE_UUID GATE_HOST=gate.你的域名 bash vps/install.sh
~~~

脚本会安装 sstp-client、xray（固定版本并校验 SHA256）、nginx，注册 WARP，建立 8 个 SSTP 槽位，并启动每分钟一次的 gate-manager 定时任务。可选环境变量见 `install.sh` 开头的注释（槽位数 `GATE_SLOTS`、nginx 端口 `GATE_PORT` 等）。

> 安装脚本使用 `nodefaultroute`，不会修改 VPS 的默认路由，SSH 不受影响。

查看槽位状态：

~~~bash
gate-manager status
~~~

### 第 4 步：Cloudflare Tunnel 添加路由

Zero Trust → 网络 → Tunnels → 你的隧道 → **已发布应用程序路由** → 添加：

| 字段 | 填写 |
| :--- | :--- |
| 子域名 / 域 | `gate` / 你的域名（和 `GATE_HOST` 一致） |
| 路径 | 留空 |
| 服务 | `HTTP`，`172.17.0.1:18080` |

> cloudflared 跑在 Docker 容器里时用 `172.17.0.1`（docker0）；直接装在 VPS 上时用 `127.0.0.1:18080`，安装时设置 `GATE_LISTEN=127.0.0.1`。安装脚本结束时会打印实际要填的地址。

### 第 5 步：客户端添加订阅

~~~text
https://gate.你的域名/sub/你的GATE_UUID
~~~

订阅里有 8 个 VPN Gate 节点（`01-韩国-住宅` 这样命名）和 1 个 `WARP` 节点，连接地址、`host`/`sni` 都是 `GATE_HOST`（客户端直接连 Cloudflare 解析出的地址）。每个节点固定对应一个槽位：槽位背后的 VPN Gate 节点失效时会自动换新，客户端配置不用改；刷新订阅只是更新节点名称里的国家。

> GATE_UUID 就是访问凭证，不要公开分享订阅链接。

### 每次重建 VPS 自动安装（可选）

如果 VPS 会定期重建，可以在部署流程里检出本仓库，把 `vps/` 复制上去后执行 `install.sh`，`GATE_UUID` 放在 CI 的 Secret 里。

### Docker 部署（可替代第 3、4 步）

镜像 [`passport888/gate-tunnel`](https://hub.docker.com/r/passport888/gate-tunnel) 在 [work-tunnel-vless](https://github.com/playwjj/work-tunnel-vless)（node VLESS + cloudflared）的基础上附加了本仓库的 VPS 部分，一个容器里同时跑两套服务，cloudflared 也在容器内，不需要在宿主机另外安装。

~~~bash
docker run -d --name gate-tunnel --restart unless-stopped \
  --device /dev/ppp --cap-add NET_ADMIN \
  -e UUID=<uuid> -e TUNNEL_DOMAIN=vless.你的域名 -e TUNNEL_TOKEN=<Tunnel Token> \
  -e GATE_HOST=gate.你的域名 -e GATE_WARP_B64=<可选> \
  passport888/gate-tunnel
~~~

也可以用 env 文件和 docker-compose：在 [`docker/`](./docker/) 目录下把 `gate.env.example` 复制为 `gate.env` 并填好，然后执行 `docker compose up -d`（[`docker-compose.yml`](./docker/docker-compose.yml)）。compose 把 `/etc/gate` 挂成了卷，重建容器时会沿用已注册的 WARP 设备，不需要设置 `GATE_WARP_B64`。只想用 env 文件时，把上面命令里的 `-e` 换成 `--env-file gate.env`（值不要加引号）。

- 槽位有两种实现，由 `GATE_SSTP_MODE` 选择，默认 `auto`：容器里有 `/dev/ppp` 时用 `ppp`，否则用 `socks`。
  - `ppp`：sstpc + pppd 内核隧道，需要 `--device /dev/ppp --cap-add NET_ADMIN`，只能在 KVM 等主机上用（宿主机需已加载 `ppp_generic`：`modprobe ppp_generic`）。
  - `socks`：用户态 SSTP 客户端 [`sstp-socks`](./sstp/)，自己实现了 SSTP / PPP（MS-CHAPv2）协议，IP 包交给 gVisor 的用户态 TCP/IP 栈，每个槽位在容器内提供一个 SOCKS5 端口（`21080+K`）给 xray。不需要 `/dev/ppp`、TUN 或任何特权，**Northflank 等托管容器平台用这个**，docker run 时去掉 `--device` 和 `--cap-add` 两个参数即可。TCP 和 UDP 都支持。
  - 用 `GATE_SLOTS=0` 可以关闭 SSTP 槽位，只留 WARP。
- `GATE_UUID` 默认等于 `UUID`，其余 `GATE_*` 变量含义与 `install.sh` 相同，见 [`docker/entrypoint.sh`](./docker/entrypoint.sh) 开头的注释。
- 同一个 Tunnel 里配两条 Public Hostname，都指向容器内部：`vless.你的域名` → `http://localhost:3000`（work-tunnel-vless），`gate.你的域名` → `http://localhost:18080`（gate）。
- 容器重建会重新注册 WARP 设备。注册后执行 `docker exec gate-tunnel base64 -w0 /etc/gate/warp.json`，把结果设为 `GATE_WARP_B64` 即可复用。
- 订阅地址同第 5 步：`https://gate.你的域名/sub/<GATE_UUID>`。
- 订阅里第一个节点是 work-tunnel-vless 自己的 VLESS 节点（连 `TUNNEL_DOMAIN`，出口是容器所在机器的 IP），名称默认 `work-tunnel-vl`，可用 `GATE_VLESS_NAME` 改；不想放进订阅时设 `GATE_VLESS_SUB=0`。

---

## 配置速查表

**GitHub 仓库** Settings → Secrets and variables → Actions：

| 名称 | 类型 | 说明 |
| :--- | :--- | :--- |
| `NODES_URL` | Variable（可选） | nodes.txt 的发布地址，只用于日志提示；给 Pages 绑定自定义域名时设置，否则自动推导 |

**VPS 安装参数**（`vps/install.sh` 的环境变量）：

| 名称 | 说明 |
| :--- | :--- |
| `GATE_UUID` | 必填，主 UUID；各槽位 UUID 由它派生，也是订阅路径 |
| `GATE_HOST` | 必填，客户端访问的域名（Tunnel 路由的主机名） |
| `GATE_SLOTS` | 槽位数（同时保持的 SSTP 隧道数），默认 8 |
| `GATE_LISTEN` / `GATE_PORT` | nginx 监听地址和端口，默认 docker0 地址 / 18080 |
| `GATE_NODES_URL` | nodes.txt 地址，默认本仓库的 GitHub Pages |
| `GATE_WARP` | `1`（默认）注册 WARP 并在订阅里加一个 `WARP` 节点；`0` 关闭 |
| `GATE_NODE_SEED` | 可选，任意字符串；按它打乱选节点的顺序（住宅优先不变）。部署多台时各设不同的值（如 `a`、`b`），各台会优先连不同的 VPN Gate 节点；不设时所有机器按同一顺序选，节点基本重复 |
| `GATE_WARP_B64` | 已有 `/etc/gate/warp.json` 的 base64；设置后复用该 WARP 设备，不再注册新设备 |

**vpngate.py**（一般不用改，也可以用同名环境变量覆盖）：

| 常量 / 环境变量 | 说明 |
| :--- | :--- |
| `CHECK_CONCURRENCY` | 检测并发数，默认 32 |
| `CHECK_TIMEOUT` | 单个节点检测超时（秒），默认 45 |
| `MAX_CHECK_NODES` | 最多检测的节点数，默认 0（不限） |

---

## 说明与限制

- 只输出 `vless://` 链接（VLESS + WebSocket + TLS）
- SSTP 隧道由 Linux 内核的 PPP（`ppp` 模式）或用户态网络栈（`socks` 模式）承载，TCP/UDP 都支持；目标只支持 IPv4（VPN Gate 只分配 IPv4）
- 速度主要取决于 VPN Gate 节点本身的带宽，各节点差别很大，同一节点不同时段也不同
- 没有匹配到槽位的流量会被丢弃，不会从 VPS 自己的 IP 出去
- VPN Gate 是志愿者节点，随时可能下线；gate-manager 约 1 分钟内会把失效槽位换成新节点

---

## 常见问题

### 所有节点都连不上
- 先在浏览器打开订阅地址，能看到一串 base64 文本说明 Tunnel 和 nginx 正常
- 在 VPS 上运行 `gate-manager status`，看各槽位的 `pppK` 是否有 IP（Docker 里用 `docker exec gate-tunnel gate-manager status`，`socks` 模式显示为 `socks:端口`；单个槽位的日志在容器内 `/var/log/gate/slot-K.log`）
- 查看日志：`journalctl -u gate-manager -n 50`、`journalctl -u gate-xray -n 50`

### 某个节点连不上
对应槽位背后的 VPN Gate 节点可能刚失效，等约 1 分钟 gate-manager 会自动换新；也可以在 VPS 上手动运行 `gate-manager sync`。

### WARP 节点连不上
- `cat /etc/gate/warp.json` 确认已注册；没有这个文件时重新运行 `install.sh`
- `journalctl -u gate-xray -n 50` 查看 wireguard 报错；VPS 所在网络封了 UDP 2408 时，把 `warp.json` 里 `endpoint` 的端口改成 `500`、`1701` 或 `4500`，然后执行 `gate-manager xray-config > /usr/local/etc/xray/config.json && systemctl restart gate-xray`
- 想换一个 WARP 设备：删除 `/etc/gate/warp.json` 后重新运行 `install.sh`（设置了 `GATE_WARP_B64` 的话也要一并更新或去掉）

### 节点没有更新
到 Actions 页看最近一次运行是否成功。GitHub 定时任务本身会延迟几分钟到半小时，属正常现象。公开仓库 60 天没有任何提交时，GitHub 会自动暂停定时任务，需要到 Actions 页重新启用。

### 检测全部失败
检测器是仓库内置的 Node.js 脚本（`sstp_check.mjs`），随 Actions 运行，不依赖任何需要自己部署的外部服务。先看 Actions 日志里 `SSTP CHECK` 一节的逐节点失败原因；若全部节点都是同一种错误（如运行环境网络问题），换时间重跑一次再判断。

### 部分节点可用但没有出口 IP
检测时经隧道访问 iplocate.io 读取出口信息。VPN Gate 的 `public-vpn-*` 节点共用少量出口 IP，常被 iplocate 限流（HTTP 429）。能收到 429 说明隧道已经端到端打通，这类节点仍记为可用，只是出口 IP 留空，住宅/机房按主机名判断。

### 本地运行检测全部 `TCP handshake through SSTP timed out`
检测器用本机 DNS 解析 `www.iplocate.io`。如果本机开着 Clash、Surge 等 fake-ip 模式的代理，解析结果会是 `198.18.x.x` 这种假地址，经 VPN Gate 隧道发过去自然没有回应。关掉代理的 fake-ip 模式，或在 GitHub Actions 上运行即可。

---

## 致谢

| 项目 | 用途 |
| :--- | :--- |
| [hezhanleiok/gate](https://github.com/hezhanleiok/gate) | 本项目的原始项目：节点抓取、检测与 GitHub Pages 发布流程 |
| [VPN Gate](https://www.vpngate.net/) | SSTP 节点数据源 |
| [lsh8848/cm-Workers-CheckSocks5](https://github.com/lsh8848/cm-Workers-CheckSocks5) | 早期版本的检测 Worker；`sstp_check.mjs` 沿用了它的结果格式，检测现已改为仓库内置，不再依赖 Cloudflare Worker |
| [fdciabdul/Vpngate-Scraper-API](https://github.com/fdciabdul/Vpngate-Scraper-API) | VPN Gate 节点数据的 GitHub 镜像（官方源失效时回退） |
| [sstp-client](https://sourceforge.net/projects/sstp-client/) | Linux SSTP 客户端 |
| [Xray-core](https://github.com/XTLS/Xray-core) | VLESS 服务端 |
