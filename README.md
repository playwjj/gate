# VPN Gate SSTP 家宽节点 🚀

自动抓取 [VPN Gate](https://www.vpngate.net/) 的 SSTP 家宽/机房节点，逐个验证可用性，按国家分组、标注住宅/机房，再通过自建的 Cloudflare Worker 转成 VLESS 订阅。**每 30 分钟自动更新一次。**

> VPN Gate 的 SSTP 节点更新快，手动测试筛选太痛苦。本仓库把它全自动了：客户端只需添加一次订阅，之后刷新订阅就能拿到最新的可用节点。

---

## 架构

~~~text
VPN Gate 官方源
      │  GitHub Actions 每 30 分钟定时抓取
      ▼
筛选 SSTP 节点 → 去重
      │
      ▼
检测 Worker（Cloudflare）
      │  GET /check?sstp=vpn:vpn@host:port → 是否可用 + 出口 IP（住宅/机房判定）
      ▼
保留可用节点 → 按国家分组 → 住宅/机房标注 → 延迟排序
      │
      ▼
生成 nodes.txt + 节点网页（GitHub Pages 发布，公开、不含任何密钥）
      │
      ▼
gate-worker（Cloudflare，本仓库 worker/ 目录）
      │  GET /<UUID>  拉取 nodes.txt → 输出 vless 订阅
      │  WS  /sstp/…  VLESS 入站 → SSTP 握手 → 转发流量
      ▼
客户端订阅 → 使用 VPN Gate 家宽节点
~~~

使用时的流量路径：

~~~text
客户端 —VLESS/WS/TLS→ 优选域名(Cloudflare) → gate-worker —SSTP→ VPN Gate 节点 → 目标网站
~~~

---

## 部署教程

### 前置条件

- 一个 Cloudflare 账号（免费即可）
- 一个 GitHub 账号
- 一个已接入 Cloudflare 的域名（可选，推荐）

### 第 1 步：部署检测 Worker

1. 打开 https://github.com/lsh8848/cm-Workers-CheckSocks5
2. Cloudflare 控制台 → **Workers 和 Pages** → **创建** → **创建 Worker**
3. 把 `_worker.js` 的全部内容粘贴进编辑器，点 **部署**
4. 记下 Worker 地址，形如 `https://check-sstp.你的用户名.workers.dev`
5. 验证：浏览器打开 `https://你的检测Worker域名/check?sstp=vpn:vpn@任意节点:端口`，能返回 JSON 即成功

### 第 2 步：Fork 本仓库

在 GitHub 上打开本仓库，点 **Fork**，复制到你的账号下。

### 第 3 步：配置 Secret

检测 Worker 地址保存在 GitHub Secrets 里，防止公开后被别人盗用额度。**不需要修改任何代码或工作流文件。**

1. 进入你 Fork 后的仓库 → **Settings** → **Secrets and variables → Actions** → **Secrets** 标签页
2. 点 **New repository secret**：
   - **Name**：`CHECK_WORKER`（必须完全一致）
   - **Secret**：完整检测链接，例如 `https://check-sstp.你的用户名.workers.dev/check?sstp=vpn:vpn@`
3. 点 **Add secret** 保存

> 未设置 `CHECK_WORKER` 时，工作流会直接失败并提示添加。Secret 的值在 Actions 日志里显示为 `***`，也不会写入公开的网页数据。

### 第 4 步：开启 GitHub Pages 与 Actions

1. 仓库 → **Settings → Pages**，**Source** 选 **GitHub Actions**（选中即生效，没有保存按钮；不要点下方推荐工作流的 Configure）
2. 进 **Actions** 页，若提示启用 Actions 就点启用
3. 手动运行一次：**Actions → VPN Gate Node Check → Run workflow**
4. 跑完看到绿色 ✓ 即成功，之后每 30 分钟自动运行

运行记录最后一步 **Show site URL** 会显示实际地址，一般是：

~~~text
https://你的GitHub用户名.github.io/仓库名/            ← 节点网页
https://你的GitHub用户名.github.io/仓库名/nodes.txt   ← 节点清单
~~~

### 第 5 步：部署 gate-worker（VLESS 中转 + 订阅）

1. Cloudflare 控制台 → **Workers 和 Pages** → **创建** → **创建 Worker**，起名如 `gate-worker`，点 **部署**
2. 点 **编辑代码**，把 [`worker/_worker.js`](./worker/_worker.js) 的全部内容粘贴进去，点 **部署**
3. **设置 → 变量和机密**，添加：

   | 名称 | 类型 | 值 |
   | :--- | :--- | :--- |
   | `UUID` | 密钥 | 任意 UUID，可用 https://www.uuidgenerator.net/ 生成 |
   | `NODES_URL` | 文本 | 第 4 步得到的 `nodes.txt` 地址 |
   | `HOST` | 文本（可选） | 订阅里的 sni/host，默认取访问订阅时的域名 |

4. （推荐）**设置 → 域和路由** 绑定自定义域名

命令行部署方式见 [worker/README.md](./worker/README.md)。

### 第 6 步：客户端添加订阅

订阅地址：

~~~text
https://你的gate-worker域名/你的UUID
~~~

支持导入 `vless://` 链接的客户端都可以用，例如 v2rayN、v2rayNG、Shadowrocket、sing-box、Clash Meta。之后**刷新订阅**即可拿到最新节点。

> UUID 就是访问凭证：订阅地址和每个节点都包含它，不要公开分享订阅链接。

---

## 配置速查表

**GitHub 仓库** Settings → Secrets and variables → Actions：

| 名称 | 类型 | 说明 |
| :--- | :--- | :--- |
| `CHECK_WORKER` | Secret（必填） | 检测 Worker 地址，形如 `https://xxx.workers.dev/check?sstp=vpn:vpn@` |
| `NODES_URL` | Variable（可选） | nodes.txt 的发布地址，只用于日志提示；给 Pages 绑定自定义域名时设置，否则自动推导 |

**gate-worker** 设置 → 变量和机密：

| 名称 | 说明 |
| :--- | :--- |
| `UUID` | 必填，VLESS 用户 ID，同时是订阅路径 |
| `NODES_URL` | 必填，nodes.txt 地址 |
| `HOST` | 可选，订阅里的 sni/host |

**vpngate.py**（一般不用改，也可以用同名环境变量覆盖）：

| 常量 / 环境变量 | 说明 |
| :--- | :--- |
| `EDGE_HOSTS` | 入口优选域名列表，逗号分隔，格式 `域名:443` |
| `OPTIMAL_API` | 优选 IP API，结果会和 `EDGE_HOSTS` 合并 |
| `CHECK_CONCURRENCY` | 检测并发数，默认 32 |
| `CHECK_TIMEOUT` | 单个节点检测超时（秒），默认 90 |
| `MAX_CHECK_NODES` | 最多检测的节点数，默认 0（不限） |

---

## 更换优选域名

`nodes.txt` 每行的入口地址是「优选域名」，决定客户端连 Cloudflare 时用哪个 IP、稳不稳。

1. 用测速工具（如 bestcf）测一批 Cloudflare 优选域名，挑延迟低、实际能连通的
2. 打开 `vpngate.py`，把 `EDGE_HOSTS` 换成你测出来的域名（格式 `域名:443`）
3. 提交推送，等下一次自动运行或手动触发 Action

---

## 支持范围与限制

- 只输出 `vless://` 链接（VLESS + WebSocket + TLS）
- 只支持 TCP 和 IPv4 目标；UDP 只支持 DNS（53 端口），由 Worker 改走 DoH
- SSTP 隧道内是极简 TCP 实现（无重传、固定窗口），速度受 VPN Gate 节点带宽限制，本地实测约 60 KB/s，适合网页浏览，不适合大文件下载
- 每条新连接都要重新做 SSTP 握手，首包延迟约 5–8 秒
- VPN Gate 是志愿者节点，个别节点随时可能下线，换一个节点或刷新订阅即可

---

## 常见问题

### 只有几个节点能连
入口优选域名大部分不通。用 bestcf 重新测速，把 `EDGE_HOSTS` 换成实测能通的域名。

### 所有节点都连不上
- 订阅地址里的 UUID 是否和 gate-worker 的 `UUID` 一致
- gate-worker 的 `NODES_URL` 是否能在浏览器打开
- 先在浏览器打开订阅地址，能看到一串 base64 文本说明 Worker 正常
- 在 Cloudflare 控制台 → gate-worker → **日志** 查看具体报错（如 `UUID 不匹配`、`TCP handshake through SSTP timed out`）

### 节点没有更新
到 Actions 页看最近一次运行是否成功。GitHub 定时任务本身会延迟几分钟到半小时，属正常现象。公开仓库 60 天没有任何提交时，GitHub 会自动暂停定时任务，需要到 Actions 页重新启用。

### 检测 Worker 报错
确认检测 Worker 部署成功、仓库 Secret `CHECK_WORKER` 填对，浏览器直接访问 `https://你的检测Worker/check?sstp=...` 看是否返回 JSON。

---

## 致谢

| 项目 | 用途 |
| :--- | :--- |
| [VPN Gate](https://www.vpngate.net/) | SSTP 节点数据源 |
| [lsh8848/cm-Workers-CheckSocks5](https://github.com/lsh8848/cm-Workers-CheckSocks5) | 检测 Worker：验证 SSTP 节点可用性并读取出口 IP |
| [fdciabdul/Vpngate-Scraper-API](https://github.com/fdciabdul/Vpngate-Scraper-API) | VPN Gate 节点数据的 GitHub 镜像（官方源失效时回退） |
| [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) | gate-worker 的 SSTP 握手代码改编自此项目 |

## 许可证

`worker/` 目录以 [GPL-2.0](./worker/LICENSE) 发布。
