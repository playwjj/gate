# VPNGate SSTP 家宽节点（edgetunnel 链式代理） 🚀

自动抓取 [VPN Gate](https://www.vpngate.net/) 的 SSTP 家宽/机房节点，调用检测 Worker 逐个验证可用性，按国家分组、标注住宅/机房，生成可直接通过 **URL 自动轮换** 的节点清单。**每 30 分钟自动更新一次。**

> 核心价值：VPN Gate 的 SSTP 节点 30 分钟就换一批，手动测试筛选太痛苦。本仓库把它全自动了——你只需把 `nodes.txt` 的网址填进 edgetunnel 后台一次，之后节点每 30 分钟自动换，零手动。

---

## 架构（数据流向）

~~~text
VPN Gate 官方源
      │  (每 30 分钟，GitHub Actions 定时抓取)
      ▼
筛选 SSTP 节点 → 去重
      │
      ▼
检测 Worker (CheckSocks5，部署在 Cloudflare)
      │  GET /check?sstp=vpn:vpn@host:port
      │  返回 success + 出口 IP(住宅/机房判定)
      ▼
保留成功节点 → 按国家分组 → 住宅/机房标注 → 延迟排序
      │
      ▼
生成 nodes.txt (GitHub Pages 发布)
      │
      ▼
edgetunnel 后台「自定义优选IP」框填 https://…/nodes.txt
      │  edgetunnel 每次生成订阅时自动 fetch → 解析 $sstp:// → 套链式代理
      ▼
客户端订阅 edgetunnel 订阅 → 使用 SSTP 家宽节点 (每 30 分钟自动换)
~~~

---

## 一、完整部署教程（从零开始）

### 前置条件
- 一个 Cloudflare 账号（免费即可）
- 一个 GitHub 账号
- 一个已转入 Cloudflare 的域名（可选，但强烈推荐）

### 第 1 步：部署 edgetunnel（核心使用端）

1. 登录 Cloudflare 控制台，点击左侧 **Workers 和 Pages**
2. 点击 **创建** → 选择 **创建 Worker**，起名 `edgetunnel`，点击 **部署**
3. 打开 https://github.com/cmliu/edgetunnel/blob/main/_worker.js ，复制全部代码
4. 回到 Cloudflare Worker 编辑器，粘贴代码，点击 **保存并部署**
5. 在 **设置** → **变量** 中，添加变量 `ADMIN`，值填你的管理员密码
6. 在 **绑定** 中，添加 KV 命名空间绑定，变量名称填 `KV`
7. （推荐）在 **触发器** 中绑定自定义域名
8. 浏览器访问 `https://你的域名/admin`，登录后台
9. **在后台首页记下你的 UUID 和节点域名**（后面要用）

> **关键**：`UUID` 和 `节点域名` 是 edgetunnel 自己的配置，**不需要**在 `vpngate.py` 中设置。`vpngate.py` 只负责生成 `nodes.txt`，edgetunnel 会用它自己的 UUID/域名去生成最终订阅。

### 第 2 步：部署检测 Worker（CheckSocks5）

1. 打开 https://github.com/lsh8848/cm-Workers-CheckSocks5 ，点 **Fork**
2. 进 Cloudflare 控制台 → Workers 和 Pages → 创建 → 创建 Worker
3. 把 `_worker.js` 的全部内容粘贴进编辑器，点「部署」
4. 记下这个 Worker 的域名，形如 `https://xxx.你的用户名.workers.dev`
5. 验证：浏览器打开 `https://你的Worker域名/check?sstp=vpn:vpn@任意节点:端口` ，能返回 JSON 即成功

### 第 3 步：Fork 本仓库

在 GitHub 上打开本仓库，点 **Fork**，复制到你账号下。

### 第 4 步：配置 Secret 密钥（重点）

为了防止检测 Worker 地址公开后被别人盗用、刷爆额度，检测地址保存在 GitHub Secrets（隐藏密钥）里，工作流自动读取，**不需要修改任何代码或工作流文件**。

1. 进入你 Fork 后的仓库，点击顶部菜单的 **Settings**
2. 左侧边栏依次点击 **Secrets and variables → Actions**，停留在 **Secrets** 标签页
3. 点击绿色按钮 **New repository secret**：
   - **Name**：`CHECK_WORKER`（必须完全一致）
   - **Secret**：第 2 步得到的完整检测 Worker 链接，例如 `https://check-sstp.你的用户名.workers.dev/check?sstp=vpn:vpn@`
4. 点击 **Add secret** 保存

> 未设置 `CHECK_WORKER` 时，工作流会直接失败并提示你添加。Secret 的值在 Actions 日志里会显示为 `***`，也不会写入公开的 `data.json`。

**（可选）自定义域名**：如果给 GitHub Pages 绑定了自定义域名，可在同一页面的 **Variables** 标签页新建变量 `NODES_URL`，值为 `https://你的域名/nodes.txt`。不设置则自动推导为 `https://你的用户名.github.io/仓库名/nodes.txt`。

> **注意**：`vpngate.py` 中**不需要**配置 `EDT_UUID` 和 `EDT_DOMAIN`。你之前看到的这两个变量是旧版遗留，现已删除。edgetunnel 后台会自己处理 UUID 和域名。

### 第 5 步：开启 GitHub Pages 与 Actions

1. 进你 fork 的仓库 → Settings → Pages，Source 设为 **GitHub Actions**
2. 进 Actions 页，若提示启用 Actions 就点启用
3. 手动触发一次：Actions → VPN Gate Node Check → Run workflow → Run workflow
4. 等它跑完（约 1 分钟），看到绿色 ✓ 即成功

### 第 6 步：确认产物

跑完后，在 Actions 运行记录的最后一步 **Show site URL** 能看到实际地址，一般是：
~~~text
https://你的GitHub用户名.github.io/仓库名/nodes.txt
~~~
浏览器打开，能看到一堆 `优选域名:443#国家-住宅-XX …` 的行，就说明全部打通了。

---

## 二、使用教程（URL 自动轮换，一次配置永久生效）

1. 进 edgetunnel 后台（你的域名/admin），找到「自定义优选IP」文本框
2. 粘贴**一行网址**：
   ~~~text
   https://你的GitHub用户名.github.io/仓库名/nodes.txt
   ~~~
3. 点保存
4. 客户端刷新订阅 → 每次刷新 edgetunnel 都重新拉取一次 nodes.txt，节点自动更新

> 原理：`nodes.txt` 是纯节点行版本（无注释头），每行 `入口域名:443#国家-住宅-01$sstp://vpn:vpn@节点:端口`。edgetunnel 下次生成订阅时会 fetch 这个网址、逐行解析成优选入口 + 链式代理指令。你只填一次，之后节点每 30 分钟自动换、零手动。

---

## 三、如何更换优选域名

入口地址用的是「优选域名」，决定客户端连 Cloudflare 用哪个 IP、稳不稳。

### 在哪个文件改
- 文件：vpngate.py
- 位置：`EDGE_HOSTS = [ ... ]`

### 改法
1. 用测速工具（如 bestcf）测一批 Cloudflare 优选域名，挑「延迟低 + 实际能连通」的
2. 打开 vpngate.py，把 `EDGE_HOSTS` 里的域名列表换成你测出来的（逗号分隔，格式 `域名:443`）
3. 提交推送，等下一次自动运行或手动触发 Action

---

## 四、配置速查表

GitHub 仓库 Settings → Secrets and variables → Actions：

| 名称 | 类型 | 说明 |
| :--- | :--- | :--- |
| `CHECK_WORKER` | Secret（必填） | 检测 Worker 地址，形如 `https://xxx.workers.dev/check?sstp=vpn:vpn@` |
| `NODES_URL` | Variable（可选） | nodes.txt 的发布地址，仅用于日志提示；绑定自定义域名时设置，否则自动推导 |

vpngate.py：

| 常量 | 说明 |
| :--- | :--- |
| `EDGE_HOSTS` | 入口优选域名（换域名改这里） |
| `WORKER_CHECK_URL` | 检测 Worker，读取环境变量 `CHECK_WORKER`（Action 里来自仓库 Secret；本地运行时自行设置环境变量） |
| `NODES_URL` | nodes.txt 的发布地址，仅用于日志提示。根据 `GITHUB_REPOSITORY` 自动推导，可用仓库 Variable `NODES_URL` 覆盖 |

> 再次强调：`vpngate.py` **不需要**配置 `EDT_UUID` 和 `EDT_DOMAIN`，这两个参数属于 edgetunnel 本身。

---

## 五、常见问题

### 只有几个节点能连
入口优选域名大部分被墙。用 bestcf 重新测速，把 `EDGE_HOSTS` 换成实测能通的域名。

### 全部 -1
检查：edgetunnel 是否部署好、域名是否解析到 Cloudflare、UUID 是否填对、传输协议是否对得上。

### 30 分钟没更新
到 Actions 页看最近一次运行是否成功、cron 是否还在。

### 检测 Worker 报错
确认 Worker 部署成功、域名填对（仓库 Secret `CHECK_WORKER`），浏览器直接访问 `https://你的Worker/check?sstp=...` 看是否返回 JSON。

### 不知道 UUID 和节点域名在哪里看
登录 edgetunnel 后台（`https://你的域名/admin`），在后台首页就能看到。

---

*流水线：GitHub Actions（每 30 分钟 cron） → vpngate.py → 检测 Worker → GitHub Pages*

---

## 引用与致谢

本项目的实现离不开以下开源项目和服务的支持，在此表示衷心的感谢：

| 项目 | 用途 | 链接 |
| :--- | :--- | :--- |
| **cmliu/edgetunnel** | VLESS 代理 + 链式代理，节点最终通过它使用 | https://github.com/cmliu/edgetunnel |
| **lsh8848/cm-Workers-CheckSocks5** | 检测 Worker：验证 SSTP 节点可用性并读取出口 IP | https://github.com/lsh8848/cm-Workers-CheckSocks5 |
| **fdciabdul/Vpngate-Scraper-API** | VPN Gate 节点数据的 GitHub 镜像（官方源失效时回退） | https://github.com/fdciabdul/Vpngate-Scraper-API |
| **VPN Gate** | SSTP 节点数据源 | https://www.vpngate.net/ |
| **Star History** | 提供项目热度曲线图生成服务 | https://star-history.com/ |

---

## 项目热度

[![Star History Chart](https://api.star-history.com/svg?repos=hezhanleiok/gate&type=Date)](https://star-history.com/#hezhanleiok/gate&Date)

---

**特别感谢**：
感谢所有为开源社区做出贡献的开发者们！没有你们的无私奉献，就没有这个项目的诞生。也感谢每一位使用、测试和反馈问题的用户，是你们的支持让这个项目不断完善。
