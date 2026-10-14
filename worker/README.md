# gate-worker：VLESS → SSTP 精简中转 Worker

替代 edgetunnel 的精简版，单文件约 650 行，只做两件事：

1. **订阅**：`GET https://你的Worker域名/<UUID>` → 读取 `nodes.txt`，输出 base64 的 `vless://` 订阅
2. **中转**：VLESS over WebSocket 入站 → 与 VPN Gate 节点完成 SSTP 握手 → 转发流量

~~~text
客户端 —VLESS/WS/TLS→ 优选域名(Cloudflare) → gate-worker —SSTP→ VPN Gate 家宽节点 → 目标网站
~~~

节点信息写在 WebSocket 路径里（`/sstp/vpn:vpn@节点:端口`），Worker 不需要存储任何节点数据；`nodes.txt` 每 30 分钟更新，客户端刷新订阅即可拿到新节点。

## 部署（Cloudflare 控制台）

1. Cloudflare 控制台 → **Workers 和 Pages** → **创建** → **创建 Worker**，起名如 `gate-worker`，点 **部署**
2. 点 **编辑代码**，把 [`_worker.js`](./_worker.js) 全部内容粘贴进去，点 **部署**
3. **设置 → 变量和机密**，添加：

   | 名称 | 类型 | 值 |
   | :--- | :--- | :--- |
   | `UUID` | 密钥（Secret） | 任意 UUID，可用 https://www.uuidgenerator.net/ 生成 |
   | `NODES_URL` | 文本 | `https://你的GitHub用户名.github.io/gate/nodes.txt` |
   | `HOST` | 文本（可选） | 订阅里的 sni/host，默认取访问订阅时的域名 |

4. （推荐）**设置 → 域和路由** 绑定自定义域名
5. 客户端添加订阅：`https://你的Worker域名/你的UUID`

> `UUID` 就是访问凭证：订阅地址和每个 vless 节点都包含它，不要公开分享订阅链接。

## 部署（wrangler 命令行）

~~~bash
cd worker
# 修改 wrangler.toml 里的 NODES_URL
npx wrangler secret put UUID
npx wrangler deploy
~~~

## 支持范围

- 只输出通用 `vless://` 链接（v2rayN / v2rayNG / Shadowrocket / sing-box / Clash Meta 等可直接导入）
- 只支持 TCP 和 IPv4 目标；UDP 只支持 DNS（53 端口），改走 DoH
- SSTP 隧道内是极简 TCP 实现（无重传、固定 64KB 窗口），单连接速度上限约为 64KB ÷ Worker 到节点的往返延迟，实际还受 VPN Gate 节点带宽影响；丢包时连接会直接断开而不是变慢。适合网页浏览，不适合大文件下载
- 每条新连接都要重新做 SSTP/PPP 多轮握手，首包会有明显延迟（几秒），具体取决于 Worker 到节点的往返延迟

## 许可证

`sstpConnect()` 改编自 [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)（GPL-2.0），本目录同样以 [GPL-2.0](./LICENSE) 发布。
