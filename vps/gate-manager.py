#!/usr/bin/env python3
"""
gate-manager: 在 VPS 上维护 N 个 SSTP 槽位, 并生成 xray / nginx 配置和订阅

槽位有两种实现 (gate.env 里的 SSTP_MODE):
  ppp    sstpc + pppd, 每个槽位一个内核网卡 pppK, xray 绑定网卡出站 (需要 /dev/ppp 和 NET_ADMIN)
  socks  sstp-socks (用户态 SSTP + gVisor 网络栈), 每个槽位一个本地 SOCKS5 端口 SOCKS_BASE+K,
         xray 经 SOCKS5 出站; 不需要任何特权, 只支持 run 模式 (容器)

用法:
  gate-manager sync           检查各槽位, 坏掉的从 nodes.txt 换新节点, 更新订阅 (systemd timer 定时调用)
  gate-manager run            容器模式: 没有 systemd, 由本进程直接管理 sstpc, 每分钟 sync 一次
  gate-manager status         打印各槽位状态
  gate-manager xray-config    输出 xray 配置 JSON
  gate-manager nginx-config   输出 nginx 站点配置
  gate-manager warp-register  注册 Cloudflare WARP 设备, 生成 WARP 槽位用的 WireGuard 配置 (已有则跳过)

配置读取 /etc/gate/gate.env (由 install.sh 或容器入口脚本生成)
"""
import base64
import datetime
import json
import os
import random
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor

ENV_FILE = "/etc/gate/gate.env"
STATE_FILE = "/var/lib/gate/state.json"
SUB_FILE = "/var/lib/gate/sub.txt"
WARP_FILE = "/etc/gate/warp.json"
WARP_REG_URL = "https://api.cloudflareclient.com/v0a2158/reg"
WARP_PEER_PORT = 2408
WS_PATH = "/ws"
PROBE_URL = "http://cp.cloudflare.com/generate_204"
BAD_NODE_TTL = 3600  # 连接失败的节点 1 小时内不再尝试
CONNECT_WAIT = 30
SYNC_INTERVAL = 60
LOG_DIR = "/var/log/gate"

# run 模式下 sstpc / sstp-socks 是本进程的子进程, 不经过 systemd 的 gate-slot@ 单元
INLINE = False
SSTPC = {}
SOCKS_MODE = False
SOCKS_BASE = 21080


def log(msg):
    print(f"[gate] {msg}", flush=True)


def load_config():
    cfg = {}
    with open(ENV_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                cfg[key.strip()] = value.strip().strip('"').strip("'")
    cfg["SLOTS"] = int(cfg.get("SLOTS", "8"))
    cfg["XRAY_PORT"] = int(cfg.get("XRAY_PORT", "10086"))
    cfg["WARP"] = cfg.get("WARP", "1") == "1"
    cfg["SSTP_MODE"] = cfg.get("SSTP_MODE", "ppp")
    cfg["SOCKS_BASE"] = int(cfg.get("SOCKS_BASE", "21080"))
    global SOCKS_MODE, SOCKS_BASE
    SOCKS_MODE, SOCKS_BASE = cfg["SSTP_MODE"] == "socks", cfg["SOCKS_BASE"]
    return cfg


def slot_uuid(master, k):
    return str(uuid.uuid5(uuid.UUID(master), f"slot{k}"))


# ---------------------------------------------------------------------------
# 节点
# ---------------------------------------------------------------------------
NODE_RE = re.compile(r"#([^$]+)\$sstp://(?:([^:@]+):([^@]*)@)?([^:\s]+):(\d+)")


def fetch_nodes(url):
    """返回 nodes.txt 里的节点列表"""
    with urllib.request.urlopen(url, timeout=30) as resp:
        text = resp.read().decode("utf-8", "replace")
    nodes = []
    for line in text.splitlines():
        m = NODE_RE.search(line)
        if m:
            name, user, password, host, port = m.groups()
            nodes.append({
                "name": re.sub(r"-\d+$", "", name.strip()),  # 韩国-住宅-03 → 韩国-住宅
                "node": f"{host}:{port}",
                "user": user or "vpn",
                "password": password or "vpn",
            })
    return nodes


def order_candidates(nodes, seed=""):
    """住宅优先, 各国家轮流取, 让槽位尽量覆盖不同国家

    seed 非空时按它打乱国家顺序和各国家内的节点顺序 (同一个 seed 结果固定),
    多台机器设不同的 GATE_NODE_SEED 就会优先连不同的节点
    """
    rng = random.Random(seed) if seed else None

    def interleave(items):
        buckets = {}
        for n in items:
            buckets.setdefault(n["name"].split("-")[0], []).append(n)
        if rng:
            buckets = dict(rng.sample(list(buckets.items()), len(buckets)))
            for bucket in buckets.values():
                rng.shuffle(bucket)
        out = []
        while any(buckets.values()):
            for country in list(buckets):
                if buckets[country]:
                    out.append(buckets[country].pop(0))
        return out
    residential = [n for n in nodes if "住宅" in n["name"]]
    others = [n for n in nodes if "住宅" not in n["name"]]
    return interleave(residential) + interleave(others)


# ---------------------------------------------------------------------------
# WARP 槽位: xray 用 WireGuard 直连 Cloudflare WARP, 不经过 SSTP
# ---------------------------------------------------------------------------
def x25519_public_key(private):
    """RFC 7748 X25519 标量乘基点, 免得依赖 wireguard-tools / cryptography"""
    p = 2**255 - 19
    k = bytearray(private)
    k[0] &= 248
    k[31] = (k[31] & 127) | 64
    n = int.from_bytes(k, "little")
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for t in reversed(range(255)):
        bit = (n >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b, c, d = x2 + z2, x2 - z2, x3 + z3, x3 - z3
        aa, bb, da, cb = a * a, b * b, d * a, c * b
        e = aa - bb
        x3, z3 = (da + cb) ** 2 % p, x1 * (da - cb) ** 2 % p
        x2, z2 = aa * bb % p, e * (aa + 121665 * e) % p
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def warp_import(b64):
    """复用已有的 WARP 设备 (GATE_WARP_B64 = base64 的 warp.json), 成功返回 True"""
    try:
        warp = json.loads(base64.b64decode(b64))
        for key in ("private_key", "peer_public_key", "endpoint", "address", "reserved"):
            warp[key]
    except (ValueError, KeyError, TypeError):
        log("GATE_WARP_B64 无法解析, 改为注册新的 WARP 设备")
        return False
    fd = os.open(WARP_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(warp, f, indent=1)
    log("复用 GATE_WARP_B64 中的 WARP 设备")
    return True


def warp_register():
    if os.path.exists(WARP_FILE):
        log(f"WARP 已注册 ({WARP_FILE}), 跳过")
        return
    if os.environ.get("GATE_WARP_B64") and warp_import(os.environ["GATE_WARP_B64"]):
        return
    private = bytearray(os.urandom(32))
    private[0] &= 248
    private[31] = (private[31] & 127) | 64
    body = json.dumps({
        "key": base64.b64encode(x25519_public_key(private)).decode(),
        "install_id": "", "fcm_token": "", "model": "PC", "serial_number": "", "locale": "en_US",
        "tos": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }).encode()
    req = urllib.request.Request(WARP_REG_URL, data=body, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": "okhttp/3.12.1", "CF-Client-Version": "a-6.10-2158",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        conf = json.load(resp)["config"]
    peer, addresses = conf["peers"][0], conf["interface"]["addresses"]
    warp = {
        "private_key": base64.b64encode(private).decode(),
        "peer_public_key": peer["public_key"],
        # 用 IP 而不是 engage.cloudflareclient.com, 不依赖 DNS; 端口可改成 500/1701/4500
        "endpoint": f"{peer['endpoint']['v4'].rsplit(':', 1)[0]}:{WARP_PEER_PORT}",
        "address": [f"{addresses['v4']}/32", f"{addresses['v6']}/128"],
        "reserved": list(base64.b64decode(conf["client_id"])),
    }
    fd = os.open(WARP_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(warp, f, indent=1)
    log(f"WARP 注册成功: {warp['address'][0]} via {warp['endpoint']}")


def load_warp(cfg):
    if not cfg["WARP"]:
        return None
    try:
        with open(WARP_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# 槽位
# ---------------------------------------------------------------------------
def socks_status_file(k):
    return f"/var/lib/gate/slot-{k}.json"


def slot_ip(k):
    """槽位拿到的 VPN Gate 内网 IP, 隧道没建立时返回 None"""
    if not SOCKS_MODE:
        return ppp_ip(k)
    # sstp-socks 连接成功后写状态文件, 退出时删除; 进程被 kill -9 时文件会残留, 所以还要看进程在不在
    try:
        with open(socks_status_file(k), encoding="utf-8") as f:
            st = json.load(f)
        os.kill(st["pid"], 0)
        if INLINE and (k not in SSTPC or SSTPC[k].poll() is not None):
            return None
        return st["ip"]
    except (OSError, ValueError, KeyError):
        return None


def ppp_ip(k):
    out = subprocess.run(["ip", "-4", "-o", "addr", "show", f"ppp{k}"], capture_output=True, text=True).stdout
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def probe(k):
    via = ["--socks5-hostname", f"127.0.0.1:{SOCKS_BASE + k}"] if SOCKS_MODE else ["--interface", f"ppp{k}"]
    result = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "10", *via, PROBE_URL],
        capture_output=True, text=True,
    )
    return result.stdout.strip() == "204"


def slot_healthy(k):
    # 探测失败再试一次: 一次偶发超时就换掉节点并拉黑 1 小时太亏
    return slot_ip(k) is not None and (probe(k) or probe(k))


def stop_slot(k):
    if not INLINE:
        subprocess.run(["systemctl", "stop", f"gate-slot@{k}"], capture_output=True)
        return
    proc = SSTPC.pop(k, None)
    if proc:
        # sstpc 在自己的进程组里, 连同它拉起的 pppd 一起结束
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(10)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        except ProcessLookupError:
            proc.wait()
    if SOCKS_MODE:
        try:
            os.remove(socks_status_file(k))
        except OSError:
            pass
        return
    # pppd 可能脱离了 sstpc 的进程组, 按 pid 文件补刀, 否则 pppK 一直被占用
    try:
        with open(f"/var/run/ppp{k}.pid", encoding="utf-8") as f:
            pid = int(f.read().split()[0])
        with open(f"/proc/{pid}/comm", encoding="utf-8") as f:
            if f.read().strip() == "pppd":
                os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError, IndexError):
        pass


def start_slot(k, node):
    if INLINE:
        stop_slot(k)
        if SOCKS_MODE:
            cmd = ["sstp-socks", "-server", node["node"], "-user", node["user"], "-pass", node["password"],
                   "-listen", f"127.0.0.1:{SOCKS_BASE + k}", "-status", socks_status_file(k),
                   "-timeout", f"{CONNECT_WAIT}s"]
        else:
            # 参数和 install.sh 里 gate-slot@.service 的 ExecStart 保持一致
            cmd = ["sstpc", "--log-stderr", "--cert-warn", "--tls-ext", "--user", node["user"],
                   "--password", node["password"], node["node"], "noauth", "nodefaultroute",
                   "noipdefault", "nodetach", "unit", str(k), "refuse-eap"]
        with open(f"{LOG_DIR}/slot-{k}.log", "w", encoding="utf-8") as logf:
            SSTPC[k] = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=logf, stderr=subprocess.STDOUT, start_new_session=True,
            )
    else:
        with open(f"/etc/gate/slot-{k}.env", "w", encoding="utf-8") as f:
            f.write(f"NODE={node['node']}\nSSTP_USER={node['user']}\nSSTP_PASS={node['password']}\n")
        subprocess.run(["systemctl", "restart", f"gate-slot@{k}"], capture_output=True)
    deadline = time.time() + CONNECT_WAIT
    while time.time() < deadline:
        if slot_ip(k):
            return probe(k)
        if INLINE and SSTPC[k].poll() is not None:
            return False
        time.sleep(1)
    return False


def slot_log_tail(k):
    """run 模式下槽位日志的最后一行, 用来说明连接失败的原因"""
    try:
        with open(f"{LOG_DIR}/slot-{k}.log", encoding="utf-8", errors="replace") as f:
            lines = [line.strip() for line in f if line.strip()]
        return f": {lines[-1]}" if lines else ""
    except OSError:
        return ""


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"slots": {}, "bad": {}}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)
    os.replace(tmp, STATE_FILE)


def sync(cfg):
    state = load_state()
    now = time.time()
    state["bad"] = {n: t for n, t in state.get("bad", {}).items() if now - t < BAD_NODE_TTL}
    slots = range(1, cfg["SLOTS"] + 1)

    # SLOTS=0 (没有 /dev/ppp 的平台) 时只有 WARP 槽位
    with ThreadPoolExecutor(max_workers=max(cfg["SLOTS"], 1)) as pool:
        health = dict(zip(slots, pool.map(slot_healthy, slots)))

    # VPN Gate 各服务器独立分配 10.211.x.x, 不同槽位偶尔会拿到相同 IP, 重复的视为不健康
    # (只影响 ppp 模式的内核路由; socks 模式每个槽位是独立的用户态网络栈, 不冲突)
    seen_ips = {}
    for k in slots:
        if health[k] and not SOCKS_MODE:
            ip = slot_ip(k)
            if ip in seen_ips:
                log(f"slot{k}: IP {ip} 与 slot{seen_ips[ip]} 重复, 重新分配")
                health[k] = False
            else:
                seen_ips[ip] = k

    state.pop("entries", None)

    broken = [k for k in slots if not health[k]]
    for k in slots:
        if health[k]:
            continue
        old = state["slots"].pop(str(k), None)
        if old:
            log(f"slot{k}: {old['node']} 已失效")
            state["bad"][old["node"]] = now
        stop_slot(k)

    if broken:
        try:
            all_nodes = fetch_nodes(cfg["NODES_URL"])
        except Exception as e:
            log(f"拉取 nodes.txt 失败: {e}")
            all_nodes = []
        nodes = order_candidates(all_nodes, cfg.get("NODE_SEED", ""))
        in_use = {s["node"] for s in state["slots"].values()}
        queue = [n for n in nodes if n["node"] not in in_use and n["node"] not in state["bad"]]
        lock = threading.Lock()

        def fill(k):
            for _ in range(4):
                with lock:
                    if not queue:
                        return
                    node = queue.pop(0)
                if start_slot(k, node):
                    with lock:
                        state["slots"][str(k)] = {"node": node["node"], "name": node["name"], "since": int(time.time())}
                    log(f"slot{k}: 已连接 {node['name']} {node['node']} ({slot_dev(k)} {slot_ip(k)})")
                    return
                with lock:
                    state["bad"][node["node"]] = time.time()
                reason = ": 隧道已建立, 但探测失败" if slot_ip(k) else slot_log_tail(k) if INLINE else ""
                log(f"slot{k}: {node['node']} 连接失败{reason}")
            stop_slot(k)

        with ThreadPoolExecutor(max_workers=len(broken)) as pool:
            list(pool.map(fill, broken))

    save_state(state)
    write_subscription(cfg, state)
    log(f"健康槽位 {len(state['slots'])}/{cfg['SLOTS']}")


def write_subscription(cfg, state):
    host = cfg["HOST"]
    params = urllib.parse.urlencode({
        "encryption": "none", "security": "tls", "sni": host, "fp": "chrome",
        "type": "ws", "host": host, "path": WS_PATH,
    })
    links = cfg.get("EXTRA_LINKS", "").split()  # 额外的固定节点 (如容器里 work-tunnel-vless 自己的节点), 空格分隔
    for k in range(1, cfg["SLOTS"] + 1):
        slot = state["slots"].get(str(k))
        remark = f"{k:02d}-{slot['name']}" if slot else f"{k:02d}-连接中"
        links.append(f"vless://{slot_uuid(cfg['UUID'], k)}@{host}:443?{params}#{urllib.parse.quote(remark)}")
    if load_warp(cfg):
        links.append(f"vless://{slot_uuid(cfg['UUID'], 'warp')}@{host}:443?{params}#WARP")
    os.makedirs(os.path.dirname(SUB_FILE), exist_ok=True)
    tmp = SUB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode())
    os.replace(tmp, SUB_FILE)


def slot_dev(k):
    return f"socks:{SOCKS_BASE + k}" if SOCKS_MODE else f"ppp{k}"


def run(cfg):
    global INLINE
    INLINE = True
    os.makedirs(LOG_DIR, exist_ok=True)

    def shutdown(*_):
        for k in list(SSTPC):
            stop_slot(k)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    while True:
        try:
            sync(cfg)
        except Exception as e:
            log(f"sync 出错: {e}")
        time.sleep(SYNC_INTERVAL)


def status(cfg):
    state = load_state()
    for k in range(1, cfg["SLOTS"] + 1):
        slot = state["slots"].get(str(k))
        ip = slot_ip(k)
        desc = f"{slot['name']} {slot['node']}" if slot else "-"
        print(f"slot{k}  {slot_dev(k)}={ip or 'down':<15} {desc}")
    warp = load_warp(cfg)
    print(f"warp   {warp['endpoint'] if warp else '未启用'}")


# ---------------------------------------------------------------------------
# 配置生成
# ---------------------------------------------------------------------------
def xray_config(cfg):
    slots = range(1, cfg["SLOTS"] + 1)
    clients = [{"id": slot_uuid(cfg["UUID"], k), "email": f"slot{k}"} for k in slots]
    if SOCKS_MODE:
        # 域名交给 sstp-socks 在隧道内解析
        outbounds = [{
            "tag": f"slot{k}",
            "protocol": "socks",
            "settings": {"servers": [{"address": "127.0.0.1", "port": SOCKS_BASE + k}]},
        } for k in slots]
    else:
        outbounds = [{
            "tag": f"slot{k}",
            "protocol": "freedom",
            "settings": {"domainStrategy": "UseIPv4"},
            "streamSettings": {"sockopt": {"interface": f"ppp{k}"}},
        } for k in slots]
    rules = [{"type": "field", "user": [f"slot{k}"], "outboundTag": f"slot{k}"} for k in slots]
    warp = load_warp(cfg)
    if warp:
        clients.append({"id": slot_uuid(cfg["UUID"], "warp"), "email": "warp"})
        outbounds.append({
            "tag": "warp",
            "protocol": "wireguard",
            "settings": {
                # 用户态 (gvisor) 实现: xray 有 CAP_NET_ADMIN 时默认会建内核 TUN 并改策略路由, 这里不需要
                "noKernelTun": True,
                "secretKey": warp["private_key"],
                "address": warp["address"],
                "peers": [{"publicKey": warp["peer_public_key"], "endpoint": warp["endpoint"], "keepAlive": 25}],
                "reserved": warp["reserved"],
                "mtu": 1280,
                "domainStrategy": "ForceIPv4",
            },
        })
        rules.append({"type": "field", "user": ["warp"], "outboundTag": "warp"})
    return {
        "log": {"loglevel": "warning"},
        # xray 内置 DNS 的查询也要过路由: 打上 tag 走 VPS 直连, 否则会落到默认的 block
        "dns": {"tag": "dns-internal", "servers": ["1.1.1.1", "8.8.8.8"], "queryStrategy": "UseIPv4"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": cfg["XRAY_PORT"],
            "protocol": "vless",
            "settings": {"clients": clients, "decryption": "none"},
            "streamSettings": {"network": "ws", "wsSettings": {"path": WS_PATH}},
        }],
        # 第一个 outbound 是默认出口: 没匹配到槽位的流量直接丢弃, 不会从 VPS 自己的 IP 出去
        "outbounds": [{"tag": "block", "protocol": "blackhole"}] + outbounds + [{"tag": "dns-direct", "protocol": "freedom"}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["dns-internal"], "outboundTag": "dns-direct"}] + rules},
    }


def nginx_config(cfg):
    return f"""server {{
    listen {cfg['LISTEN']}:{cfg['PORT']};
    server_name _;

    location = {WS_PATH} {{
        proxy_pass http://127.0.0.1:{cfg['XRAY_PORT']};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 1d;
        proxy_send_timeout 1d;
    }}

    location = /sub/{cfg['UUID']} {{
        default_type text/plain;
        add_header Cache-Control no-store;
        alias {SUB_FILE};
    }}

    location / {{
        return 404;
    }}
}}
"""


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "sync"
    cfg = load_config()
    if cmd == "sync":
        sync(cfg)
    elif cmd == "run":
        run(cfg)
    elif cmd == "status":
        status(cfg)
    elif cmd == "xray-config":
        print(json.dumps(xray_config(cfg), indent=2))
    elif cmd == "nginx-config":
        print(nginx_config(cfg), end="")
    elif cmd == "warp-register":
        warp_register()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
