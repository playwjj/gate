#!/usr/bin/env python3
"""
gate-manager: 在 VPS 上维护 N 个 SSTP 槽位 (ppp1..pppN), 并生成 xray / nginx 配置和订阅

用法:
  gate-manager sync           检查各槽位, 坏掉的从 nodes.txt 换新节点, 更新订阅 (systemd timer 定时调用)
  gate-manager status         打印各槽位状态
  gate-manager xray-config    输出 xray 配置 JSON
  gate-manager nginx-config   输出 nginx 站点配置

配置读取 /etc/gate/gate.env (由 install.sh 生成)
"""
import base64
import json
import os
import re
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
WS_PATH = "/ws"
PROBE_URL = "http://cp.cloudflare.com/generate_204"
BAD_NODE_TTL = 3600  # 连接失败的节点 1 小时内不再尝试
CONNECT_WAIT = 30


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
    return cfg


def slot_uuid(master, k):
    return str(uuid.uuid5(uuid.UUID(master), f"slot{k}"))


# ---------------------------------------------------------------------------
# 节点
# ---------------------------------------------------------------------------
NODE_RE = re.compile(r"#([^$]+)\$sstp://(?:([^:@]+):([^@]*)@)?([^:\s]+):(\d+)")


def fetch_nodes(url):
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


def order_candidates(nodes):
    """住宅优先, 各国家轮流取, 让槽位尽量覆盖不同国家"""
    def interleave(items):
        buckets = {}
        for n in items:
            buckets.setdefault(n["name"].split("-")[0], []).append(n)
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
# 槽位
# ---------------------------------------------------------------------------
def ppp_ip(k):
    out = subprocess.run(["ip", "-4", "-o", "addr", "show", f"ppp{k}"], capture_output=True, text=True).stdout
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def probe(k):
    result = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "10", "--interface", f"ppp{k}", PROBE_URL],
        capture_output=True, text=True,
    )
    return result.stdout.strip() == "204"


def slot_healthy(k):
    return ppp_ip(k) is not None and probe(k)


def stop_slot(k):
    subprocess.run(["systemctl", "stop", f"gate-slot@{k}"], capture_output=True)


def start_slot(k, node):
    with open(f"/etc/gate/slot-{k}.env", "w", encoding="utf-8") as f:
        f.write(f"NODE={node['node']}\nSSTP_USER={node['user']}\nSSTP_PASS={node['password']}\n")
    subprocess.run(["systemctl", "restart", f"gate-slot@{k}"], capture_output=True)
    deadline = time.time() + CONNECT_WAIT
    while time.time() < deadline:
        if ppp_ip(k):
            return probe(k)
        time.sleep(1)
    return False


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

    with ThreadPoolExecutor(max_workers=cfg["SLOTS"]) as pool:
        health = dict(zip(slots, pool.map(slot_healthy, slots)))

    # VPN Gate 各服务器独立分配 10.211.x.x, 不同槽位偶尔会拿到相同 IP, 重复的视为不健康
    seen_ips = {}
    for k in slots:
        if health[k]:
            ip = ppp_ip(k)
            if ip in seen_ips:
                log(f"slot{k}: IP {ip} 与 slot{seen_ips[ip]} 重复, 重新分配")
                health[k] = False
            else:
                seen_ips[ip] = k

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
            nodes = order_candidates(fetch_nodes(cfg["NODES_URL"]))
        except Exception as e:
            log(f"拉取 nodes.txt 失败: {e}")
            nodes = []
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
                    log(f"slot{k}: 已连接 {node['name']} {node['node']} (ppp{k} {ppp_ip(k)})")
                    return
                with lock:
                    state["bad"][node["node"]] = time.time()
                log(f"slot{k}: {node['node']} 连接失败")
            stop_slot(k)

        with ThreadPoolExecutor(max_workers=len(broken)) as pool:
            list(pool.map(fill, broken))

    save_state(state)
    write_subscription(cfg, state)
    log(f"健康槽位 {len(state['slots'])}/{cfg['SLOTS']}")


def write_subscription(cfg, state):
    host = cfg["HOST"]
    links = []
    for k in range(1, cfg["SLOTS"] + 1):
        slot = state["slots"].get(str(k))
        remark = f"{k:02d}-{slot['name']}" if slot else f"{k:02d}-连接中"
        params = urllib.parse.urlencode({
            "encryption": "none", "security": "tls", "sni": host, "fp": "chrome",
            "type": "ws", "host": host, "path": WS_PATH,
        })
        links.append(f"vless://{slot_uuid(cfg['UUID'], k)}@{host}:443?{params}#{urllib.parse.quote(remark)}")
    os.makedirs(os.path.dirname(SUB_FILE), exist_ok=True)
    tmp = SUB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode())
    os.replace(tmp, SUB_FILE)


def status(cfg):
    state = load_state()
    for k in range(1, cfg["SLOTS"] + 1):
        slot = state["slots"].get(str(k))
        ip = ppp_ip(k)
        desc = f"{slot['name']} {slot['node']}" if slot else "-"
        print(f"slot{k}  ppp{k}={ip or 'down':<15} {desc}")


# ---------------------------------------------------------------------------
# 配置生成
# ---------------------------------------------------------------------------
def xray_config(cfg):
    slots = range(1, cfg["SLOTS"] + 1)
    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": cfg["XRAY_PORT"],
            "protocol": "vless",
            "settings": {
                "clients": [{"id": slot_uuid(cfg["UUID"], k), "email": f"slot{k}"} for k in slots],
                "decryption": "none",
            },
            "streamSettings": {"network": "ws", "wsSettings": {"path": WS_PATH}},
        }],
        # 第一个 outbound 是默认出口: 没匹配到槽位的流量直接丢弃, 不会从 VPS 自己的 IP 出去
        "outbounds": [{"tag": "block", "protocol": "blackhole"}] + [{
            "tag": f"slot{k}",
            "protocol": "freedom",
            "settings": {"domainStrategy": "UseIPv4"},
            "streamSettings": {"sockopt": {"interface": f"ppp{k}"}},
        } for k in slots],
        "routing": {"rules": [{"type": "field", "user": [f"slot{k}"], "outboundTag": f"slot{k}"} for k in slots]},
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
    elif cmd == "status":
        status(cfg)
    elif cmd == "xray-config":
        print(json.dumps(xray_config(cfg), indent=2))
    elif cmd == "nginx-config":
        print(nginx_config(cfg), end="")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
