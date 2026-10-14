#!/bin/bash
# gate VPS 安装脚本: SSTP 槽位 (sstpc/pppd) + xray (VLESS/WS) + nginx (订阅 + WS 反代)
#
# 用法 (root, 和 gate-manager.py 放在同一目录):
#   GATE_UUID=<uuid> GATE_HOST=gate.example.com bash install.sh
#
# 环境变量:
#   GATE_UUID       必填, 主 UUID (各槽位 UUID 由它派生, 也是订阅路径)
#   GATE_HOST       必填, 客户端访问的域名 (Cloudflare Tunnel 的 Public Hostname)
#   GATE_SLOTS      槽位数, 默认 8
#   GATE_NODES_URL  nodes.txt 地址, 默认 https://playwjj.github.io/gate/nodes.txt
#   GATE_LISTEN     nginx 监听地址, 默认 docker0 的地址 (供容器里的 cloudflared 访问), 没有 docker0 时用 127.0.0.1
#   GATE_PORT       nginx 监听端口, 默认 18080
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

: "${GATE_UUID:?需要 GATE_UUID}"
: "${GATE_HOST:?需要 GATE_HOST}"
GATE_SLOTS="${GATE_SLOTS:-8}"
GATE_NODES_URL="${GATE_NODES_URL:-https://playwjj.github.io/gate/nodes.txt}"
GATE_PORT="${GATE_PORT:-18080}"
GATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XRAY_VERSION="v26.3.27"
XRAY_SHA256="23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
if [ -z "${GATE_LISTEN:-}" ]; then
  GATE_LISTEN=$(ip -4 -o addr show docker0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  GATE_LISTEN="${GATE_LISTEN:-127.0.0.1}"
fi

apt_retry() {
  for attempt in $(seq 1 10); do
    "$@" && return 0
    echo "apt 失败 (第 ${attempt} 次, 可能被其他进程锁住), 15 秒后重试..."
    sleep 15
  done
  return 1
}

echo "[gate] 1/6 安装 sstp-client / ppp / nginx"
if ! command -v sstpc >/dev/null; then
  apt_retry apt-get install -y -q software-properties-common
  add-apt-repository -y ppa:eivnaes/network-manager-sstp
fi
apt_retry apt-get install -y -q sstp-client ppp nginx-light curl python3
modprobe ppp_generic ppp_async ppp_mppe 2>/dev/null || true

echo "[gate] 2/6 安装 xray $XRAY_VERSION"
if ! /usr/local/bin/xray version 2>/dev/null | grep -q "Xray ${XRAY_VERSION#v} "; then
  apt_retry apt-get install -y -q unzip
  tmp=$(mktemp -d)
  curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-linux-64.zip" -o "$tmp/xray.zip"
  echo "$XRAY_SHA256  $tmp/xray.zip" | sha256sum -c -
  unzip -oq "$tmp/xray.zip" xray -d "$tmp"
  install -m 755 "$tmp/xray" /usr/local/bin/xray
  rm -rf "$tmp"
fi
mkdir -p /usr/local/etc/xray

echo "[gate] 3/6 安装 gate-manager 与 systemd 单元"
mkdir -p /etc/gate /var/lib/gate
install -m 755 "$GATE_DIR/gate-manager.py" /usr/local/bin/gate-manager
cat > /etc/gate/gate.env <<EOF
UUID=$GATE_UUID
HOST=$GATE_HOST
SLOTS=$GATE_SLOTS
NODES_URL=$GATE_NODES_URL
LISTEN=$GATE_LISTEN
PORT=$GATE_PORT
EOF
chmod 600 /etc/gate/gate.env

cat > /etc/systemd/system/gate-slot@.service <<'EOF'
[Unit]
Description=gate SSTP slot %i (ppp%i)
After=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/gate/slot-%i.env
# nodefaultroute: 不改 VPS 默认路由, 流量只在 xray 指定 ppp%i 时才走隧道
ExecStart=/usr/sbin/sstpc --log-stderr --cert-warn --tls-ext --user ${SSTP_USER} --password ${SSTP_PASS} ${NODE} noauth nodefaultroute noipdefault nodetach unit %i refuse-eap
Restart=no
EOF

cat > /etc/systemd/system/gate-manager.service <<'EOF'
[Unit]
Description=gate slot manager
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/gate-manager sync
EOF

cat > /etc/systemd/system/gate-manager.timer <<'EOF'
[Unit]
Description=gate slot manager (every 3 minutes)

[Timer]
OnBootSec=1min
OnUnitActiveSec=3min

[Install]
WantedBy=timers.target
EOF

# xray 以 nobody 运行, 绑定 ppp 网卡 (SO_BINDTODEVICE) 需要 CAP_NET_RAW
cat > /etc/systemd/system/gate-xray.service <<'EOF'
[Unit]
Description=gate xray (VLESS → SSTP slots)
After=network-online.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

echo "[gate] 4/6 生成 xray / nginx 配置"
/usr/local/bin/gate-manager xray-config > /usr/local/etc/xray/config.json
/usr/local/bin/gate-manager nginx-config > /etc/nginx/sites-available/gate
ln -sf /etc/nginx/sites-available/gate /etc/nginx/sites-enabled/gate
rm -f /etc/nginx/sites-enabled/default
nginx -t

echo "[gate] 5/6 启动服务"
systemctl daemon-reload
systemctl enable gate-xray >/dev/null
systemctl restart gate-xray nginx
systemctl enable gate-manager.timer >/dev/null

echo "[gate] 6/6 首次建立 SSTP 槽位 (约 1 分钟)"
/usr/local/bin/gate-manager sync
systemctl start gate-manager.timer
/usr/local/bin/gate-manager status

echo
echo "[gate] 完成"
echo "  Cloudflare Tunnel Public Hostname: $GATE_HOST → http://$GATE_LISTEN:$GATE_PORT"
echo "  订阅地址: https://$GATE_HOST/sub/<GATE_UUID>"
