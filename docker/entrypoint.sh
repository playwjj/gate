#!/bin/sh
# gate 容器入口: 生成配置, 启动 xray / nginx / gate-manager, 最后交给原镜像的 start.sh (node VLESS + cloudflared)
#
# 环境变量 (原镜像的 UUID / PORT / TUNNEL_DOMAIN / TUNNEL_TOKEN 等照旧):
#   GATE_HOST       必填, gate 的域名 (Tunnel 里另加一个 Public Hostname → http://localhost:$GATE_PORT)
#   GATE_UUID       主 UUID, 默认等于 UUID (各槽位 UUID 由它派生, 也是订阅路径)
#   GATE_SLOTS      SSTP 槽位数, 默认 8; 0 = 关闭 SSTP 只留 WARP
#   GATE_SSTP_MODE  auto (默认): 有 /dev/ppp 用 ppp, 否则用 socks
#                   ppp   = sstpc + pppd 内核隧道 (需要 --device /dev/ppp --cap-add NET_ADMIN)
#                   socks = 用户态 sstp-socks, 不需要任何特权 (Northflank 等托管容器平台)
#   GATE_NODES_URL  nodes.txt 地址, 默认 https://playwjj.github.io/gate/nodes.txt
#   GATE_PORT       nginx 端口, 默认 18080 (只监听 127.0.0.1, 由容器内的 cloudflared 访问)
#   GATE_WARP       1 (默认) 启用 WARP 槽位, 0 关闭
#   GATE_NODE_SEED  任意字符串, 按它打乱选节点的顺序; 多台机器各设不同的值, 就会优先连不同的 VPN Gate 节点
#   GATE_WARP_B64   已有的 /etc/gate/warp.json 的 base64, 复用同一个 WARP 设备 (容器重建时建议设置)
set -eu

GATE_UUID="${GATE_UUID:-${UUID:-}}"
: "${GATE_UUID:?需要 GATE_UUID (或 UUID)}"
: "${GATE_HOST:?需要 GATE_HOST}"
GATE_SLOTS="${GATE_SLOTS:-8}"
GATE_NODES_URL="${GATE_NODES_URL:-https://playwjj.github.io/gate/nodes.txt}"
GATE_PORT="${GATE_PORT:-18080}"
GATE_WARP="${GATE_WARP:-1}"
GATE_SSTP_MODE="${GATE_SSTP_MODE:-auto}"

if [ "$GATE_SSTP_MODE" = auto ]; then
  if [ -c /dev/ppp ]; then GATE_SSTP_MODE=ppp; else GATE_SSTP_MODE=socks; fi
fi
case "$GATE_SSTP_MODE" in
  ppp|socks) echo "[gate] SSTP 槽位模式: $GATE_SSTP_MODE" ;;
  *) echo "[gate] GATE_SSTP_MODE 只能是 auto / ppp / socks"; exit 1 ;;
esac

mkdir -p /etc/gate /var/lib/gate /var/log/gate /usr/local/etc/xray
(umask 077; cat > /etc/gate/gate.env <<ENV
UUID=$GATE_UUID
HOST=$GATE_HOST
SLOTS=$GATE_SLOTS
NODES_URL=$GATE_NODES_URL
LISTEN=127.0.0.1
PORT=$GATE_PORT
WARP=$GATE_WARP
SSTP_MODE=$GATE_SSTP_MODE
NODE_SEED=${GATE_NODE_SEED:-}
ENV
)

if [ "$GATE_WARP" = 1 ]; then
  gate-manager warp-register || echo "[gate] WARP 注册失败, 本次不启用 WARP 槽位 (重启容器会再试)"
fi
[ "$GATE_SLOTS" = 0 ] && [ ! -f /etc/gate/warp.json ] && echo "[gate] 警告: SSTP 和 WARP 槽位都没有, 订阅为空"
gate-manager xray-config > /usr/local/etc/xray/config.json
gate-manager nginx-config > /etc/nginx/http.d/gate.conf
nginx -t -q

# 进程退出后 5 秒重启
keep() {
  (while :; do "$@" || true; echo "[gate] $1 退出, 5 秒后重启"; sleep 5; done) &
}
keep xray run -config /usr/local/etc/xray/config.json
keep nginx -g "daemon off;"
keep gate-manager run

echo "[gate] 订阅地址: https://$GATE_HOST/sub/$GATE_UUID"
echo "[gate] Cloudflare Tunnel Public Hostname: $GATE_HOST → http://localhost:$GATE_PORT"
cd /app
exec /app/start.sh
