#!/bin/sh
# gate 容器入口: 生成配置, 启动 xray / nginx / gate-manager, 最后交给原镜像的 start.sh (node VLESS + cloudflared)
#
# 环境变量 (原镜像的 UUID / PORT / TUNNEL_DOMAIN / TUNNEL_TOKEN 等照旧):
#   GATE_HOST       必填, gate 的域名 (Tunnel 里另加一个 Public Hostname → http://localhost:$GATE_PORT)
#   GATE_UUID       主 UUID, 默认等于 UUID (各槽位 UUID 由它派生, 也是订阅路径)
#   GATE_SLOTS      SSTP 槽位数, 默认 8; 0 = 关闭 SSTP 只留 WARP. 没有 /dev/ppp 时自动变成 0
#   GATE_NODES_URL  nodes.txt 地址, 默认 https://playwjj.github.io/gate/nodes.txt
#   GATE_PORT       nginx 端口, 默认 18080 (只监听 127.0.0.1, 由容器内的 cloudflared 访问)
#   GATE_WARP       1 (默认) 启用 WARP 槽位, 0 关闭
#   GATE_WARP_B64   已有的 /etc/gate/warp.json 的 base64, 复用同一个 WARP 设备 (容器重建时建议设置)
set -eu

GATE_UUID="${GATE_UUID:-${UUID:-}}"
: "${GATE_UUID:?需要 GATE_UUID (或 UUID)}"
: "${GATE_HOST:?需要 GATE_HOST}"
GATE_SLOTS="${GATE_SLOTS:-8}"
GATE_NODES_URL="${GATE_NODES_URL:-https://playwjj.github.io/gate/nodes.txt}"
GATE_PORT="${GATE_PORT:-18080}"
GATE_WARP="${GATE_WARP:-1}"

if [ "$GATE_SLOTS" -gt 0 ] && [ ! -c /dev/ppp ]; then
  echo "[gate] 没有 /dev/ppp (KVM 上需要 --device /dev/ppp --cap-add NET_ADMIN), 关闭 SSTP 槽位, 只提供 WARP"
  GATE_SLOTS=0
fi

mkdir -p /etc/gate /var/lib/gate /var/log/gate /usr/local/etc/xray
(umask 077; cat > /etc/gate/gate.env <<ENV
UUID=$GATE_UUID
HOST=$GATE_HOST
SLOTS=$GATE_SLOTS
NODES_URL=$GATE_NODES_URL
LISTEN=127.0.0.1
PORT=$GATE_PORT
WARP=$GATE_WARP
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
