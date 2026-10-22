# gate 容器镜像: 在 work-tunnel-vless (node VLESS + cloudflared) 的基础上附加 gate 的 VPS 部分
#
# 构建 (在仓库根目录): docker build -f docker/Dockerfile -t gate-tunnel-vless .
ARG BASE_IMAGE=passport888/work-tunnel-vless:1.2.7

# Alpine 稳定版仓库没有 sstp-client, 在同一个基础镜像上从源码编译, 保证和运行时的 ppp / openssl 版本一致
FROM ${BASE_IMAGE} AS sstp-build
ARG SSTP_VERSION=1.0.20
RUN apk add --no-cache build-base autoconf automake libtool pkgconf git openssl-dev libevent-dev ppp-dev
RUN git clone -q --depth 1 --branch "$SSTP_VERSION" https://gitlab.com/sstp-project/sstp-client.git /src \
 && cd /src \
 && ./autogen.sh \
 && ./configure --prefix=/usr --sbindir=/usr/sbin --sysconfdir=/etc --localstatedir=/var --disable-static \
 && make -j"$(nproc)" \
 && make install DESTDIR=/out \
 && rm -rf /out/usr/include /out/usr/share /out/usr/lib/*.la /out/usr/lib/pppd/*/*.la

# 用户态 SSTP 客户端 (没有 /dev/ppp 的平台用), 纯 Go 静态编译, 在构建机架构上交叉编译
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS sstp-socks-build
ARG TARGETARCH
WORKDIR /src
COPY sstp/go.mod sstp/go.sum ./
RUN go mod download
COPY sstp/*.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/sstp-socks .

FROM ${BASE_IMAGE}
ARG TARGETARCH
ARG XRAY_VERSION=v26.3.27
RUN apk add --no-cache ppp-daemon libevent python3 nginx iproute2 tini unzip \
 && case "$TARGETARCH" in \
      amd64) zip=Xray-linux-64.zip;        sha=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae ;; \
      arm64) zip=Xray-linux-arm64-v8a.zip; sha=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c ;; \
      *) echo "不支持的架构: $TARGETARCH"; exit 1 ;; \
    esac \
 && curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/$zip" -o /tmp/xray.zip \
 && echo "$sha  /tmp/xray.zip" | sha256sum -c - \
 && unzip -oq /tmp/xray.zip xray -d /usr/local/bin \
 && rm /tmp/xray.zip \
 && apk del unzip \
 && rm -f /etc/nginx/http.d/default.conf
COPY --from=sstp-build /out/ /
COPY --from=sstp-socks-build /out/sstp-socks /usr/local/bin/sstp-socks
COPY vps/gate-manager.py /usr/local/bin/gate-manager
COPY docker/entrypoint.sh /usr/local/bin/gate-entrypoint
RUN chmod 755 /usr/local/bin/gate-manager /usr/local/bin/gate-entrypoint

# tini 回收 pppd / sstp-socks 等孤儿进程; 入口脚本最后 exec 原镜像的 /app/start.sh (node + cloudflared)
ENTRYPOINT ["/sbin/tini", "-g", "--"]
CMD ["/usr/local/bin/gate-entrypoint"]
