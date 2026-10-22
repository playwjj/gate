// sstp-socks: 用户态 SSTP 客户端, 把一条 SSTP 隧道作为本地 SOCKS5 代理提供出来
//
// 不需要 /dev/ppp、TUN 或 NET_ADMIN: SSTP / PPP 协议自己实现, IP 包交给 gVisor 的用户态 TCP/IP 栈,
// 因此能在 Northflank 这类受限容器里运行. gate-manager 在没有 /dev/ppp 时为每个槽位起一个进程.
//
// 用法: sstp-socks -server host:port [-user vpn -pass vpn] -listen 127.0.0.1:21081 [-status /path/slot.json]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

func main() {
	server := flag.String("server", "", "SSTP 服务器 host:port")
	user := flag.String("user", "vpn", "用户名")
	pass := flag.String("pass", "vpn", "密码")
	listen := flag.String("listen", "127.0.0.1:1080", "SOCKS5 监听地址")
	status := flag.String("status", "", "连接成功后写入状态 JSON (本端 IP 等), 退出时删除")
	timeout := flag.Duration("timeout", 30*time.Second, "建立连接的超时")
	flag.Parse()
	log.SetFlags(log.LstdFlags)
	if *server == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *status != "" {
		os.Remove(*status)
	}
	exit := func(code int) {
		if *status != "" {
			os.Remove(*status)
		}
		os.Exit(code)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", *listen, err)
	}

	deadline := time.Now().Add(*timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	s, err := dialSSTP(ctx, *server)
	cancel()
	if err != nil {
		log.Printf("连接 %s 失败: %v", *server, err)
		exit(1)
	}
	bindReq, err := s.connectRequest()
	if err != nil {
		log.Printf("SSTP 握手失败: %v", err)
		exit(1)
	}
	s.conn.SetDeadline(time.Time{})
	p := newSession(s, *user, *pass, bindReq)
	if err := p.negotiate(deadline); err != nil {
		log.Printf("PPP 协商失败: %v", err)
		exit(1)
	}

	// VPN Gate (SoftEther) 下发的 DNS 优先, 后面补公共 DNS, 都经隧道查询
	dns := append(p.dns, netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1"))
	mtu := min(p.peerMRU, 1400)
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{p.localIP}, dns, mtu)
	if err != nil {
		log.Printf("创建用户态网络栈失败: %v", err)
		exit(1)
	}
	p.onIP = func(b []byte) { dev.Write([][]byte{b}, 0) }
	go func() {
		bufs, sizes := [][]byte{make([]byte, 65535)}, []int{0}
		for {
			n, err := dev.Read(bufs, sizes, 0)
			if err != nil {
				p.fail(err)
				return
			}
			if n == 1 {
				if err := s.sendPPP(protoIPv4, bufs[0][:sizes[0]]); err != nil {
					p.fail(err)
					return
				}
			}
		}
	}()
	go (&socksServer{tnet: tnet, localIP: p.localIP}).serve(ln)

	if *status != "" {
		b, _ := json.Marshal(map[string]any{"server": *server, "ip": p.localIP.String(), "dns": p.dns, "mtu": mtu, "pid": os.Getpid()})
		tmp := *status + ".tmp"
		if err := os.WriteFile(tmp, b, 0o644); err == nil {
			os.Rename(tmp, *status)
		}
	}
	log.Printf("已连接 %s, 本端 IP %s, DNS %v, MTU %d, SOCKS5 %s", *server, p.localIP, p.dns, mtu, *listen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	stop := make(chan struct{})
	go func() {
		<-sig
		close(stop)
		s.sendCtrl(msgCallDisconnect)
		s.Close()
		exit(0)
	}()

	err = p.run()
	select {
	case <-stop:
		select {} // 收到信号后由上面的 goroutine 退出
	default:
	}
	log.Printf("连接断开: %v", err)
	s.Close()
	exit(1)
}
