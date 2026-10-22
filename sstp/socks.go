package main

// 本地 SOCKS5 服务 (无认证, CONNECT + UDP ASSOCIATE), 出站连接走 SSTP 隧道里的用户态 TCP/IP 栈

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

type socksServer struct {
	tnet    *netstack.Net
	localIP netip.Addr
}

func (s *socksServer) serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func socksReply(c net.Conn, rep byte, bind netip.AddrPort) error {
	b := []byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0}
	if bind.Addr().Is4() {
		a := bind.Addr().As4()
		copy(b[4:8], a[:])
		binary.BigEndian.PutUint16(b[8:], bind.Port())
	}
	_, err := c.Write(b)
	return err
}

// readAddr 读 SOCKS5 地址 (ATYP + 地址 + 端口), 返回 host:port
func readAddr(r io.Reader) (string, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return "", err
	}
	var host string
	switch t[0] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return "", err
		}
		host = netip.AddrFrom4(a).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		host = string(name)
	case 4:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return "", err
		}
		host = netip.AddrFrom16(a).String()
	default:
		return "", errors.New("不支持的地址类型")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func (s *socksServer) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 5 {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, hdr[1])); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	var req [3]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 {
		return
	}
	addr, err := readAddr(c)
	if err != nil {
		socksReply(c, 8, netip.AddrPort{})
		return
	}
	switch req[1] {
	case 1:
		s.connect(c, addr)
	case 3:
		s.udpAssociate(c)
	default:
		socksReply(c, 7, netip.AddrPort{})
	}
}

func (s *socksServer) connect(c net.Conn, addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// 隧道里只有 IPv4, 域名在隧道内解析
	r, err := s.tnet.DialContext(ctx, "tcp4", addr)
	if err != nil {
		socksReply(c, 5, netip.AddrPort{})
		return
	}
	defer r.Close()
	if socksReply(c, 0, netip.AddrPortFrom(s.localIP, 0)) != nil {
		return
	}
	c.SetDeadline(time.Time{})
	relay(c, r)
}

type closeWriter interface{ CloseWrite() error }

func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// udpAssociate: 客户端发到本地 UDP 端口的数据报解包后从隧道发出, 回包加上 SOCKS5 UDP 头发回去; 控制 TCP 连接断开时结束
func (s *socksServer) udpAssociate(c net.Conn) {
	host, _, _ := net.SplitHostPort(c.LocalAddr().String())
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		socksReply(c, 1, netip.AddrPort{})
		return
	}
	defer lc.Close()
	rc, err := s.tnet.ListenUDPAddrPort(netip.AddrPortFrom(s.localIP, 0))
	if err != nil {
		socksReply(c, 1, netip.AddrPort{})
		return
	}
	defer rc.Close()
	if socksReply(c, 0, lc.LocalAddr().(*net.UDPAddr).AddrPort()) != nil {
		return
	}
	c.SetDeadline(time.Time{})

	var mu sync.Mutex
	var client *net.UDPAddr
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := rc.ReadFrom(buf[10:])
			if err != nil {
				return
			}
			ua, ok := from.(*net.UDPAddr)
			if !ok || ua.IP.To4() == nil {
				continue
			}
			ip4 := ua.IP.To4()
			pkt := buf[:10+n]
			copy(pkt, []byte{0, 0, 0, 1})
			copy(pkt[4:8], ip4)
			binary.BigEndian.PutUint16(pkt[8:], uint16(ua.Port))
			mu.Lock()
			dst := client
			mu.Unlock()
			if dst != nil {
				lc.WriteToUDP(pkt, dst)
			}
		}
	}()
	go func() {
		resolved := map[string]*net.UDPAddr{}
		buf := make([]byte, 65535)
		for {
			n, from, err := lc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			client = from
			mu.Unlock()
			// RSV(2) FRAG(1) ATYP...; 不支持分片
			if n < 4 || buf[2] != 0 {
				continue
			}
			r := &sliceReader{b: buf[3:n]}
			addr, err := readAddr(r)
			if err != nil {
				continue
			}
			dst, ok := resolved[addr]
			if !ok {
				dst, err = s.resolveUDP(addr)
				if err != nil {
					log.Printf("UDP 目标 %s 解析失败: %v", addr, err)
					continue
				}
				if len(resolved) > 1024 {
					clear(resolved)
				}
				resolved[addr] = dst
			}
			rc.WriteTo(r.b, dst)
		}
	}()
	io.Copy(io.Discard, c)
}

func (s *socksServer) resolveUDP(addr string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(port)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, err := s.tnet.LookupContextHost(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
			return &net.UDPAddr{IP: a.AsSlice(), Port: p}, nil
		}
	}
	return nil, errors.New("没有 IPv4 地址")
}

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
