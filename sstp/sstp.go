package main

// SSTP 传输层 (MS-SSTP): TLS + HTTP 握手 + SSTP 数据/控制包, PPP 帧直接放在数据包里

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	msgCallConnectRequest = 0x0001
	msgCallConnectAck     = 0x0002
	msgCallConnectNak     = 0x0003
	msgCallConnected      = 0x0004
	msgCallAbort          = 0x0005
	msgCallDisconnect     = 0x0006
	msgCallDisconnectAck  = 0x0007
	msgEchoRequest        = 0x0008
	msgEchoResponse       = 0x0009

	attrEncapsulatedProtocol = 1
	attrCryptoBinding        = 3
	attrCryptoBindingReq     = 4

	hashSHA1   = 1
	hashSHA256 = 2
)

type sstpConn struct {
	conn    *tls.Conn
	r       *bufio.Reader
	wmu     sync.Mutex
	certRaw []byte
}

type packet struct {
	ctrl bool
	body []byte
}

func dialSSTP(ctx context.Context, addr string) (*sstpConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// VPN Gate 的证书都是自签名的, 和 sstpc --cert-warn 一样不校验; 证书哈希仍用于 crypto binding
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second},
		Config:    &tls.Config{ServerName: host, InsecureSkipVerify: true},
	}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := c.(*tls.Conn)
	if dl, ok := ctx.Deadline(); ok {
		tc.SetDeadline(dl)
	}
	s := &sstpConn{conn: tc, r: bufio.NewReaderSize(tc, 64<<10), certRaw: tc.ConnectionState().PeerCertificates[0].Raw}

	var guid [16]byte
	rand.Read(guid[:])
	req := fmt.Sprintf("SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"+
		"Host: %s\r\nContent-Length: 18446744073709551615\r\nSSTPCORRELATIONID: {%X-%X-%X-%X-%X}\r\n\r\n",
		host, guid[0:4], guid[4:6], guid[6:8], guid[8:10], guid[10:16])
	if _, err := tc.Write([]byte(req)); err != nil {
		tc.Close()
		return nil, err
	}
	status, err := s.r.ReadString('\n')
	if err != nil {
		tc.Close()
		return nil, fmt.Errorf("HTTP 握手: %w", err)
	}
	if f := strings.Fields(status); len(f) < 2 || f[1] != "200" {
		tc.Close()
		return nil, fmt.Errorf("HTTP 握手: %q", strings.TrimSpace(status))
	}
	for {
		line, err := s.r.ReadString('\n')
		if err != nil {
			tc.Close()
			return nil, fmt.Errorf("HTTP 握手: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	return s, nil
}

func (s *sstpConn) Close() error { return s.conn.Close() }

func (s *sstpConn) readPacket() (packet, error) {
	var h [4]byte
	if _, err := io.ReadFull(s.r, h[:]); err != nil {
		return packet{}, err
	}
	if h[0] != 0x10 {
		return packet{}, fmt.Errorf("SSTP 版本不对: %#x", h[0])
	}
	n := int(binary.BigEndian.Uint16(h[2:]) & 0x0fff)
	if n < 4 {
		return packet{}, errors.New("SSTP 包长度不对")
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(s.r, body); err != nil {
		return packet{}, err
	}
	return packet{ctrl: h[1]&1 == 1, body: body}, nil
}

// writeRaw 写一个完整的 SSTP 包 (已含 4 字节头)
func (s *sstpConn) writeRaw(pkt []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := s.conn.Write(pkt)
	return err
}

func sstpHeader(pkt []byte, ctrl bool) {
	pkt[0] = 0x10
	pkt[1] = 0
	if ctrl {
		pkt[1] = 1
	}
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
}

// sendPPP 发送一个 PPP 帧 (地址/控制域 FF 03 + 2 字节协议号, 不压缩)
func (s *sstpConn) sendPPP(proto uint16, data []byte) error {
	pkt := make([]byte, 8+len(data))
	sstpHeader(pkt, false)
	pkt[4], pkt[5] = 0xff, 0x03
	binary.BigEndian.PutUint16(pkt[6:], proto)
	copy(pkt[8:], data)
	return s.writeRaw(pkt)
}

func ctrlPacket(typ uint16, attrs ...[]byte) []byte {
	n := 8
	for _, a := range attrs {
		n += len(a)
	}
	pkt := make([]byte, 8, n)
	sstpHeader(pkt[:n], true)
	binary.BigEndian.PutUint16(pkt[4:], typ)
	binary.BigEndian.PutUint16(pkt[6:], uint16(len(attrs)))
	for _, a := range attrs {
		pkt = append(pkt, a...)
	}
	return pkt
}

func sstpAttr(id byte, val []byte) []byte {
	a := make([]byte, 4+len(val))
	a[1] = id
	binary.BigEndian.PutUint16(a[2:], uint16(len(a)))
	copy(a[4:], val)
	return a
}

func (s *sstpConn) sendCtrl(typ uint16, attrs ...[]byte) error {
	return s.writeRaw(ctrlPacket(typ, attrs...))
}

func parseCtrl(body []byte) (uint16, map[byte][]byte, error) {
	if len(body) < 4 {
		return 0, nil, errors.New("SSTP 控制包太短")
	}
	typ := binary.BigEndian.Uint16(body)
	attrs := map[byte][]byte{}
	b := body[4:]
	for len(b) >= 4 {
		n := int(binary.BigEndian.Uint16(b[2:]) & 0x0fff)
		if n < 4 || n > len(b) {
			break
		}
		attrs[b[1]] = b[4:n]
		b = b[n:]
	}
	return typ, attrs, nil
}

// connectRequest 发 Call Connect Request, 返回服务器 ACK 里的 crypto binding 请求 (hash 位图 + nonce)
func (s *sstpConn) connectRequest() ([]byte, error) {
	if err := s.sendCtrl(msgCallConnectRequest, sstpAttr(attrEncapsulatedProtocol, []byte{0, 1})); err != nil {
		return nil, err
	}
	for {
		p, err := s.readPacket()
		if err != nil {
			return nil, err
		}
		if !p.ctrl {
			continue
		}
		typ, attrs, err := parseCtrl(p.body)
		if err != nil {
			return nil, err
		}
		switch typ {
		case msgCallConnectAck:
			req := attrs[attrCryptoBindingReq]
			if len(req) < 36 {
				return nil, errors.New("Call Connect Ack 里没有 crypto binding 请求")
			}
			return req, nil
		case msgCallConnectNak:
			return nil, errors.New("服务器拒绝 Call Connect Request")
		case msgCallAbort, msgCallDisconnect:
			return nil, errors.New("服务器中止连接")
		}
	}
}

// callConnected 发 Call Connected, 带 crypto binding (MS-SSTP 3.2.5.2): 证书哈希 + 用 HLAK 派生的 CMK 算的 Compound MAC
func (s *sstpConn) callConnected(bindReq, hlak []byte) error {
	mask, nonce := bindReq[3], bindReq[4:36]
	var newHash func() hash.Hash
	var certHash []byte
	val := make([]byte, 100) // 保留 3 + hash 协议 1 + nonce 32 + 证书哈希 32 + Compound MAC 32
	if mask&hashSHA256 != 0 {
		val[3], newHash = hashSHA256, sha256.New
		h := sha256.Sum256(s.certRaw)
		certHash = h[:]
	} else {
		val[3], newHash = hashSHA1, sha1.New
		h := sha1.Sum(s.certRaw)
		certHash = h[:]
	}
	copy(val[4:36], nonce)
	copy(val[36:68], certHash)
	pkt := ctrlPacket(msgCallConnected, sstpAttr(attrCryptoBinding, val))

	// CMK = PRF+(HLAK, "SSTP inner method derived CMK", len) 的第一块 T1 = HMAC(HLAK, seed | len(2 字节小端) | 0x01)
	size := newHash().Size()
	seed := append([]byte("SSTP inner method derived CMK"), byte(size), byte(size>>8), 1)
	m := hmac.New(newHash, hlak)
	m.Write(seed)
	cmk := m.Sum(nil)
	m = hmac.New(newHash, cmk)
	m.Write(pkt)
	copy(pkt[len(pkt)-32:], m.Sum(nil))
	return s.writeRaw(pkt)
}
