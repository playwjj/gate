package main

// PPP 客户端: LCP → 认证 (MS-CHAPv2 / CHAP-MD5 / PAP) → SSTP Call Connected → IPCP, 之后转发 IPv4 包

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

const (
	protoIPv4 = 0x0021
	protoIPCP = 0x8021
	protoLCP  = 0xc021
	protoPAP  = 0xc023
	protoCHAP = 0xc223

	codeConfReq    = 1
	codeConfAck    = 2
	codeConfNak    = 3
	codeConfRej    = 4
	codeTermReq    = 5
	codeTermAck    = 6
	codeProtoRej   = 8
	codeEchoReq    = 9
	codeEchoReply  = 10
	chapMSCHAPv2   = 0x81
	chapMD5        = 0x05
	retransmitWait = 3 * time.Second
)

type option struct {
	typ byte
	val []byte
}

func parseOpts(b []byte) ([]option, error) {
	var opts []option
	for len(b) > 0 {
		if len(b) < 2 || int(b[1]) < 2 || int(b[1]) > len(b) {
			return nil, errors.New("PPP 选项格式错误")
		}
		opts = append(opts, option{b[0], b[2:b[1]]})
		b = b[b[1]:]
	}
	return opts, nil
}

func encodeOpts(opts []option) []byte {
	var b []byte
	for _, o := range opts {
		b = append(b, o.typ, byte(2+len(o.val)))
		b = append(b, o.val...)
	}
	return b
}

func cpPacket(code, id byte, data []byte) []byte {
	b := make([]byte, 4+len(data))
	b[0], b[1] = code, id
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[4:], data)
	return b
}

// parsePPP 去掉地址/控制域, 兼容对方协商了 ACFC / PFC 的压缩帧
func parsePPP(b []byte) (uint16, []byte, bool) {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0x03 {
		b = b[2:]
	}
	if len(b) >= 1 && b[0]&1 == 1 {
		return uint16(b[0]), b[1:], true
	}
	if len(b) < 2 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint16(b), b[2:], true
}

// cp 是一个控制协议 (LCP / IPCP) 中我们这一侧的 Configure-Request 状态
type cp struct {
	proto   uint16
	id      byte
	opts    []option
	sent    time.Time
	ourAck  bool // 对方 Ack 了我们的请求
	peerAck bool // 我们 Ack 了对方的请求
}

func (c *cp) open() bool { return c.ourAck && c.peerAck }

type session struct {
	s          *sstpConn
	user, pass string
	bindReq    []byte
	pkts       chan packet
	errc       chan error

	lcp, ipcp     cp
	magic         [4]byte
	peerMRU       int
	authProto     uint16
	authAlgo      byte
	authStarted   bool
	authDone      bool
	authSent      time.Time
	hlak          []byte
	connectedSent bool
	nextID        byte

	localIP  netip.Addr
	dns      []netip.Addr
	onIP     func([]byte)
	lastRecv time.Time
}

func newSession(s *sstpConn, user, pass string, bindReq []byte) *session {
	p := &session{
		s: s, user: user, pass: pass, bindReq: bindReq,
		pkts: make(chan packet, 512), errc: make(chan error, 2),
		peerMRU: 1500, hlak: make([]byte, 32), lastRecv: time.Now(),
	}
	rand.Read(p.magic[:])
	p.lcp = cp{proto: protoLCP, opts: []option{{5, p.magic[:]}}}
	zero := []byte{0, 0, 0, 0}
	p.ipcp = cp{proto: protoIPCP, opts: []option{{3, zero}, {129, zero}, {131, zero}}}
	go p.reader()
	return p
}

func (p *session) reader() {
	for {
		pk, err := p.s.readPacket()
		if err != nil {
			p.errc <- err
			return
		}
		p.pkts <- pk
	}
}

func (p *session) fail(err error) {
	select {
	case p.errc <- err:
	default:
	}
}

func (p *session) sendConfReq(c *cp) error {
	c.id++
	c.sent = time.Now()
	return p.s.sendPPP(c.proto, cpPacket(codeConfReq, c.id, encodeOpts(c.opts)))
}

// negotiate 一直协商到 IPCP 打开, 拿到本端 IP
func (p *session) negotiate(deadline time.Time) error {
	if err := p.sendConfReq(&p.lcp); err != nil {
		return err
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for !p.ipcp.open() {
		select {
		case pk := <-p.pkts:
			if err := p.handle(pk); err != nil {
				return err
			}
		case err := <-p.errc:
			return err
		case now := <-tick.C:
			if now.After(deadline) {
				return fmt.Errorf("PPP 协商超时 (lcp=%v auth=%v ipcp=%v/%v)", p.lcp.open(), p.authDone, p.ipcp.ourAck, p.ipcp.peerAck)
			}
			var err error
			switch {
			case !p.lcp.ourAck && now.Sub(p.lcp.sent) > retransmitWait:
				err = p.sendConfReq(&p.lcp)
			case p.authProto == protoPAP && p.authStarted && !p.authDone && now.Sub(p.authSent) > retransmitWait:
				err = p.sendPAP()
			case p.connectedSent && !p.ipcp.ourAck && now.Sub(p.ipcp.sent) > retransmitWait:
				err = p.sendConfReq(&p.ipcp)
			}
			if err != nil {
				return err
			}
		}
		if err := p.advance(); err != nil {
			return err
		}
	}
	for _, o := range p.ipcp.opts {
		if len(o.val) != 4 {
			continue
		}
		ip := netip.AddrFrom4([4]byte(o.val))
		switch {
		case o.typ == 3:
			p.localIP = ip
		case ip.IsUnspecified():
		case o.typ == 129 || o.typ == 131:
			p.dns = append(p.dns, ip)
		}
	}
	if !p.localIP.IsValid() || p.localIP.IsUnspecified() {
		return errors.New("IPCP 没有分配 IP")
	}
	return nil
}

// advance 在 LCP 打开后推进: 开始认证 → 认证成功后发 Call Connected 并开始 IPCP
func (p *session) advance() error {
	if !p.lcp.open() {
		return nil
	}
	if !p.authStarted {
		p.authStarted = true
		switch p.authProto {
		case 0:
			p.authDone = true
		case protoPAP:
			if err := p.sendPAP(); err != nil {
				return err
			}
		}
		// CHAP 等服务器先发 Challenge
	}
	if p.authDone && !p.connectedSent {
		p.connectedSent = true
		if err := p.s.callConnected(p.bindReq, p.hlak); err != nil {
			return err
		}
		return p.sendConfReq(&p.ipcp)
	}
	return nil
}

// run 在连接建立后处理收到的包, 并用 SSTP Echo 保活, 90 秒收不到任何东西就认为断了
func (p *session) run() error {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case pk := <-p.pkts:
			if err := p.handle(pk); err != nil {
				return err
			}
		case err := <-p.errc:
			return err
		case now := <-tick.C:
			idle := now.Sub(p.lastRecv)
			if idle > 90*time.Second {
				return errors.New("90 秒没有收到数据, 连接已断")
			}
			if idle > 20*time.Second {
				if err := p.s.sendCtrl(msgEchoRequest); err != nil {
					return err
				}
			}
		}
	}
}

func (p *session) handle(pk packet) error {
	p.lastRecv = time.Now()
	if pk.ctrl {
		typ, _, err := parseCtrl(pk.body)
		if err != nil {
			return err
		}
		switch typ {
		case msgEchoRequest:
			return p.s.sendCtrl(msgEchoResponse)
		case msgCallDisconnect:
			p.s.sendCtrl(msgCallDisconnectAck)
			return errors.New("服务器断开连接 (Call Disconnect)")
		case msgCallAbort:
			return errors.New("服务器中止连接 (Call Abort)")
		}
		return nil
	}
	proto, data, ok := parsePPP(pk.body)
	if !ok {
		return nil
	}
	switch proto {
	case protoIPv4:
		if p.onIP != nil {
			p.onIP(data)
		}
		return nil
	case protoLCP:
		return p.handleLCP(data)
	case protoCHAP:
		return p.handleCHAP(data)
	case protoPAP:
		return p.handlePAP(data)
	case protoIPCP:
		return p.handleIPCP(data)
	}
	// IPv6CP / CCP 等不支持的协议: LCP Protocol-Reject
	if p.lcp.open() {
		rej := make([]byte, 2, 2+len(data))
		binary.BigEndian.PutUint16(rej, proto)
		rej = append(rej, data...)
		if len(rej) > p.peerMRU-4 {
			rej = rej[:p.peerMRU-4]
		}
		p.nextID++
		return p.s.sendPPP(protoLCP, cpPacket(codeProtoRej, p.nextID, rej))
	}
	return nil
}

// splitCP 解析 LCP / IPCP 包头, 按长度字段截断
func splitCP(data []byte) (code, id byte, payload []byte, ok bool) {
	if len(data) < 4 {
		return
	}
	n := int(binary.BigEndian.Uint16(data[2:]))
	if n < 4 || n > len(data) {
		return
	}
	return data[0], data[1], data[4:n], true
}

// handleConfResponse 处理对方对我们 Configure-Request 的 Ack / Nak / Reject
func (p *session) handleConfResponse(c *cp, code, id byte, payload []byte, nakable func(byte) bool) error {
	if id != c.id {
		return nil
	}
	opts, err := parseOpts(payload)
	if err != nil {
		return err
	}
	switch code {
	case codeConfAck:
		c.ourAck = true
		return nil
	case codeConfNak:
		for _, o := range opts {
			found := false
			for i := range c.opts {
				if c.opts[i].typ == o.typ {
					c.opts[i].val, found = o.val, true
				}
			}
			if !found && nakable(o.typ) {
				c.opts = append(c.opts, o)
			}
		}
	case codeConfRej:
		var kept []option
		for _, mine := range c.opts {
			rejected := false
			for _, o := range opts {
				rejected = rejected || o.typ == mine.typ
			}
			if !rejected {
				kept = append(kept, mine)
			}
		}
		c.opts = kept
	}
	return p.sendConfReq(c)
}

// replyConfReq 回应对方的 Configure-Request: 有不认识的选项就 Reject, 有不接受的就 Nak, 否则 Ack
func (p *session) replyConfReq(c *cp, id byte, payload []byte, check func(option) (accept bool, nak []byte)) (bool, error) {
	opts, err := parseOpts(payload)
	if err != nil {
		return false, err
	}
	var rej, nak []option
	for _, o := range opts {
		accept, suggestion := check(o)
		switch {
		case suggestion != nil:
			nak = append(nak, option{o.typ, suggestion})
		case !accept:
			rej = append(rej, o)
		}
	}
	switch {
	case rej != nil:
		return false, p.s.sendPPP(c.proto, cpPacket(codeConfRej, id, encodeOpts(rej)))
	case nak != nil:
		return false, p.s.sendPPP(c.proto, cpPacket(codeConfNak, id, encodeOpts(nak)))
	}
	c.peerAck = true
	return true, p.s.sendPPP(c.proto, cpPacket(codeConfAck, id, payload))
}

func (p *session) handleLCP(data []byte) error {
	code, id, payload, ok := splitCP(data)
	if !ok {
		return nil
	}
	switch code {
	case codeConfReq:
		mru, authProto, authAlgo := 1500, uint16(0), byte(0)
		acked, err := p.replyConfReq(&p.lcp, id, payload, func(o option) (bool, []byte) {
			switch o.typ {
			case 1: // MRU
				if len(o.val) == 2 {
					mru = int(binary.BigEndian.Uint16(o.val))
				}
				return true, nil
			case 2, 5, 7, 8: // ACCM, Magic-Number, PFC, ACFC
				return true, nil
			case 3: // Authentication-Protocol
				if len(o.val) >= 2 {
					switch binary.BigEndian.Uint16(o.val) {
					case protoPAP:
						authProto = protoPAP
						return true, nil
					case protoCHAP:
						if len(o.val) == 3 && (o.val[2] == chapMSCHAPv2 || o.val[2] == chapMD5) {
							authProto, authAlgo = protoCHAP, o.val[2]
							return true, nil
						}
					}
				}
				return false, []byte{0xc2, 0x23, chapMSCHAPv2}
			}
			return false, nil
		})
		if acked {
			p.peerMRU, p.authProto, p.authAlgo = mru, authProto, authAlgo
		}
		return err
	case codeConfAck, codeConfNak, codeConfRej:
		return p.handleConfResponse(&p.lcp, code, id, payload, func(byte) bool { return false })
	case codeTermReq:
		p.s.sendPPP(protoLCP, cpPacket(codeTermAck, id, nil))
		return errors.New("服务器结束 PPP 会话 (LCP Terminate-Request)")
	case codeEchoReq:
		return p.s.sendPPP(protoLCP, cpPacket(codeEchoReply, id, p.magic[:]))
	}
	return nil
}

func (p *session) handleCHAP(data []byte) error {
	code, id, payload, ok := splitCP(data)
	if !ok {
		return nil
	}
	switch code {
	case 1: // Challenge
		if len(payload) < 1 || len(payload) < 1+int(payload[0]) {
			return nil
		}
		challenge := payload[1 : 1+payload[0]]
		var value []byte
		switch {
		case p.authAlgo == chapMSCHAPv2 && len(challenge) == 16:
			peer := make([]byte, 16)
			rand.Read(peer)
			value, p.hlak = mschapv2(challenge, peer, p.user, p.pass)
		case p.authAlgo == chapMD5:
			h := md5.New()
			h.Write([]byte{id})
			h.Write([]byte(p.pass))
			h.Write(challenge)
			value = h.Sum(nil)
		default:
			return fmt.Errorf("不支持的 CHAP 算法 %#x", p.authAlgo)
		}
		resp := append([]byte{byte(len(value))}, value...)
		resp = append(resp, p.user...)
		return p.s.sendPPP(protoCHAP, cpPacket(2, id, resp))
	case 3: // Success
		p.authDone = true
	case 4: // Failure
		return fmt.Errorf("CHAP 认证失败: %s", payload)
	}
	return nil
}

func (p *session) sendPAP() error {
	p.authSent = time.Now()
	p.nextID++
	b := append([]byte{byte(len(p.user))}, p.user...)
	b = append(b, byte(len(p.pass)))
	b = append(b, p.pass...)
	return p.s.sendPPP(protoPAP, cpPacket(1, p.nextID, b))
}

func (p *session) handlePAP(data []byte) error {
	code, _, payload, ok := splitCP(data)
	if !ok {
		return nil
	}
	switch code {
	case 2:
		p.authDone = true
	case 3:
		return fmt.Errorf("PAP 认证失败: %s", payload)
	}
	return nil
}

func (p *session) handleIPCP(data []byte) error {
	code, id, payload, ok := splitCP(data)
	if !ok {
		return nil
	}
	switch code {
	case codeConfReq:
		_, err := p.replyConfReq(&p.ipcp, id, payload, func(o option) (bool, []byte) {
			return o.typ == 3, nil // 只接受 IP-Address (对端地址), 不要 VJ 压缩
		})
		return err
	case codeConfAck, codeConfNak, codeConfRej:
		return p.handleConfResponse(&p.ipcp, code, id, payload, func(t byte) bool { return t == 3 || t == 129 || t == 131 })
	case codeTermReq:
		p.s.sendPPP(protoIPCP, cpPacket(codeTermAck, id, nil))
		return errors.New("服务器结束 IPCP")
	}
	return nil
}
