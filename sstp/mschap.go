package main

// MS-CHAPv2 (RFC 2759) 和 MPPE 主密钥 (RFC 3079); 主密钥拼成 SSTP crypto binding 用的 HLAK

import (
	"crypto/des"
	"crypto/sha1"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

var (
	magic1 = []byte("This is the MPPE Master Key")
	magic2 = []byte("On the client side, this is the send key; on the server side, it is the receive key.")
	magic3 = []byte("On the client side, this is the receive key; on the server side, it is the send key.")
)

func md4Sum(b []byte) []byte {
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

func sha1Sum(parts ...[]byte) []byte {
	h := sha1.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func ntPasswordHash(password string) []byte {
	u := utf16.Encode([]rune(password))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return md4Sum(b)
}

// desEncrypt 用 7 字节密钥 (扩展成 8 字节, 校验位 crypto/des 不管) 加密 8 字节块
func desEncrypt(key7, block []byte) []byte {
	k := []byte{
		key7[0],
		key7[0]<<7 | key7[1]>>1,
		key7[1]<<6 | key7[2]>>2,
		key7[2]<<5 | key7[3]>>3,
		key7[3]<<4 | key7[4]>>4,
		key7[4]<<3 | key7[5]>>5,
		key7[5]<<2 | key7[6]>>6,
		key7[6] << 1,
	}
	c, _ := des.NewCipher(k)
	out := make([]byte, 8)
	c.Encrypt(out, block)
	return out
}

// mschapv2 返回 49 字节的 Response 值 (PeerChallenge 16 + 保留 8 + NT-Response 24 + Flags 1) 和 HLAK
func mschapv2(authChallenge, peerChallenge []byte, user, password string) (resp, hlak []byte) {
	pwHash := ntPasswordHash(password)
	challenge := sha1Sum(peerChallenge, authChallenge, []byte(user))[:8]
	z := make([]byte, 21)
	copy(z, pwHash)
	nt := make([]byte, 0, 24)
	for i := 0; i < 3; i++ {
		nt = append(nt, desEncrypt(z[7*i:7*i+7], challenge)...)
	}
	resp = make([]byte, 49)
	copy(resp, peerChallenge)
	copy(resp[24:], nt)

	master := sha1Sum(md4Sum(pwHash), nt, magic1)[:16]
	pad1, pad2 := make([]byte, 40), make([]byte, 40)
	for i := range pad2 {
		pad2[i] = 0xf2
	}
	send := sha1Sum(master, pad1, magic2, pad2)[:16]
	recv := sha1Sum(master, pad1, magic3, pad2)[:16]
	// HLAK = 客户端 MasterReceiveKey | MasterSendKey (MS-SSTP 3.2.5.2.3, 和 sstp-client 一致)
	return resp, append(recv, send...)
}
