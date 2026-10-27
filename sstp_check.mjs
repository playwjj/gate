#!/usr/bin/env node
/**
 * sstp_check.mjs — VPN Gate SSTP 节点批量检测器 (零依赖, Node >= 18)
 * ================================================================
 * 自己实现的 SSTP 客户端: TLS 连接节点 → SSTP_DUPLEX_POST 握手 →
 * PPP 协商 (LCP → PAP / CHAP-MD5 / MS-CHAPv2 → SSTP Call Connected → IPCP) →
 * 在 PPP 上跑一条最小 TCP 会话 →
 * 经隧道向 www.iplocate.io 发 HTTPS 请求, 以真实出口 IP 判定节点可用性,
 * 并带回出口的国家 / ASN / 机房属性。
 *
 * 输入 (stdin, JSON):
 *   {"nodes": [{"host": "...", "port": 443,
 *               "username": "vpn", "password": "vpn"}],
 *    "concurrency": 32, "timeoutMs": 30000}
 * 输出 (stdout, JSON):
 *   {"results": [{"host", "port", "success", "responseTime",
 *                  "exit": {...} | null, "error": string | null}]}
 * 进度日志写 stderr。
 */

import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns/promises';
import { Duplex } from 'node:stream';
import { randomUUID, randomInt, randomBytes, createHash, createHmac } from 'node:crypto';

const SSTP_PATH = '/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/';
const TARGET_HOST = 'www.iplocate.io';
const TARGET_PORT = 443;
const TCP_MSS = 1400;
const EMPTY = Buffer.alloc(0);

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------
const u16 = (buf, off) => (buf[off] << 8) | buf[off + 1];
const u32 = (buf, off) => ((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]) >>> 0;

function internetChecksum(buf) {
  let sum = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) sum += (buf[i] << 8) | buf[i + 1];
  if (buf.length % 2) sum += buf[buf.length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

const ipv4ToBytes = (ip) => Buffer.from(ip.split('.').map(Number));
const bytesToIpv4 = (b) => [...b].join('.');

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// ---------------------------------------------------------------------------
// MS-CHAPv2 (RFC 2759) + MPPE 主密钥 (RFC 3079), 与 sstp/mschap.go 一致
// Node 17+ 的 OpenSSL 3 默认禁用 MD4 / DES, 这里用纯 JS 实现 (只需 MD4 摘要和 DES 单块加密)
// ---------------------------------------------------------------------------
function md4(input) {
  const bitLen = input.length * 8;
  const padLen = ((input.length + 8) >> 6 << 6) + 64;
  const msg = Buffer.alloc(padLen);
  input.copy(msg);
  msg[input.length] = 0x80;
  msg.writeUInt32LE(bitLen >>> 0, padLen - 8);
  msg.writeUInt32LE(Math.floor(bitLen / 0x100000000), padLen - 4);
  const rotl = (x, n) => (x << n) | (x >>> (32 - n));
  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
  const x = new Array(16);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) x[i] = msg.readUInt32LE(off + 4 * i);
    const [aa, bb, cc, dd] = [a, b, c, d];
    const f = (p, q, r) => (p & q) | (~p & r);
    const g = (p, q, r) => (p & q) | (p & r) | (q & r);
    const h = (p, q, r) => p ^ q ^ r;
    for (const i of [0, 4, 8, 12]) {
      a = rotl((a + f(b, c, d) + x[i]) | 0, 3);
      d = rotl((d + f(a, b, c) + x[i + 1]) | 0, 7);
      c = rotl((c + f(d, a, b) + x[i + 2]) | 0, 11);
      b = rotl((b + f(c, d, a) + x[i + 3]) | 0, 19);
    }
    for (const i of [0, 1, 2, 3]) {
      a = rotl((a + g(b, c, d) + x[i] + 0x5a827999) | 0, 3);
      d = rotl((d + g(a, b, c) + x[i + 4] + 0x5a827999) | 0, 5);
      c = rotl((c + g(d, a, b) + x[i + 8] + 0x5a827999) | 0, 9);
      b = rotl((b + g(c, d, a) + x[i + 12] + 0x5a827999) | 0, 13);
    }
    for (const i of [0, 2, 1, 3]) {
      a = rotl((a + h(b, c, d) + x[i] + 0x6ed9eba1) | 0, 3);
      d = rotl((d + h(a, b, c) + x[i + 8] + 0x6ed9eba1) | 0, 9);
      c = rotl((c + h(d, a, b) + x[i + 4] + 0x6ed9eba1) | 0, 11);
      b = rotl((b + h(c, d, a) + x[i + 12] + 0x6ed9eba1) | 0, 15);
    }
    a = (a + aa) | 0; b = (b + bb) | 0; c = (c + cc) | 0; d = (d + dd) | 0;
  }
  const out = Buffer.alloc(16);
  [a, b, c, d].forEach((v, i) => out.writeInt32LE(v, 4 * i));
  return out;
}

const DES_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
const DES_FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
const DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
const DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
const DES_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
const DES_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];
const DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const DES_S = [
  [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
];

// DES 单块加密 (按位数组实现, 只在认证时调用 3 次, 不在乎性能); key / block 均为 8 字节
function desEncryptBlock(key, block) {
  const toBits = (buf) => [...buf].flatMap((byte) => [7, 6, 5, 4, 3, 2, 1, 0].map((i) => (byte >> i) & 1));
  const permute = (bits, table) => table.map((i) => bits[i - 1]);
  const keyBits = permute(toBits(key), DES_PC1);
  let c = keyBits.slice(0, 28);
  let d = keyBits.slice(28);
  const subkeys = DES_SHIFTS.map((s) => {
    c = [...c.slice(s), ...c.slice(0, s)];
    d = [...d.slice(s), ...d.slice(0, s)];
    return permute([...c, ...d], DES_PC2);
  });
  const ip = permute(toBits(block), DES_IP);
  let l = ip.slice(0, 32);
  let r = ip.slice(32);
  for (const k of subkeys) {
    const x = permute(r, DES_E).map((bit, i) => bit ^ k[i]);
    const s = [];
    for (let i = 0; i < 8; i++) {
      const six = x.slice(6 * i, 6 * i + 6);
      const v = DES_S[i][(six[0] << 5) | (six[5] << 4) | (six[1] << 3) | (six[2] << 2) | (six[3] << 1) | six[4]];
      s.push((v >> 3) & 1, (v >> 2) & 1, (v >> 1) & 1, v & 1);
    }
    const f = permute(s, DES_P);
    [l, r] = [r, l.map((bit, i) => bit ^ f[i])];
  }
  const bits = permute([...r, ...l], DES_FP);
  return Buffer.from(Array.from({ length: 8 }, (_, i) => bits.slice(8 * i, 8 * i + 8).reduce((v, bit) => (v << 1) | bit, 0)));
}

// 7 字节密钥扩展成 8 字节 (校验位不管) 后加密
function desEncrypt7(key7, block) {
  const k = Buffer.from([
    key7[0],
    (key7[0] << 7) | (key7[1] >> 1),
    (key7[1] << 6) | (key7[2] >> 2),
    (key7[2] << 5) | (key7[3] >> 3),
    (key7[3] << 4) | (key7[4] >> 4),
    (key7[4] << 3) | (key7[5] >> 5),
    (key7[5] << 2) | (key7[6] >> 6),
    key7[6] << 1,
  ].map((v) => v & 0xff));
  return desEncryptBlock(k, block);
}

const sha1 = (...parts) => {
  const h = createHash('sha1');
  for (const p of parts) h.update(p);
  return h.digest();
};

// 返回 49 字节的 Response 值 (PeerChallenge 16 + 保留 8 + NT-Response 24 + Flags 1) 和 HLAK
function mschapv2(authChallenge, peerChallenge, username, password) {
  const pwHash = md4(Buffer.from(password, 'utf16le'));
  const challenge = sha1(peerChallenge, authChallenge, Buffer.from(username, 'utf8')).subarray(0, 8);
  const z = Buffer.alloc(21);
  pwHash.copy(z);
  const nt = Buffer.concat([0, 1, 2].map((i) => desEncrypt7(z.subarray(7 * i, 7 * i + 7), challenge)));
  const response = Buffer.alloc(49);
  peerChallenge.copy(response);
  nt.copy(response, 24);

  const master = sha1(md4(pwHash), nt, Buffer.from('This is the MPPE Master Key')).subarray(0, 16);
  const pad1 = Buffer.alloc(40);
  const pad2 = Buffer.alloc(40, 0xf2);
  const send = sha1(master, pad1, Buffer.from('On the client side, this is the send key; on the server side, it is the receive key.'), pad2).subarray(0, 16);
  const recv = sha1(master, pad1, Buffer.from('On the client side, this is the receive key; on the server side, it is the send key.'), pad2).subarray(0, 16);
  // HLAK = 客户端 MasterReceiveKey | MasterSendKey (MS-SSTP 3.2.5.2.3, 和 sstp-client 一致)
  return { response, hlak: Buffer.concat([recv, send]) };
}

// ---------------------------------------------------------------------------
// 套接字字节读取器: 在 TLS socket 之上提供 readBytes / readLine
// ---------------------------------------------------------------------------
class ByteReader {
  constructor(socket) {
    this.buffer = EMPTY;
    this.waiters = [];
    this.listeners = [];
    this.error = null;
    socket.on('data', (chunk) => {
      this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;
      this.pump();
    });
    const fail = (err) => {
      if (!this.error) this.error = err;
      this.pump();
    };
    socket.on('error', fail);
    socket.on('close', () => fail(new Error('socket closed')));
  }
  pump() {
    while (this.waiters.length) {
      const w = this.waiters[0];
      if (this.buffer.length >= w.n) {
        this.waiters.shift();
        const out = this.buffer.subarray(0, w.n);
        this.buffer = this.buffer.subarray(w.n);
        w.resolve(out);
      } else if (this.error) {
        this.waiters.shift();
        w.reject(this.error);
      } else {
        break;
      }
    }
    const listeners = this.listeners;
    this.listeners = [];
    for (const resolve of listeners) resolve();
  }
  readBytes(n) {
    if (this.buffer.length >= n) {
      const out = this.buffer.subarray(0, n);
      this.buffer = this.buffer.subarray(n);
      return Promise.resolve(out);
    }
    if (this.error) return Promise.reject(this.error);
    return new Promise((resolve, reject) => this.waiters.push({ n, resolve, reject }));
  }
  waitForData() {
    return new Promise((resolve) => this.listeners.push(resolve));
  }
  async readLine(timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const idx = this.buffer.indexOf(0x0a);
      if (idx >= 0) {
        const line = this.buffer.subarray(0, idx).toString('latin1').replace(/\r$/, '');
        this.buffer = this.buffer.subarray(idx + 1);
        return line;
      }
      if (this.error) throw this.error;
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error('read line timeout');
      await Promise.race([
        this.waitForData(),
        new Promise((r) => setTimeout(r, Math.min(remaining, 250))),
      ]);
    }
  }
}

// ---------------------------------------------------------------------------
// SSTP + PPP 客户端 (单个节点)
// ---------------------------------------------------------------------------
class SstpClient {
  constructor({ host, port, username, password }, timeoutMs) {
    this.host = host;
    this.port = port;
    this.username = username ?? 'vpn';
    this.password = password ?? 'vpn';
    this.timeoutMs = timeoutMs;
    this.pppId = 1;
    this.socket = null;
    this.reader = null;
    this.deadline = Date.now() + timeoutMs;
  }

  remaining() {
    const ms = this.deadline - Date.now();
    if (ms <= 0) throw new Error('check timed out');
    return ms;
  }

  async connect() {
    const socket = tls.connect({
      host: this.host,
      port: this.port,
      servername: net.isIP(this.host) ? undefined : this.host,
      rejectUnauthorized: false, // SSTP 节点多为自签证书; 可用性检测不依赖证书校验
    });
    this.socket = socket;
    await withTimeout(
      new Promise((resolve, reject) => {
        socket.once('secureConnect', resolve);
        socket.once('error', reject);
      }),
      Math.min(this.remaining(), 10000),
      'SSTP server connection timed out',
    );
    this.certRaw = socket.getPeerCertificate()?.raw ?? EMPTY; // crypto binding 要用服务器证书的哈希
    this.reader = new ByteReader(socket);
  }

  write(buf) {
    return new Promise((resolve, reject) => {
      this.socket.write(buf, (err) => (err ? reject(err) : resolve()));
    });
  }

  // --- SSTP 帧 ---
  buildDataPacket(pppFrame) {
    const len = 6 + pppFrame.length;
    const packet = Buffer.alloc(len);
    packet[0] = 0x10;
    packet[1] = 0x00;
    packet[2] = ((len >> 8) & 0x0f) | 0x80;
    packet[3] = len & 0xff;
    packet[4] = 0xff;
    packet[5] = 0x03;
    pppFrame.copy(packet, 6);
    return packet;
  }

  buildControlPacket(messageType, attributes) {
    const attrsLen = attributes.reduce((s, a) => s + 4 + a.data.length, 0);
    const packet = Buffer.alloc(8 + attrsLen);
    packet[0] = 0x10;
    packet[1] = 0x01;
    packet.writeUInt16BE((8 + attrsLen) | 0x8000, 2);
    packet.writeUInt16BE(messageType, 4);
    packet.writeUInt16BE(attributes.length, 6);
    let offset = 8;
    for (const attr of attributes) {
      packet[offset] = 0;
      packet[offset + 1] = attr.id;
      packet.writeUInt16BE(4 + attr.data.length, offset + 2);
      attr.data.copy(packet, offset + 4);
      offset += 4 + attr.data.length;
    }
    return packet;
  }

  // 控制包 body (已去掉 4 字节 SSTP 头): 消息类型 2 + 属性数 2 + 属性 (保留 1 + ID 1 + 长度 2 + 值)
  parseControl(body) {
    const attrs = new Map();
    if (body.length < 4) return { type: 0, attrs };
    for (let offset = 4; offset + 4 <= body.length;) {
      const length = u16(body, offset + 2) & 0x0fff;
      if (length < 4 || offset + length > body.length) break;
      attrs.set(body[offset + 1], body.subarray(offset + 4, offset + length));
      offset += length;
    }
    return { type: u16(body, 0), attrs };
  }

  // Call Connected + crypto binding (MS-SSTP 3.2.5.2), 与 sstp/sstp.go 的 callConnected 一致:
  // 证书哈希 + 用 HLAK 派生的 CMK 对整包算 Compound MAC
  buildCallConnected(bindRequest, hlak) {
    const useSha256 = (bindRequest[3] & 0x02) !== 0;
    const algorithm = useSha256 ? 'sha256' : 'sha1';
    const value = Buffer.alloc(100); // 保留 3 + hash 协议 1 + nonce 32 + 证书哈希 32 + Compound MAC 32
    value[3] = useSha256 ? 2 : 1;
    bindRequest.copy(value, 4, 4, 36);
    createHash(algorithm).update(this.certRaw).digest().copy(value, 36);
    const packet = this.buildControlPacket(0x0004, [{ id: 3, data: value }]);
    // CMK = PRF+(HLAK, "SSTP inner method derived CMK", len) 的第一块 T1 = HMAC(HLAK, seed | len(2 字节小端) | 0x01)
    const size = useSha256 ? 32 : 20;
    const seed = Buffer.concat([Buffer.from('SSTP inner method derived CMK'), Buffer.from([size & 0xff, size >> 8, 1])]);
    const cmk = createHmac(algorithm, hlak).update(seed).digest();
    createHmac(algorithm, cmk).update(packet).digest().copy(packet, packet.length - 32);
    return packet;
  }

  async readPacket(timeoutCapMs = 10000) {
    const cap = Math.min(this.remaining(), timeoutCapMs);
    const header = await withTimeout(this.reader.readBytes(4), cap, 'SSTP read timeout');
    const length = u16(header, 2) & 0x0fff;
    if (length < 4) throw new Error('Invalid SSTP packet length');
    const body = length > 4
      ? await withTimeout(this.reader.readBytes(length - 4), cap, 'SSTP packet body read timeout')
      : EMPTY;
    return { isControl: (header[1] & 1) !== 0, body };
  }

  // --- PPP 帧 ---
  buildConfigurePacket(protocol, code, id, options) {
    const optLen = options.reduce((s, o) => s + 2 + o.data.length, 0);
    const frame = Buffer.alloc(6 + optLen);
    frame.writeUInt16BE(protocol, 0);
    frame[2] = code;
    frame[3] = id;
    frame.writeUInt16BE(4 + optLen, 4);
    let offset = 6;
    for (const opt of options) {
      frame[offset] = opt.type;
      frame[offset + 1] = 2 + opt.data.length;
      opt.data.copy(frame, offset + 2);
      offset += 2 + opt.data.length;
    }
    return frame;
  }

  buildPapRequest(id) {
    const user = Buffer.from(this.username, 'utf8');
    const pass = Buffer.from(this.password, 'utf8');
    const papLen = 6 + user.length + pass.length;
    const frame = Buffer.alloc(2 + papLen);
    frame.writeUInt16BE(0xc023, 0);
    frame[2] = 1;
    frame[3] = id;
    frame.writeUInt16BE(papLen, 4);
    frame[6] = user.length;
    user.copy(frame, 7);
    frame[7 + user.length] = pass.length;
    pass.copy(frame, 8 + user.length);
    return frame;
  }

  // 解析服务器发来的 PPP 帧 (body 已去掉 SSTP 头; 可能带 FF03)
  parsePppFrame(data) {
    const offset = data.length >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
    if (data.length - offset < 4) return null;
    const protocol = u16(data, offset);
    if (protocol === 0x0021) {
      return { protocol, ipPacket: data.subarray(offset + 2) };
    }
    if (data.length - offset < 6) return null;
    return {
      protocol,
      code: data[offset + 2],
      id: data[offset + 3],
      payload: data.subarray(offset + 6),
      rawPacket: data.subarray(offset),
    };
  }

  parseOptions(data) {
    const options = [];
    for (let offset = 0; offset + 2 <= data.length;) {
      const type = data[offset];
      const length = data[offset + 1];
      if (length < 2 || offset + length > data.length) break;
      options.push({ type, data: data.subarray(offset + 2, offset + length) });
      offset += length;
    }
    return options;
  }

  // 完成 SSTP 握手 + PPP 协商, 返回服务器分配的隧道内 IPv4
  async establishTunnel() {
    const hostHeader = this.port === 443 ? this.host : `${this.host}:${this.port}`;
    const httpRequest = Buffer.from(
      `SSTP_DUPLEX_POST ${SSTP_PATH} HTTP/1.1\r\n`
      + `Host: ${hostHeader}\r\n`
      + 'Content-Length: 18446744073709551615\r\n'
      + `SSTPCORRELATIONID: {${randomUUID()}}\r\n\r\n`,
      'latin1',
    );
    const encapsulated = Buffer.alloc(2);
    encapsulated.writeUInt16BE(1, 0);
    const mru = Buffer.alloc(2);
    mru.writeUInt16BE(1500, 0);
    await withTimeout(
      this.write(Buffer.concat([
        httpRequest,
        this.buildControlPacket(0x0001, [{ id: 1, data: encapsulated }]),
        this.buildDataPacket(this.buildConfigurePacket(0xc021, 1, this.pppId++, [{ type: 1, data: mru }])),
      ])),
      Math.min(this.remaining(), 10000),
      'SSTP HTTP handshake request timed out',
    );

    const statusLine = await this.reader.readLine(Math.min(this.remaining(), 10000));
    for (;;) {
      const line = await this.reader.readLine(Math.min(this.remaining(), 10000));
      if (line === '') break;
    }
    if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine || '')) {
      throw new Error(`SSTP HTTP handshake failed: ${statusLine || 'invalid status'}`);
    }

    let localLcpAcked = false;
    let peerLcpAcked = false;
    let authProto = 0; // 服务器在 LCP 里要求的认证: 0 = 不认证, 0xc023 = PAP, 0xc223 = CHAP
    let authAlgo = 0; // CHAP 算法: 0x81 = MS-CHAPv2, 0x05 = MD5
    let authNaks = 0;
    let papSent = false;
    let authDone = false;
    let hlak = Buffer.alloc(32); // PAP / CHAP-MD5 没有密钥材料, HLAK 按规范取全 0
    let connectAcked = false;
    let bindRequest = null;
    let connectedSent = false;
    let ipcpStarted = false;
    let ipcpFinished = false;
    let assignedIp = null;

    const lcpOpen = () => localLcpAcked && peerLcpAcked;
    const sendPapIfReady = async () => {
      if (!lcpOpen() || authProto !== 0xc023 || papSent) return;
      await this.write(this.buildDataPacket(this.buildPapRequest(this.pppId++)));
      papSent = true;
    };
    // 认证完成 (或无需认证) 后: 先发 SSTP Call Connected (带 crypto binding), 再开始 IPCP
    const startIpcpIfReady = async () => {
      if (!lcpOpen() || !connectAcked || ipcpStarted || (authProto && !authDone)) return;
      if (bindRequest && !connectedSent) {
        await this.write(this.buildCallConnected(bindRequest, hlak));
        connectedSent = true;
      }
      await this.write(this.buildDataPacket(this.buildConfigurePacket(0x8021, 1, this.pppId++, [
        { type: 3, data: Buffer.alloc(4) },
      ])));
      ipcpStarted = true;
    };

    for (let round = 0; round < 100 && !ipcpFinished; round++) {
      const packet = await this.readPacket();
      if (packet.isControl) {
        const { type, attrs } = this.parseControl(packet.body);
        if (type === 0x0002) { // Call Connect Ack: 记下 crypto binding 请求 (nonce + 支持的哈希)
          connectAcked = true;
          const req = attrs.get(4);
          bindRequest = req && req.length >= 36 ? req : null;
          await startIpcpIfReady();
        } else if (type === 0x0003) {
          throw new Error('SSTP Call Connect Request rejected');
        } else if (type === 0x0005 || type === 0x0006) {
          throw new Error('SSTP server aborted the call');
        } else if (type === 0x0008) { // Echo Request
          await this.write(this.buildControlPacket(0x0009, []));
        }
        continue;
      }

      const ppp = this.parsePppFrame(packet.body);
      if (!ppp) continue;

      if (ppp.protocol === 0xc021) { // LCP
        if (ppp.code === 1) { // Configure-Request → Ack (认证方式不支持时 Nak)
          const authOption = this.parseOptions(ppp.payload).find((o) => o.type === 3);
          let proto = 0;
          let algo = 0;
          if (authOption && authOption.data.length >= 2) {
            proto = u16(authOption.data, 0);
            algo = authOption.data.length === 3 ? authOption.data[2] : 0;
            const supported = proto === 0xc023 || (proto === 0xc223 && (algo === 0x81 || algo === 0x05));
            if (!supported) {
              // 和 sstp/ppp.go 一样 Nak 并建议 MS-CHAPv2, 服务器会换一种认证方式重新发 Configure-Request
              if (++authNaks > 3) {
                throw new Error(`SSTP unsupported PPP authentication protocol: 0x${proto.toString(16)}`);
              }
              await this.write(this.buildDataPacket(this.buildConfigurePacket(0xc021, 3, ppp.id, [
                { type: 3, data: Buffer.from([0xc2, 0x23, 0x81]) },
              ])));
              continue;
            }
          }
          authProto = proto;
          authAlgo = algo;
          const ack = Buffer.from(ppp.rawPacket);
          ack[2] = 2;
          await this.write(this.buildDataPacket(ack));
          peerLcpAcked = true;
          await sendPapIfReady();
          await startIpcpIfReady();
        } else if (ppp.code === 2) { // Configure-Ack
          localLcpAcked = true;
          await sendPapIfReady();
          await startIpcpIfReady();
        } else if (ppp.code === 5) { // Terminate-Request
          throw new Error('SSTP server terminated the PPP session');
        } else if (ppp.code === 9) { // Echo-Request → Echo-Reply (没有协商 Magic-Number, 填 0)
          await this.write(this.buildDataPacket(Buffer.from([0xc0, 0x21, 10, ppp.id, 0, 8, 0, 0, 0, 0])));
        }
        continue;
      }

      if (ppp.protocol === 0xc023) { // PAP
        if (ppp.code === 2) {
          authDone = true;
          await startIpcpIfReady();
        } else if (ppp.code === 3) {
          throw new Error('SSTP PAP authentication failed');
        }
        continue;
      }

      if (ppp.protocol === 0xc223) { // CHAP
        if (ppp.code === 1) { // Challenge → Response
          const size = ppp.payload[0];
          if (!size || ppp.payload.length < 1 + size) continue;
          const challenge = ppp.payload.subarray(1, 1 + size);
          let value;
          if (authAlgo === 0x81 && challenge.length === 16) {
            ({ response: value, hlak } = mschapv2(challenge, randomBytes(16), this.username, this.password));
          } else if (authAlgo === 0x05) {
            value = createHash('md5').update(Buffer.from([ppp.id])).update(this.password, 'utf8').update(challenge).digest();
          } else {
            throw new Error(`SSTP unsupported CHAP algorithm: 0x${authAlgo.toString(16)}`);
          }
          const user = Buffer.from(this.username, 'utf8');
          const frame = Buffer.alloc(7 + value.length + user.length);
          frame.writeUInt16BE(0xc223, 0);
          frame[2] = 2;
          frame[3] = ppp.id;
          frame.writeUInt16BE(frame.length - 2, 4);
          frame[6] = value.length;
          value.copy(frame, 7);
          user.copy(frame, 7 + value.length);
          await this.write(this.buildDataPacket(frame));
        } else if (ppp.code === 3) { // Success
          authDone = true;
          await startIpcpIfReady();
        } else if (ppp.code === 4) { // Failure
          throw new Error(`SSTP CHAP authentication failed: ${ppp.payload.toString('latin1')}`);
        }
        continue;
      }

      if (ppp.protocol === 0x8021) { // IPCP
        if (ppp.code === 1) { // Configure-Request → Ack
          const ack = Buffer.from(ppp.rawPacket);
          ack[2] = 2;
          await this.write(this.buildDataPacket(ack));
          await startIpcpIfReady();
        } else if (ppp.code === 3) { // Configure-Nak → 用建议地址重发请求
          const addressOption = this.parseOptions(ppp.payload).find((o) => o.type === 3);
          if (addressOption && addressOption.data.length === 4) {
            assignedIp = bytesToIpv4(addressOption.data);
            await this.write(this.buildDataPacket(this.buildConfigurePacket(0x8021, 1, this.pppId++, [
              { type: 3, data: addressOption.data },
            ])));
            ipcpStarted = true;
          }
        } else if (ppp.code === 2) { // Configure-Ack → 协商完成
          const addressOption = this.parseOptions(ppp.payload).find((o) => o.type === 3);
          if (addressOption && addressOption.data.length === 4) {
            assignedIp = bytesToIpv4(addressOption.data);
          }
          ipcpFinished = true;
        }
      }
    }

    if (!assignedIp) throw new Error('SSTP did not assign an IPv4 address');
    this.assignedIp = assignedIp;
    return assignedIp;
  }

  close() {
    try { this.socket?.destroy(); } catch { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// PPP 之上的单条 TCP 连接, 包装成 Duplex 供 tls.connect 使用
// ---------------------------------------------------------------------------
class TcpOverPpp extends Duplex {
  constructor(client, sourceIp, destinationIp, destinationPort) {
    super();
    this.client = client;
    this.sourceAddress = ipv4ToBytes(sourceIp);
    this.destinationAddress = ipv4ToBytes(destinationIp);
    this.destinationPort = destinationPort;
    this.sourcePort = 10000 + randomInt(50000);
    this.seq = randomInt(0xffffffff);
    this.ack = 0;
    this.finReceived = false;
    this.synAckWaiter = null;
    this.dead = false;
    this.outOfOrder = new Map(); // seq → { payload, fin }: 先到的乱序段, 等缺口补齐再交付
  }

  buildFrame(flags, payload = EMPTY) {
    const tcpLength = 20 + payload.length;
    const ipLength = 20 + tcpLength;
    const frame = Buffer.alloc(8 + ipLength);
    const ip = frame.subarray(8);
    // SSTP 数据包头 + PPP FF03 + IPv4 协议号
    frame[0] = 0x10;
    frame[1] = 0x00;
    frame[2] = (((8 + ipLength) >> 8) & 0x0f) | 0x80;
    frame[3] = (8 + ipLength) & 0xff;
    frame[4] = 0xff;
    frame[5] = 0x03;
    frame[6] = 0x00;
    frame[7] = 0x21;
    // IPv4 头
    ip[0] = 0x45;
    ip.writeUInt16BE(ipLength, 2);
    ip.writeUInt16BE(randomInt(65536), 4);
    ip[6] = 0x40; // DF
    ip[8] = 64; // TTL
    ip[9] = 6; // TCP
    this.sourceAddress.copy(ip, 12);
    this.destinationAddress.copy(ip, 16);
    ip.writeUInt16BE(internetChecksum(ip.subarray(0, 20)), 10);
    // TCP 头
    const tcp = ip.subarray(20);
    tcp.writeUInt16BE(this.sourcePort, 0);
    tcp.writeUInt16BE(this.destinationPort, 2);
    tcp.writeUInt32BE(this.seq >>> 0, 4);
    tcp.writeUInt32BE(this.ack >>> 0, 8);
    tcp[12] = 0x50;
    tcp[13] = flags;
    tcp.writeUInt16BE(65535, 14);
    if (payload.length) payload.copy(tcp, 20);
    const pseudo = Buffer.concat([
      this.sourceAddress,
      this.destinationAddress,
      Buffer.from([0, 6, tcpLength >> 8, tcpLength & 0xff]),
      tcp.subarray(0, tcpLength),
    ]);
    tcp.writeUInt16BE(internetChecksum(pseudo), 16);
    return frame;
  }

  matchIncoming(ipPacket) {
    if (ipPacket.length < 40 || ipPacket[9] !== 6) return null;
    const ihl = (ipPacket[0] & 0x0f) * 4;
    if (ipPacket.length < ihl + 20) return null;
    if (u16(ipPacket, ihl) !== this.destinationPort) return null;
    if (u16(ipPacket, ihl + 2) !== this.sourcePort) return null;
    return {
      flags: ipPacket[ihl + 13],
      sequence: u32(ipPacket, ihl + 4),
      payloadOffset: ihl + ((ipPacket[ihl + 12] >> 4) & 0x0f) * 4,
    };
  }

  async handshake() {
    const synAck = new Promise((resolve, reject) => {
      this.synAckWaiter = { resolve, reject };
    });
    const syn = this.buildFrame(0x02); // SYN
    this.seq = (this.seq + 1) >>> 0;
    await this.client.write(syn);
    // 没有完整的重传机制, 至少重发 SYN: 隧道刚建好时首个包被丢的情况并不少见
    const resend = setInterval(() => this.client.write(syn).catch(() => {}), 3000);
    let incoming;
    try {
      incoming = await withTimeout(synAck, Math.min(this.client.remaining(), 10000), 'TCP handshake through SSTP timed out');
    } finally {
      clearInterval(resend);
    }
    this.ack = (incoming.sequence + 1) >>> 0;
    await this.client.write(this.buildFrame(0x10)); // ACK
  }

  // SSTP 泵: 在 TCP 阶段持续调用, 把 PPP 里的 IP 包喂给本连接
  async pumpOnce() {
    const packet = await this.client.readPacket(60000);
    if (packet.isControl) return;
    const ppp = this.client.parsePppFrame(packet.body);
    if (!ppp || ppp.protocol !== 0x0021) return;
    const incoming = this.matchIncoming(ppp.ipPacket);
    if (!incoming) return;

    if (this.synAckWaiter && (incoming.flags & 0x12) === 0x12) {
      const waiter = this.synAckWaiter;
      this.synAckWaiter = null;
      waiter.resolve(incoming);
      return;
    }

    if (this.synAckWaiter) return; // 握手完成前的其他段一律忽略

    if (incoming.flags & 0x04) { // RST
      this.finReceived = true;
      this.push(null);
      return;
    }

    let payload = incoming.payloadOffset < ppp.ipPacket.length
      ? ppp.ipPacket.subarray(incoming.payloadOffset)
      : EMPTY;
    const fin = (incoming.flags & 0x01) !== 0;
    if (!payload.length && !fin) return; // 纯 ACK

    // 按序号重组: 重复段丢弃 (部分重叠的裁掉头部), 超前的段先缓存;
    // 两种情况都立刻回 ACK, 让对端尽快重传缺口
    const offset = (incoming.sequence - this.ack) | 0;
    if (offset < 0) {
      if (-offset >= payload.length) {
        this.client.write(this.buildFrame(0x10)).catch(() => {});
        return;
      }
      payload = payload.subarray(-offset);
    } else if (offset > 0) {
      if (!this.outOfOrder.has(incoming.sequence)) {
        this.outOfOrder.set(incoming.sequence, { payload: Buffer.from(payload), fin });
      }
      this.client.write(this.buildFrame(0x10)).catch(() => {});
      return;
    }

    this.deliver(payload, fin);
    while (!this.finReceived && this.outOfOrder.has(this.ack)) {
      const next = this.outOfOrder.get(this.ack);
      this.outOfOrder.delete(this.ack);
      this.deliver(next.payload, next.fin);
    }
    try {
      await this.client.write(this.buildFrame(this.finReceived ? 0x11 : 0x10)); // ACK / FIN+ACK
    } catch { /* ignore */ }
  }

  deliver(payload, fin) {
    if (payload.length) {
      this.ack = (this.ack + payload.length) >>> 0;
      this.push(Buffer.from(payload));
    }
    if (fin) {
      this.finReceived = true;
      this.ack = (this.ack + 1) >>> 0;
      this.push(null);
    }
  }

  async pumpLoop() {
    while (!this.dead && !this.finReceived) {
      try {
        await this.pumpOnce();
      } catch {
        if (!this.dead) this.push(null);
        return;
      }
    }
  }

  _read() {}

  _write(chunk, _encoding, callback) {
    (async () => {
      try {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        for (let offset = 0; offset < bytes.length; offset += TCP_MSS) {
          const segment = bytes.subarray(offset, Math.min(offset + TCP_MSS, bytes.length));
          await this.client.write(this.buildFrame(0x18, segment)); // PSH+ACK
          this.seq = (this.seq + segment.length) >>> 0;
        }
        callback();
      } catch (err) {
        callback(err);
      }
    })();
  }

  _final(callback) {
    this.client.write(this.buildFrame(0x11)).catch(() => {}).finally(() => callback()); // FIN+ACK
  }

  _destroy(err, callback) {
    this.dead = true;
    if (this.synAckWaiter) {
      this.synAckWaiter.reject(err || new Error('tcp session destroyed'));
      this.synAckWaiter = null;
    }
    callback(err);
  }
}

// ---------------------------------------------------------------------------
// 单节点检测: 建隧道 → 经隧道 HTTPS GET iplocate /api/lookup → 出口信息
// ---------------------------------------------------------------------------
async function checkNode(node, timeoutMs) {
  const startedAt = Date.now();
  const client = new SstpClient(node, timeoutMs);
  let session = null;
  try {
    const targetIpPromise = dns.resolve4(TARGET_HOST).then((ips) => ips[0]);
    await client.connect();
    const [sourceIp, targetIp] = await Promise.all([client.establishTunnel(), targetIpPromise]);
    if (!targetIp) throw new Error(`cannot resolve ${TARGET_HOST}`);

    session = new TcpOverPpp(client, sourceIp, targetIp, TARGET_PORT);
    const pump = session.pumpLoop();
    pump.catch(() => {});
    await session.handshake();

    const exit = await withTimeout(
      new Promise((resolve, reject) => {
        const tlsSocket = tls.connect({
          socket: session,
          servername: TARGET_HOST,
          rejectUnauthorized: true,
        });
        const chunks = [];
        tlsSocket.once('secureConnect', () => {
          tlsSocket.write(
            `GET /api/lookup HTTP/1.1\r\nHost: ${TARGET_HOST}\r\n`
            + 'User-Agent: Mozilla/5.0 gate-sstp-check/1.0\r\n'
            + 'Accept: application/json\r\nConnection: close\r\n\r\n',
          );
        });
        tlsSocket.on('data', (chunk) => chunks.push(chunk));
        tlsSocket.once('end', () => {
          try {
            const text = Buffer.concat(chunks).toString('utf8');
            const headerEnd = text.indexOf('\r\n\r\n');
            if (headerEnd === -1) throw new Error('Invalid target response headers');
            const headerText = text.slice(0, headerEnd);
            const statusMatch = headerText.split('\r\n')[0].match(/HTTP\/\d(?:\.\d)?\s+(\d+)/i);
            const statusCode = statusMatch ? Number(statusMatch[1]) : NaN;
            if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) {
              const err = new Error(`Target /api/lookup request failed: ${headerText.split('\r\n')[0]}`);
              // 能收到目标的 HTTP 响应, 说明隧道本身已端到端打通, 只是出口信息拿不到
              if (Number.isFinite(statusCode)) err.httpStatus = statusCode;
              throw err;
            }
            let bodyText = text.slice(headerEnd + 4);
            if (/transfer-encoding:\s*chunked/i.test(headerText)) {
              let cursor = 0;
              let output = '';
              while (cursor < bodyText.length) {
                const lineEnd = bodyText.indexOf('\r\n', cursor);
                if (lineEnd === -1) break;
                const size = parseInt(bodyText.slice(cursor, lineEnd).split(';')[0].trim(), 16);
                if (!Number.isFinite(size) || size === 0) break;
                cursor = lineEnd + 2;
                output += bodyText.slice(cursor, cursor + size);
                cursor += size + 2;
              }
              bodyText = output || bodyText;
            }
            const json = JSON.parse(bodyText.trim());
            if (!json || !json.ip) throw new Error('Target /api/lookup returned no ip');
            resolve({
              ...json,
              asn: json.asn
                ? { ...json.asn, org: json.asn.name, descr: json.asn.name }
                : json.asn,
              // 未返回 privacy 时给 null, 交给 vpngate.py 按 ASN / 主机名判断, 而不是一律当住宅
              is_datacenter: json.privacy?.is_hosting ?? null,
            });
          } catch (err) {
            reject(err);
          }
        });
        tlsSocket.once('error', reject);
      }),
      client.remaining(),
      'target request timed out',
    );
    return {
      host: node.host,
      port: node.port,
      success: true,
      responseTime: Date.now() - startedAt,
      colo: null,
      exit,
      error: null,
    };
  } catch (error) {
    return {
      host: node.host,
      port: node.port,
      success: false,
      responseTime: Date.now() - startedAt,
      colo: null,
      exit: null,
      error: error?.message || String(error),
      httpStatus: error?.httpStatus ?? null,
    };
  } finally {
    try { session?.destroy(); } catch { /* ignore */ }
    client.close();
  }
}

// ---------------------------------------------------------------------------
// 批量运行
// ---------------------------------------------------------------------------
async function main() {
  const input = JSON.parse(await new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', (c) => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  }));
  const nodes = Array.isArray(input.nodes) ? input.nodes : [];
  const concurrency = Math.max(1, input.concurrency || 32);
  const timeoutMs = Math.max(1000, input.timeoutMs || 30000);

  const results = new Array(nodes.length);
  let cursor = 0;
  let done = 0;
  const runWorker = async () => {
    for (;;) {
      const index = cursor++;
      if (index >= nodes.length) return;
      let result = await checkNode(nodes[index], timeoutMs);
      // iplocate 对热门出口 IP (如 SoftEther 共享 NAT 池) 会限流 429:
      // 这类节点隧道本身是通的, 整节点重试一次 (新隧道) 往往就能过
      if (!result.success && /request failed: HTTP\/1\.1 429/.test(result.error || '')) {
        await new Promise((r) => setTimeout(r, 3000));
        const retry = await checkNode(nodes[index], timeoutMs);
        retry.responseTime += result.responseTime;
        result = retry;
      }
      // 仍被限流 (共享出口的节点常见): 隧道已验证可用, 记为成功, 出口信息留空
      if (!result.success && result.httpStatus === 429) {
        result = { ...result, success: true, error: null };
      }
      delete result.httpStatus;
      results[index] = result;
      done += 1;
      const r = results[index];
      console.error(`[${done}/${nodes.length}] ${r.host}:${r.port} ${r.success ? 'OK ' + (r.exit?.ip || '') : 'FAIL ' + (r.error || '')} ${r.responseTime}ms`);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, nodes.length) }, runWorker));
  process.stdout.write(JSON.stringify({ results }));
}

main().catch((err) => {
  console.error(`fatal: ${err?.stack || err}`);
  process.exit(1);
});
