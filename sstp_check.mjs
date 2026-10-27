#!/usr/bin/env node
/**
 * sstp_check.mjs — VPN Gate SSTP 节点批量检测器 (零依赖, Node >= 18)
 * ================================================================
 * 自己实现的 SSTP 客户端: TLS 连接节点 → SSTP_DUPLEX_POST 握手 →
 * PPP 协商 (LCP → PAP → IPCP) → 在 PPP 上跑一条最小 TCP 会话 →
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
import { randomUUID, randomInt } from 'node:crypto';

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
    let papRequired = false;
    let papSent = false;
    let papDone = false;
    let ipcpStarted = false;
    let ipcpFinished = false;
    let assignedIp = null;

    const sendPapIfReady = async () => {
      if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
      await this.write(this.buildDataPacket(this.buildPapRequest(this.pppId++)));
      papSent = true;
    };
    const startIpcpIfReady = async () => {
      if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
      await this.write(this.buildDataPacket(this.buildConfigurePacket(0x8021, 1, this.pppId++, [
        { type: 3, data: Buffer.alloc(4) },
      ])));
      ipcpStarted = true;
    };

    for (let round = 0; round < 50 && !ipcpFinished; round++) {
      const packet = await this.readPacket();
      if (packet.isControl) continue;

      const ppp = this.parsePppFrame(packet.body);
      if (!ppp) continue;

      if (ppp.protocol === 0xc021) { // LCP
        if (ppp.code === 1) { // Configure-Request → Ack
          const authOption = this.parseOptions(ppp.payload).find((o) => o.type === 3);
          if (authOption && authOption.data.length >= 2) {
            const authProtocol = u16(authOption.data, 0);
            if (authProtocol !== 0xc023) {
              throw new Error(`SSTP unsupported PPP authentication protocol: 0x${authProtocol.toString(16)}`);
            }
            papRequired = true;
          }
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
        }
        continue;
      }

      if (ppp.protocol === 0xc023) { // PAP
        if (ppp.code === 2) {
          papDone = true;
          await startIpcpIfReady();
        } else if (ppp.code === 3) {
          throw new Error('SSTP PAP authentication failed');
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
