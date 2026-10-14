/*
 * gate-worker — VLESS(WebSocket) → SSTP(VPN Gate) 精简中转 Worker
 *
 * 只做两件事:
 *   1. GET /<UUID>                       读取 NODES_URL (nodes.txt) → 输出 base64 的 vless 订阅
 *   2. WS  /sstp/<user:pass@host:port>   VLESS 入站 → SSTP 握手 → 转发到 VPN Gate 节点
 *
 * 环境变量:
 *   UUID       必填, VLESS 用户 ID, 同时作为订阅路径
 *   NODES_URL  必填, gate 仓库发布的 nodes.txt 地址
 *   HOST       可选, 订阅里的 sni/host, 默认取访问订阅时的域名
 *
 * sstpConnect() 及其辅助函数改编自 cmliu/edgetunnel (https://github.com/cmliu/edgetunnel),
 * 原作品以 GPL-2.0 授权; 本文件同样以 GPL-2.0 授权发布。
 */
import { connect } from 'cloudflare:sockets';

const CONNECT_TIMEOUT_MS = 9999;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export default {
	async fetch(request, env) {
		const uuid = String(env.UUID || '').trim().toLowerCase();
		if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(uuid)) {
			return new Response('UUID 未配置或格式错误\n', { status: 500 });
		}
		const url = new URL(request.url);

		if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			const proxy = parseSstpPath(url.pathname);
			if (!proxy) return new Response('Not Found\n', { status: 404 });
			return handleVless(request, uuid, proxy);
		}

		if (url.pathname === `/${uuid}`) {
			if (!env.NODES_URL) return new Response('NODES_URL 未配置\n', { status: 500 });
			return buildSubscription(env.NODES_URL, uuid, env.HOST || url.hostname);
		}

		return new Response('Not Found\n', { status: 404 });
	}
};

//////////////////////////////////////////////////订阅///////////////////////////////////////////////

async function buildSubscription(nodesUrl, uuid, host) {
	const response = await fetch(nodesUrl, { cf: { cacheTtl: 300 } });
	if (!response.ok) return new Response(`拉取 nodes.txt 失败: HTTP ${response.status}\n`, { status: 502 });

	const links = [];
	for (const raw of (await response.text()).split('\n')) {
		// 入口域名:443#备注$sstp://user:pass@host:port
		const match = raw.trim().match(/^([^#\s]+?)(?::(\d+))?#(.*?)\$sstp:\/\/(\S+)$/i);
		if (!match) continue;
		const [, entry, port = '443', remark, sstp] = match;
		const path = `/sstp/${sstp}?ed=2560`;
		const params = new URLSearchParams({
			encryption: 'none', security: 'tls', sni: host, fp: 'chrome',
			type: 'ws', host, path
		});
		links.push(`vless://${uuid}@${entry}:${port}?${params}#${encodeURIComponent(remark.trim() || entry)}`);
	}
	if (!links.length) return new Response('nodes.txt 中没有可用节点\n', { status: 502 });

	return new Response(btoa(String.fromCharCode(...textEncoder.encode(links.join('\n')))), {
		headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
	});
}

// /sstp/vpn:vpn@host:port → { username, password, hostname, port }
function parseSstpPath(pathname) {
	const match = decodeURIComponent(pathname).match(/^\/sstp\/(?:([^:@/]+):([^@/]*)@)?([^:@/]+):(\d+)\/?$/i);
	if (!match) return null;
	const [, username = 'vpn', password = 'vpn', hostname, port] = match;
	return { username, password, hostname, port: Number(port) };
}

//////////////////////////////////////////////////VLESS 入站///////////////////////////////////////////////

function handleVless(request, uuid, proxy) {
	const [client, server] = Object.values(new WebSocketPair());
	server.accept();

	const uuidBytes = new Uint8Array(uuid.replace(/-/g, '').match(/../g).map(h => parseInt(h, 16)));
	const earlyData = decodeEarlyData(request.headers.get('sec-websocket-protocol'));
	let remote = null, remoteWriter = null, udpMode = false, headerDone = false;
	let queue = Promise.resolve();

	const closeAll = () => {
		try { remote?.close?.() } catch (e) { }
		try { if (server.readyState <= 1) server.close(1000) } catch (e) { }
	};

	const handleChunk = async chunk => {
		if (headerDone) {
			if (udpMode) return handleDnsOverUdp(chunk, server);
			return remoteWriter.write(chunk);
		}
		headerDone = true;

		const header = parseVlessHeader(chunk, uuidBytes);
		const responseHeader = new Uint8Array([header.version, 0]);

		if (header.command === 2) {
			if (header.port !== 53) throw new Error('仅支持 DNS(53) 的 UDP');
			udpMode = true;
			server.send(responseHeader);
			return handleDnsOverUdp(header.payload, server);
		}

		remote = await sstpConnect(proxy, header.address, header.port);
		remoteWriter = remote.writable.getWriter();
		if (header.payload.byteLength) await remoteWriter.write(header.payload);

		let first = true;
		remote.readable.pipeTo(new WritableStream({
			write(data) {
				if (server.readyState !== 1) throw new Error('WebSocket 已关闭');
				server.send(first ? concatBytes(responseHeader, data) : data);
				first = false;
			}
		})).catch(() => { }).finally(closeAll);
	};

	const enqueue = chunk => {
		queue = queue.then(() => handleChunk(toBytes(chunk))).catch(error => {
			console.error('[gate-worker]', error?.message || error);
			closeAll();
		});
	};

	if (earlyData) enqueue(earlyData);
	server.addEventListener('message', event => enqueue(event.data));
	server.addEventListener('close', closeAll);
	server.addEventListener('error', closeAll);

	return new Response(null, { status: 101, webSocket: client });
}

function parseVlessHeader(data, uuidBytes) {
	if (data.byteLength < 24) throw new Error('VLESS 头部过短');
	for (let i = 0; i < 16; i++) {
		if (data[1 + i] !== uuidBytes[i]) throw new Error('UUID 不匹配');
	}
	let offset = 18 + data[17];
	const command = data[offset++];
	if (command !== 1 && command !== 2) throw new Error(`不支持的 VLESS 命令: ${command}`);
	const port = (data[offset] << 8) | data[offset + 1];
	offset += 2;

	const addressType = data[offset++];
	let address;
	if (addressType === 1) {
		address = data.subarray(offset, offset + 4).join('.');
		offset += 4;
	} else if (addressType === 2) {
		const length = data[offset++];
		address = textDecoder.decode(data.subarray(offset, offset + length));
		offset += length;
	} else if (addressType === 3) {
		throw new Error('SSTP 通道仅支持 IPv4, 不支持 IPv6 目标');
	} else {
		throw new Error(`未知地址类型: ${addressType}`);
	}
	return { version: data[0], command, port, address, payload: data.subarray(offset) };
}

// UDP 仅用于 DNS: VLESS UDP 帧为 [2字节长度][DNS 报文], 改走 DoH 查询
async function handleDnsOverUdp(chunk, webSocket) {
	for (let offset = 0; offset + 2 <= chunk.byteLength;) {
		const length = (chunk[offset] << 8) | chunk[offset + 1];
		const query = chunk.subarray(offset + 2, offset + 2 + length);
		offset += 2 + length;
		const response = await fetch('https://cloudflare-dns.com/dns-query', {
			method: 'POST',
			headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
			body: query
		});
		const answer = new Uint8Array(await response.arrayBuffer());
		if (webSocket.readyState === 1) {
			webSocket.send(concatBytes(new Uint8Array([answer.byteLength >> 8, answer.byteLength & 0xff]), answer));
		}
	}
}

function decodeEarlyData(value) {
	if (!value) return null;
	try {
		const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
		return Uint8Array.from(binary, c => c.charCodeAt(0));
	} catch (e) {
		return null;
	}
}

//////////////////////////////////////////////////工具函数///////////////////////////////////////////////

function toBytes(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	if (typeof data === 'string') return textEncoder.encode(data);
	return new Uint8Array(data || 0);
}

function concatBytes(...chunks) {
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) { result.set(c, offset); offset += c.byteLength }
	return result;
}

async function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs) })
		]);
	} finally {
		clearTimeout(timer);
	}
}

function isIPv4(value) {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

async function resolveIPv4(hostname) {
	const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`, {
		headers: { 'Accept': 'application/dns-json' }
	});
	if (!response.ok) return null;
	const { Answer = [] } = await response.json();
	return Answer.find(item => item.type === 1 && isIPv4(item.data))?.data || null;
}

//////////////////////////////////////////////////sstpConnect (改编自 cmliu/edgetunnel, GPL-2.0)///////////////////////////////////////////////
const SSTP_TCP_MSS = 1400;
const SSTP_EMPTY_BYTES = new Uint8Array(0);

function readSstpUint16(bytes, offset = 0) {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

function readSstpUint32(bytes, offset = 0) {
	return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function randomSstpUint16() {
	return readSstpUint16(crypto.getRandomValues(new Uint8Array(2)));
}

function internetChecksum(bytes, offset, length) {
	let sum = 0;
	for (let index = offset; index < offset + length - 1; index += 2) sum += readSstpUint16(bytes, index);
	if (length & 1) sum += bytes[offset + length - 1] << 8;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (~sum) & 0xffff;
}

async function sstpConnect(proxy, targetHost, targetPort) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	let bufferedBytes = SSTP_EMPTY_BYTES, pppIdentifier = 1, socket = null, reader = null, writer = null;
	let closedSettled = false, resolveClosed, rejectClosed;
	const closed = new Promise((resolve, reject) => {
		resolveClosed = resolve;
		rejectClosed = reject;
	});
	closed.catch(() => { });
	const settleClosed = (settle, value) => {
		if (closedSettled) return;
		closedSettled = true;
		settle(value);
	};
	const close = () => {
		try { reader?.cancel?.().catch?.(() => { }) } catch (e) { }
		try { reader?.releaseLock?.() } catch (e) { }
		try { writer?.close?.().catch?.(() => { }) } catch (e) { }
		try { writer?.releaseLock?.() } catch (e) { }
		try { socket?.close?.() } catch (e) { }
		settleClosed(resolveClosed);
	};

	const readSocketChunk = async () => {
		const { value, done } = await reader.read();
		if (done || !value) throw new Error('SSTP socket closed');
		return toBytes(value);
	};
	const readBytes = async length => {
		while (bufferedBytes.byteLength < length) {
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? concatBytes(bufferedBytes, chunk) : chunk;
		}
		const result = bufferedBytes.subarray(0, length);
		bufferedBytes = bufferedBytes.subarray(length);
		return result;
	};
	const readHttpLine = async () => {
		for (; ;) {
			const lineEnd = bufferedBytes.indexOf(10);
			if (lineEnd >= 0) {
				const line = textDecoder.decode(bufferedBytes.subarray(0, lineEnd));
				bufferedBytes = bufferedBytes.subarray(lineEnd + 1);
				return line.replace(/\r$/, '');
			}
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? concatBytes(bufferedBytes, chunk) : chunk;
		}
	};
	const readPacket = async (timeoutMs = CONNECT_TIMEOUT_MS) => {
		const header = await withTimeout(readBytes(4), timeoutMs, 'SSTP read timeout');
		const length = readSstpUint16(header, 2) & 0x0fff;
		if (length < 4) throw new Error('Invalid SSTP packet length');
		return {
			isControl: (header[1] & 1) !== 0,
			body: length > 4 ? await withTimeout(readBytes(length - 4), timeoutMs, 'SSTP packet body read timeout') : SSTP_EMPTY_BYTES
		};
	};
	const buildSstpDataPacket = pppFrame => {
		const packetLength = 6 + pppFrame.byteLength;
		const packet = new Uint8Array(packetLength);
		packet.set([0x10, 0x00, ((packetLength >> 8) & 0x0f) | 0x80, packetLength & 0xff, 0xff, 0x03]);
		packet.set(pppFrame, 6);
		return packet;
	};
	const buildPppConfigurePacket = (protocol, code, id, options = []) => {
		const optionsLength = options.reduce((size, option) => size + 2 + option.data.byteLength, 0);
		const frame = new Uint8Array(6 + optionsLength);
		const view = new DataView(frame.buffer);
		view.setUint16(0, protocol);
		frame[2] = code;
		frame[3] = id;
		view.setUint16(4, 4 + optionsLength);
		options.reduce((offset, option) => {
			frame[offset] = option.type;
			frame[offset + 1] = 2 + option.data.byteLength;
			frame.set(option.data, offset + 2);
			return offset + 2 + option.data.byteLength;
		}, 6);
		return frame;
	};
	const parsePPPFrame = data => {
		const offset = data.byteLength >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
		if (data.byteLength - offset < 4) return null;
		const protocol = readSstpUint16(data, offset);
		if (protocol === 0x0021) return { protocol, ipPacket: data.subarray(offset + 2) };
		if (data.byteLength - offset < 6) return null;
		return { protocol, code: data[offset + 2], id: data[offset + 3], payload: data.subarray(offset + 6), rawPacket: data.subarray(offset) };
	};
	const parsePppOptions = data => {
		const options = [];
		for (let offset = 0; offset + 2 <= data.byteLength;) {
			const type = data[offset];
			const length = data[offset + 1];
			if (length < 2 || offset + length > data.byteLength) break;
			options.push({ type, data: data.subarray(offset + 2, offset + length) });
			offset += length;
		}
		return options;
	};

	try {
		const serverHost = proxy.hostname;
		const serverPort = proxy.port;
		socket = connect({ hostname: serverHost, port: serverPort }, { secureTransport: 'on', allowHalfOpen: false });
		await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, 'SSTP server connection timed out');
		reader = socket.readable.getReader();
		writer = socket.writable.getWriter();

		const httpRequest = textEncoder.encode(
			`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n`
			+ `Host: ${Number(serverPort) === 443 ? serverHost : `${serverHost}:${serverPort}`}\r\n`
			+ 'Content-Length: 18446744073709551615\r\n'
			+ `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`
		);
		const encapsulatedProtocol = new Uint8Array(2);
		new DataView(encapsulatedProtocol.buffer).setUint16(0, 1);
		const maximumReceiveUnit = new Uint8Array(2);
		new DataView(maximumReceiveUnit.buffer).setUint16(0, 1500);
		const sstpConnectRequest = new Uint8Array(12 + encapsulatedProtocol.byteLength);
		const sstpConnectView = new DataView(sstpConnectRequest.buffer);
		sstpConnectRequest[0] = 0x10;
		sstpConnectRequest[1] = 0x01;
		sstpConnectView.setUint16(2, sstpConnectRequest.byteLength | 0x8000);
		sstpConnectView.setUint16(4, 0x0001);
		sstpConnectView.setUint16(6, 1);
		sstpConnectRequest[9] = 1;
		sstpConnectView.setUint16(10, 4 + encapsulatedProtocol.byteLength);
		sstpConnectRequest.set(encapsulatedProtocol, 12);

		await withTimeout(writer.write(concatBytes(
			httpRequest,
			sstpConnectRequest,
			buildSstpDataPacket(buildPppConfigurePacket(0xc021, 1, pppIdentifier++, [
				{ type: 1, data: maximumReceiveUnit }
			]))
		)), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake request timed out');

		const statusLine = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake timed out');
		for (; ;) {
			const line = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP header read timed out');
			if (line === '') break;
		}
		if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine)) throw new Error(`SSTP HTTP handshake failed: ${statusLine || 'invalid status'}`);

		let localLcpAcked = false, peerLcpAcked = false, papRequired = false, papSent = false, papDone = false, ipcpStarted = false, ipcpFinished = false, sourceIp = null;
		const sendPapIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
			if (proxy.username === null || proxy.password === null) throw new Error('SSTP server requires PAP authentication');
			const username = textEncoder.encode(proxy.username);
			const password = textEncoder.encode(proxy.password);
			if (username.byteLength > 255 || password.byteLength > 255) throw new Error('SSTP username/password is too long');
			const papLength = 6 + username.byteLength + password.byteLength;
			const frame = new Uint8Array(2 + papLength);
			const view = new DataView(frame.buffer);
			view.setUint16(0, 0xc023);
			frame[2] = 1;
			frame[3] = pppIdentifier++;
			view.setUint16(4, papLength);
			frame[6] = username.byteLength;
			frame.set(username, 7);
			frame[7 + username.byteLength] = password.byteLength;
			frame.set(password, 8 + username.byteLength);
			await withTimeout(writer.write(buildSstpDataPacket(frame)), CONNECT_TIMEOUT_MS, 'SSTP PAP authentication request timed out');
			papSent = true;
		};
		const startIpcpIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
			await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
				{ type: 3, data: new Uint8Array(4) }
			]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP request timed out');
			ipcpStarted = true;
		};

		for (let round = 0; round < 50 && !ipcpFinished; round++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp) continue;

			if (ppp.protocol === 0xc021) {
				if (ppp.code === 1) {
					const authOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (authOption?.data?.byteLength >= 2) {
						const authProtocol = readSstpUint16(authOption.data);
						if (authProtocol !== 0xc023) throw new Error(`SSTP unsupported PPP authentication protocol: 0x${authProtocol.toString(16)}`);
						papRequired = true;
					}
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP LCP Configure-Ack timed out');
					peerLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				} else if (ppp.code === 2) {
					localLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				}
				continue;
			}

			if (ppp.protocol === 0xc023) {
				if (ppp.code === 2) {
					papDone = true;
					await startIpcpIfReady();
				} else if (ppp.code === 3) throw new Error('SSTP PAP authentication failed');
				continue;
			}

			if (ppp.protocol === 0x8021) {
				if (ppp.code === 1) {
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP IPCP Configure-Ack timed out');
					await startIpcpIfReady();
				} else if (ppp.code === 3) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) {
						sourceIp = [...addressOption.data].join('.');
						await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
							{ type: 3, data: addressOption.data }
						]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP address request timed out');
						ipcpStarted = true;
					}
				} else if (ppp.code === 2) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) sourceIp = [...addressOption.data].join('.');
					ipcpFinished = true;
				}
			}
		}
		if (!sourceIp) throw new Error('SSTP did not assign an IPv4 address');

		const targetIp = isIPv4(targetHost) ? targetHost : await resolveIPv4(targetHost);
		if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for SSTP`);

		const sourcePort = 10000 + (randomSstpUint16() % 50000);
		const sourceAddress = new Uint8Array(String(sourceIp).split('.').map(Number));
		const destinationAddress = new Uint8Array(String(targetIp).split('.').map(Number));
		let sequenceNumber = readSstpUint32(crypto.getRandomValues(new Uint8Array(4)));
		let acknowledgementNumber = 0;
		const ipHeaderTemplate = new Uint8Array(20);
		ipHeaderTemplate.set([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6]);
		ipHeaderTemplate.set(sourceAddress, 12);
		ipHeaderTemplate.set(destinationAddress, 16);
		const tcpPseudoHeader = new Uint8Array(1432);
		tcpPseudoHeader.set(sourceAddress);
		tcpPseudoHeader.set(destinationAddress, 4);
		tcpPseudoHeader[9] = 6;
		const buildTcpFrame = (flags, payload = SSTP_EMPTY_BYTES) => {
			const bytes = toBytes(payload);
			const payloadLength = bytes.byteLength;
			const tcpLength = 20 + payloadLength;
			const ipLength = 20 + tcpLength;
			const sstpLength = 8 + ipLength;
			const frame = new Uint8Array(sstpLength);
			const view = new DataView(frame.buffer);
			frame.set([0x10, 0x00, ((sstpLength >> 8) & 0x0f) | 0x80, sstpLength & 0xff, 0xff, 0x03, 0x00, 0x21]);
			frame.set(ipHeaderTemplate, 8);
			view.setUint16(10, ipLength);
			view.setUint16(12, randomSstpUint16());
			view.setUint16(18, internetChecksum(frame, 8, 20));
			view.setUint16(28, sourcePort);
			view.setUint16(30, targetPort);
			view.setUint32(32, sequenceNumber);
			view.setUint32(36, acknowledgementNumber);
			frame[40] = 0x50;
			frame[41] = flags;
			view.setUint16(42, 65535);
			if (payloadLength) frame.set(bytes, 48);
			tcpPseudoHeader[10] = tcpLength >> 8;
			tcpPseudoHeader[11] = tcpLength & 0xff;
			tcpPseudoHeader.set(frame.subarray(28, 28 + tcpLength), 12);
			view.setUint16(44, internetChecksum(tcpPseudoHeader, 0, 12 + tcpLength));
			return frame;
		};
		const matchIncomingIpPacket = ipPacket => {
			if (ipPacket.byteLength < 40 || ipPacket[9] !== 6) return null;
			const ipHeaderLength = (ipPacket[0] & 0x0f) * 4;
			if (ipPacket.byteLength < ipHeaderLength + 20) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength) !== targetPort) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength + 2) !== sourcePort) return null;
			return {
				flags: ipPacket[ipHeaderLength + 13],
				sequence: readSstpUint32(ipPacket, ipHeaderLength + 4),
				payloadOffset: ipHeaderLength + ((ipPacket[ipHeaderLength + 12] >> 4) & 0x0f) * 4
			};
		};

		await withTimeout(writer.write(buildTcpFrame(0x02)), CONNECT_TIMEOUT_MS, 'SSTP TCP SYN write timed out');
		sequenceNumber = (sequenceNumber + 1) >>> 0;
		let tcpReady = false;
		for (let attempt = 0; attempt < 30; attempt++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp || ppp.protocol !== 0x0021) continue;
			const tcp = matchIncomingIpPacket(ppp.ipPacket);
			if (!tcp || (tcp.flags & 0x12) !== 0x12) continue;
			acknowledgementNumber = (tcp.sequence + 1) >>> 0;
			await withTimeout(writer.write(buildTcpFrame(0x10)), CONNECT_TIMEOUT_MS, 'SSTP TCP ACK write timed out');
			tcpReady = true;
			break;
		}
		if (!tcpReady) throw new Error('TCP handshake through SSTP timed out');

		let streamController = null;
		const readable = new ReadableStream({
			start(controller) {
				streamController = controller;
			},
			cancel() {
				close();
			}
		});

		(async () => {
			try {
				let pendingChunks = [], pendingLength = 0;
				const flush = () => {
					if (!pendingLength) return;
					streamController.enqueue(pendingChunks.length === 1 ? pendingChunks[0] : concatBytes(...pendingChunks));
					pendingChunks = [];
					pendingLength = 0;
					writer.write(buildTcpFrame(0x10)).catch(() => { });
				};

				for (; ;) {
					const packet = await readPacket(60000);
					if (packet.isControl) continue;
					const ppp = parsePPPFrame(packet.body);
					if (!ppp || ppp.protocol !== 0x0021) continue;
					const incoming = matchIncomingIpPacket(ppp.ipPacket);
					if (!incoming) continue;

					if (incoming.payloadOffset < ppp.ipPacket.byteLength) {
						const payload = ppp.ipPacket.subarray(incoming.payloadOffset);
						if (payload.byteLength) {
							acknowledgementNumber = (incoming.sequence + payload.byteLength) >>> 0;
							pendingChunks.push(new Uint8Array(payload));
							pendingLength += payload.byteLength;
						}
					}

					if (incoming.flags & 0x01) {
						flush();
						acknowledgementNumber = (acknowledgementNumber + 1) >>> 0;
						writer.write(buildTcpFrame(0x11)).catch(() => { });
						try { streamController.close() } catch (e) { }
						close();
						return;
					}

					if (bufferedBytes.byteLength < 4 || pendingLength >= 32768) flush();
				}
			} catch (error) {
				try { streamController.error(error) } catch (e) { }
				settleClosed(rejectClosed, error);
				try { socket?.close?.() } catch (e) { }
			}
		})();

		const writable = new WritableStream({
			async write(chunk) {
				const bytes = toBytes(chunk);
				if (!bytes.byteLength) return;
				if (bytes.byteLength <= SSTP_TCP_MSS) {
					await writer.write(buildTcpFrame(0x18, bytes));
					sequenceNumber = (sequenceNumber + bytes.byteLength) >>> 0;
					return;
				}
				const frames = [];
				for (let offset = 0; offset < bytes.byteLength; offset += SSTP_TCP_MSS) {
					const segment = bytes.subarray(offset, Math.min(offset + SSTP_TCP_MSS, bytes.byteLength));
					frames.push(buildTcpFrame(0x18, segment));
					sequenceNumber = (sequenceNumber + segment.byteLength) >>> 0;
				}
				await writer.write(concatBytes(...frames));
			},
			close() {
				return writer.write(buildTcpFrame(0x11)).catch(() => { });
			},
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});

		return { readable, writable, closed, close };
	} catch (error) {
		close();
		throw error;
	}
}
