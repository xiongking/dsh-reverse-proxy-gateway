/**
 * 裸 socket 的 HTTP 客户端。
 *
 * 用 fetch 测不了两件事：压缩体原样透传，以及 WebSocket 握手。
 * 前者是因为 undici 会自动解压，后者是因为 fetch 根本不发 Upgrade。
 */
import { connect } from 'node:net';

/**
 * 发一个原始请求，读到连接关闭为止。
 * @returns {Promise<{statusLine: string, headers: Record<string,string>, body: Buffer}>}
 */
export function rawRequest({ port, path = '/', method = 'GET', headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const socket = connect(port, '127.0.0.1');
    const chunks = [];
    socket.on('error', reject);
    socket.on('connect', () => {
      const lines = [`${method} ${path} HTTP/1.1`, `Host: 127.0.0.1:${port}`];
      for (const [key, value] of Object.entries(headers)) lines.push(`${key}: ${value}`);
      if (body !== null) lines.push(`Content-Length: ${Buffer.byteLength(body)}`);
      lines.push('Connection: close', '', '');
      socket.write(lines.join('\r\n'));
      if (body !== null) socket.write(body);
    });
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('end', () => {
      const raw = Buffer.concat(chunks);
      const split = raw.indexOf('\r\n\r\n');
      const head = raw.slice(0, split === -1 ? raw.length : split).toString('latin1');
      const [statusLine, ...rest] = head.split('\r\n');
      const parsed = {};
      for (const line of rest) {
        const colon = line.indexOf(':');
        if (colon > 0) parsed[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
      }
      resolve({ statusLine, headers: parsed, body: split === -1 ? Buffer.alloc(0) : raw.slice(split + 4) });
    });
  });
}

/**
 * 发一个 WebSocket 握手，只取响应首行就断开。
 * @returns {Promise<{statusLine: string, headers: Record<string,string>}>}
 */
export function rawUpgrade({ port, path = '/', headers = {} }) {
  return new Promise((resolve, reject) => {
    const socket = connect(port, '127.0.0.1');
    let buffer = '';
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };
    socket.on('error', (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
    socket.on('close', () => {
      if (!settled) finish({ statusLine: '', headers: {} });
    });
    socket.setTimeout(4000, () => finish({ statusLine: '', headers: {} }));
    socket.on('connect', () => {
      const lines = [
        `GET ${path} HTTP/1.1`,
        `Host: 127.0.0.1:${port}`,
        'Upgrade: websocket',
        'Connection: Upgrade',
        'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
        'Sec-WebSocket-Version: 13',
      ];
      for (const [key, value] of Object.entries(headers)) lines.push(`${key}: ${value}`);
      lines.push('', '');
      socket.write(lines.join('\r\n'));
    });
    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1');
      const split = buffer.indexOf('\r\n\r\n');
      if (split === -1) return;
      const [statusLine, ...rest] = buffer.slice(0, split).split('\r\n');
      const parsed = {};
      for (const line of rest) {
        const colon = line.indexOf(':');
        if (colon > 0) parsed[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
      }
      finish({ statusLine, headers: parsed });
    });
  });
}
