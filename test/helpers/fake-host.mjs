/**
 * 假宿主 HTTP 服务 —— 站在 DSH webServer 的位置，接收网关转发过来的请求。
 *
 * 每个请求都被记录下来（头、方法、路径、body），响应可由测试逐个设定，
 * 用来断言网关有没有改写 Host、注入 cookie、删除 authorization。
 */
import { createServer } from 'node:http';
import { gzipSync, brotliCompressSync, deflateSync } from 'node:zlib';

/**
 * @param {object} [options]
 * @param {number} [options.status] 默认响应状态码
 * @param {string} [options.body] 默认响应体
 * @param {object} [options.headers] 默认响应头
 * @param {string} [options.encoding] 响应压缩方式：identity / gzip / deflate / br
 */
export async function makeFakeHost(options = {}) {
  const requests = [];
  let respond = null;

  const defaultRespond = (req) => {
    const body = options.body === undefined ? '<html><body>host page</body></html>' : options.body;
    const headers = { 'content-type': 'text/html; charset=utf-8', ...(options.headers || {}) };
    const encoding = options.encoding || 'identity';
    let payload = Buffer.from(body, 'utf8');
    if (encoding === 'gzip') {
      payload = gzipSync(payload);
      headers['content-encoding'] = 'gzip';
    } else if (encoding === 'deflate') {
      payload = deflateSync(payload);
      headers['content-encoding'] = 'deflate';
    } else if (encoding === 'br') {
      payload = brotliCompressSync(payload);
      headers['content-encoding'] = 'br';
    }
    headers['content-length'] = String(payload.length);
    return { status: options.status === undefined ? 200 : options.status, headers, payload };
  };

  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      requests.push({
        method: req.method,
        url: req.url,
        headers: { ...req.headers },
        body: Buffer.concat(chunks),
      });
    });

    // 真实 DSH 宿主会把注册过的 exact 路由派发给插件自己的处理器，
    // 而且是把请求流原样交出去。假宿主也必须这样：一旦先读完整个请求体再派发，
    // 插件侧的 readJsonBody 就再也等不到 end，POST 会永远挂住。
    const pathname = String(req.url || '/').split('?')[0];
    const registered = options.routeTable === undefined ? undefined : options.routeTable.get(pathname);
    if (registered !== undefined) {
      try {
        registered(req, res);
      } catch (error) {
        res.writeHead(500, { 'content-type': 'text/plain' });
        res.end(String(error));
      }
      return;
    }

    req.on('end', () => {
      const record = requests[requests.length - 1];
      let result;
      try {
        result = (respond || defaultRespond)(req, record);
      } catch (error) {
        result = { status: 500, headers: { 'content-type': 'text/plain' }, payload: Buffer.from(String(error)) };
      }
      res.writeHead(result.status, result.headers || {});
      if (req.method === 'HEAD' || result.status === 204 || result.status === 304) res.end();
      else res.end(result.payload);
    });
  });

  // 网关的 WebSocket 转发走的是裸 socket，宿主这边也得能接住 upgrade，
  // 否则 Node 的 http server 会因为没人监听而直接掐掉连接。
  const upgraded = new Set();
  server.on('upgrade', (req, socket) => {
    requests.push({ method: req.method, url: req.url, headers: { ...req.headers }, body: Buffer.alloc(0), upgrade: true });
    upgraded.add(socket);
    socket.on('close', () => upgraded.delete(socket));
    socket.on('error', () => {});
    if (options.upgrade === false) {
      socket.destroy();
      return;
    }
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  return {
    port,
    requests,
    /** 替换响应逻辑：(req, record) => { status, headers, payload } */
    setRespond(fn) {
      respond = fn;
    },
    /** 每个请求的最新一条记录 */
    last() {
      return requests[requests.length - 1];
    },
    async close() {
      // 升级过的连接不受 server.close() 管理，必须先掐掉，否则 close 永远等不到回调。
      for (const socket of upgraded) socket.destroy();
      upgraded.clear();
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
