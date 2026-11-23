/**
 * 「退出所有登录」的集成测试。
 *
 * 这条路由的价值全在副作用上：轮换世代之后，此前签发的所有 cookie 必须立刻失效，
 * 而凭据本身不变。测不到这一点，按钮就只是个装饰。
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync } from 'node:fs';

import { startGateway, basicAuth, REMOTE_HEADERS } from './helpers/gateway.mjs';
import { rawRequest } from './helpers/raw.mjs';

const AUTH = basicAuth('tester', 'secret');
const GATEWAY_COOKIE = 'dsh_gw';
const LOGOUT_ALL = '/coopanion/reverse-proxy-gateway/logout-all';

/** 从 set-cookie 里取出网关 cookie 的 `name=value`。 */
function pickGatewayCookie(res) {
  const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const line of raw) {
    const first = line.split(';')[0];
    if (first.startsWith(`${GATEWAY_COOKIE}=`)) return first;
  }
  return null;
}

/** 走一次 Basic 登录，拿到网关 cookie。 */
async function login(gw) {
  const res = await fetch(`${gw.base}/`, { headers: { authorization: AUTH, ...REMOTE_HEADERS } });
  assert.equal(res.status, 200);
  const cookie = pickGatewayCookie(res);
  assert.ok(cookie !== null);
  return cookie;
}

/** 用已有 cookie 访问，返回状态码。 */
async function probe(gw, cookie) {
  const res = await fetch(`${gw.base}/`, { headers: { cookie, ...REMOTE_HEADERS } });
  return res.status;
}

describe('退出所有登录', () => {
  it('轮换后旧 cookie 立刻失效，重新登录可拿到新 cookie', async () => {
    const gw = await startGateway();
    try {
      const before = await login(gw);
      assert.equal(await probe(gw, before), 200);

      const res = await fetch(`${gw.base}${LOGOUT_ALL}`, {
        method: 'POST',
        headers: { authorization: AUTH, 'content-type': 'application/json', ...REMOTE_HEADERS },
        body: '{}',
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.ok, true);
      assert.equal(typeof body.rotatedAt, 'string');

      // 同一个 cookie 再访问必须被拒。
      assert.equal(await probe(gw, before), 401);

      // 凭据没变，重新登录应当照常成功且拿到不同的 cookie。
      const after = await login(gw);
      assert.notEqual(after, before);
      assert.equal(await probe(gw, after), 200);
    } finally {
      await gw.dispose();
    }
  });

  it('响应里清掉浏览器上的网关 cookie', async () => {
    const gw = await startGateway();
    try {
      const res = await fetch(`${gw.base}${LOGOUT_ALL}`, {
        method: 'POST',
        headers: { authorization: AUTH, 'content-type': 'application/json', ...REMOTE_HEADERS },
        body: '{}',
      });
      const lines = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
      const cleared = lines.find((line) => line.startsWith(`${GATEWAY_COOKIE}=`));
      assert.ok(cleared !== undefined);
      assert.match(cleared, /Max-Age=0/i);
    } finally {
      await gw.dispose();
    }
  });

  it('非 POST 返回 405', async () => {
    const gw = await startGateway();
    try {
      for (const method of ['GET', 'PUT', 'DELETE']) {
        const res = await fetch(`${gw.base}${LOGOUT_ALL}`, { method, headers: { authorization: AUTH, ...REMOTE_HEADERS } });
        assert.equal(res.status, 405, `${method} 应当被拒`);
      }
    } finally {
      await gw.dispose();
    }
  });

  it('跨站来源返回 403，且不轮换世代', async () => {
    const gw = await startGateway();
    try {
      const cookie = await login(gw);
      // fetch 会丢掉 Origin 这类受限头，所以这里用裸 socket 写。
      const raw = await rawRequest({
        port: gw.port,
        path: LOGOUT_ALL,
        method: 'POST',
        headers: {
          authorization: AUTH,
          origin: 'https://evil.example',
          ...REMOTE_HEADERS,
        },
      });
      assert.match(raw.statusLine, /^HTTP\/1\.1 403/);
      // 没轮换，所以原 cookie 依然有效。
      assert.equal(await probe(gw, cookie), 200);
    } finally {
      await gw.dispose();
    }
  });

  it('只凭网关 cookie 也能调用（远程用户点按钮走的就是这条路）', async () => {
    const gw = await startGateway();
    try {
      const cookie = await login(gw);
      // 远程浏览器手里只有网关 cookie：没有 Basic 头，也没有宿主会话 cookie。
      const res = await fetch(`${gw.base}${LOGOUT_ALL}`, {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json', ...REMOTE_HEADERS },
        body: '{}',
      });
      assert.equal(res.status, 200, '经网关登录的用户应当能吊销自己的会话');
      const data = await res.json();
      assert.equal(data.ok, true);
      // 轮换后同一个 cookie 立刻失效。
      assert.equal(await probe(gw, cookie), 401);
    } finally {
      await gw.dispose();
    }
  });

  it('没有凭据的请求不能调用', async () => {
    const gw = await startGateway();
    try {
      const res = await fetch(`${gw.base}${LOGOUT_ALL}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...REMOTE_HEADERS },
        body: '{}',
      });
      assert.equal(res.status, 401);
    } finally {
      await gw.dispose();
    }
  });

  it('世代写不进去时，登录状态必须原样保留', async () => {
    // 磁盘满、~/.dsh 只读都会走到这里。曾经的实现是先改内存世代再写盘，
    // 于是接口回「失败」而所有设备其实已经被踢，重启后又从文件读回旧值
    // 把刚踢掉的设备恢复回来。判定标准：失败就意味着什么都没发生。
    const gw = await startGateway();
    const originalMode = 0o700;
    try {
      const cookie = await login(gw);
      chmodSync(gw.home.home, 0o500);
      const res = await fetch(`${gw.base}${LOGOUT_ALL}`, {
        method: 'POST',
        headers: { authorization: AUTH, 'content-type': 'application/json', ...REMOTE_HEADERS },
        body: '{}',
      });
      assert.equal(res.status, 500);
      const data = await res.json();
      assert.equal(data.error, 'persist-failed');
      assert.equal(await probe(gw, cookie), 200, '写入失败时不应吊销任何会话');
    } finally {
      chmodSync(gw.home.home, originalMode);
      await gw.dispose();
    }
  });
});
