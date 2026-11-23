/**
 * WebSocket 升级链路的鉴权。
 *
 * 这一组是回归测试的护栏：曾经 forwardUpgrade 完全不做任何检查就直接转发，
 * 而且转发时还会注入一条合法的宿主会话 cookie —— 等于任何人连上端口就拿到宿主权限。
 */
import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { startGateway, basicAuth, REMOTE_HEADERS } from './helpers/gateway.mjs';
import { rawUpgrade } from './helpers/raw.mjs';
import { hasSessionCookie } from '../index.mjs';

const AUTH = basicAuth('tester', 'secret');
const GATEWAY_COOKIE = 'dsh_gw';
const MUX = '/api/remote.mux';

/** 从 set-cookie 里取出网关 cookie 的 `name=value`。 */
function pickGatewayCookie(res) {
  const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const line of raw) {
    const first = line.split(';')[0];
    if (first.startsWith(`${GATEWAY_COOKIE}=`)) return first;
  }
  return null;
}

/** 先走一次普通请求拿到登录 cookie。 */
async function login(gw) {
  const res = await fetch(`${gw.base}/`, { headers: { authorization: AUTH, ...REMOTE_HEADERS } });
  assert.equal(res.status, 200);
  const cookie = pickGatewayCookie(res);
  assert.ok(cookie !== null);
  return cookie;
}

describe('WebSocket 升级鉴权', () => {
  let gw;

  before(async () => {
    gw = await startGateway();
  });

  after(async () => {
    await gw.dispose();
  });

  beforeEach(() => {
    gw.host.requests.length = 0;
  });

  it('不带任何凭据时返回 401，且宿主收不到任何请求', async () => {
    const result = await rawUpgrade({ port: gw.port, path: MUX, headers: { ...REMOTE_HEADERS } });
    assert.match(result.statusLine, /^HTTP\/1\.1 401/);
    assert.equal(gw.host.requests.length, 0);
  });

  it('Basic 凭据正确时放行到宿主', async () => {
    const result = await rawUpgrade({ port: gw.port, path: MUX, headers: { authorization: AUTH, ...REMOTE_HEADERS } });
    assert.match(result.statusLine, /^HTTP\/1\.1 101/);
    assert.equal(gw.host.requests.length, 1);
    assert.equal(gw.host.requests[0].upgrade, true);
  });

  it('登录 cookie 也能放行，且宿主看到的是注入的宿主会话 cookie', async () => {
    const cookie = await login(gw);
    const result = await rawUpgrade({ port: gw.port, path: MUX, headers: { cookie, ...REMOTE_HEADERS } });
    assert.match(result.statusLine, /^HTTP\/1\.1 101/);
    const seen = gw.host.requests.filter((item) => item.upgrade === true).pop();
    assert.ok(seen !== undefined);
    // 用验签函数判断，比匹配 cookie 名字更实在：注入的必须是能验过的宿主会话。
    assert.equal(hasSessionCookie(String(seen.headers.cookie), gw.home.secret), true);
  });

  it('伪造的 cookie 不放行，宿主零请求', async () => {
    const result = await rawUpgrade({
      port: gw.port,
      path: MUX,
      headers: { cookie: `${GATEWAY_COOKIE}=9999999999999.forged`, ...REMOTE_HEADERS },
    });
    assert.match(result.statusLine, /^HTTP\/1\.1 401/);
    assert.equal(gw.host.requests.length, 0);
  });

  it('访问 token 也能完成握手', async () => {
    const token = 'k'.repeat(24);
    const scoped = await startGateway({ config: { password: '', accessToken: token } });
    try {
      const result = await rawUpgrade({
        port: scoped.port,
        path: `${MUX}?token=${token}`,
        headers: { ...REMOTE_HEADERS },
      });
      assert.match(result.statusLine, /^HTTP\/1\.1 101/);
    } finally {
      await scoped.dispose();
    }
  });

  it('跨站来源的握手被直接断开，宿主零请求', async () => {
    const cookie = await login(gw);
    const result = await rawUpgrade({
      port: gw.port,
      path: MUX,
      headers: { cookie, origin: 'https://evil.example', ...REMOTE_HEADERS },
    });
    assert.equal(result.statusLine, '');
    // login() 本身会访问一次宿主页面，只数升级请求。
    assert.equal(gw.host.requests.filter((item) => item.upgrade === true).length, 0);
  });

  it('连错密码会被限速，之后正确的密码也先吃 429', async () => {
    const scoped = await startGateway({ config: { password: 'right-password' } });
    try {
      for (let index = 0; index < 5; index += 1) {
        const bad = await rawUpgrade({
          port: scoped.port,
          path: MUX,
          headers: { authorization: basicAuth('tester', `wrong-${index}`), ...REMOTE_HEADERS },
        });
        assert.match(bad.statusLine, /^HTTP\/1\.1 401/);
      }
      const blocked = await rawUpgrade({
        port: scoped.port,
        path: MUX,
        headers: { authorization: basicAuth('tester', 'right-password'), ...REMOTE_HEADERS },
      });
      assert.match(blocked.statusLine, /^HTTP\/1\.1 429/);
      assert.ok(Number(blocked.headers['retry-after']) > 0);
      assert.equal(scoped.host.requests.length, 0);
    } finally {
      await scoped.dispose();
    }
  });

  it('握手成功后失败计数被清零，不会带着旧账继续走', async () => {
    const scoped = await startGateway({ config: { password: 'right-password' } });
    try {
      // 先输错 3 次（阈值是 5），再用正确凭据完成一次握手。
      for (let index = 0; index < 3; index += 1) {
        await rawUpgrade({
          port: scoped.port,
          path: MUX,
          headers: { authorization: basicAuth('tester', `wrong-${index}`), ...REMOTE_HEADERS },
        });
      }
      const ok = await rawUpgrade({
        port: scoped.port,
        path: MUX,
        headers: { authorization: basicAuth('tester', 'right-password'), ...REMOTE_HEADERS },
      });
      assert.match(ok.statusLine, /^HTTP\/1\.1 101/);

      // 计数已清零，所以还能再错 4 次才锁；若没清零，第 2 次就该锁了。
      for (let index = 0; index < 4; index += 1) {
        const bad = await rawUpgrade({
          port: scoped.port,
          path: MUX,
          headers: { authorization: basicAuth('tester', `again-${index}`), ...REMOTE_HEADERS },
        });
        assert.match(bad.statusLine, /^HTTP\/1\.1 401/);
      }
    } finally {
      await scoped.dispose();
    }
  });
});
