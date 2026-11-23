/**
 * 状态接口 `/coopanion/reverse-proxy-gateway/state`。
 *
 * 这条路由曾经在重构里漏改一处，直接让宿主进程崩掉（`authenticate is not defined`）。
 * 它同时暴露端口与免密链接，所以既要能认证、也不能成为绕过限速的试探口。
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { startGateway, basicAuth, REMOTE_HEADERS } from './helpers/gateway.mjs';

const AUTH = basicAuth('tester', 'secret');
const STATE = '/coopanion/reverse-proxy-gateway/state';
const GATEWAY_COOKIE = 'dsh_gw';

function pickGatewayCookie(res) {
  const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const line of raw) {
    const first = line.split(';')[0];
    if (first.startsWith(`${GATEWAY_COOKIE}=`)) return first;
  }
  return null;
}

describe('状态接口', () => {
  it('未认证返回 401 而不是崩掉进程', async () => {
    const gw = await startGateway();
    try {
      const res = await fetch(`${gw.base}${STATE}`, { headers: { ...REMOTE_HEADERS } });
      assert.equal(res.status, 401);
      assert.match(String(res.headers.get('www-authenticate')), /^Basic realm="DSH"/);
    } finally {
      await gw.dispose();
    }
  });

  it('Basic 认证后返回完整状态', async () => {
    const gw = await startGateway({ config: { publicUrl: 'https://gw.example' } });
    try {
      const res = await fetch(`${gw.base}${STATE}`, { headers: { authorization: AUTH, ...REMOTE_HEADERS } });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.ok, true);
      assert.equal(body.enabled, true);
      assert.equal(body.listening, true);
      assert.equal(typeof body.port, 'number');
      assert.equal(body.publicUrl, 'https://gw.example');
      assert.equal(body.username, 'tester');
      assert.equal(body.basicAuth, true);
      assert.equal(body.tokenLogin, false);
    } finally {
      await gw.dispose();
    }
  });

  it('网关 cookie 也能读状态', async () => {
    const gw = await startGateway();
    try {
      const login = await fetch(`${gw.base}/`, { headers: { authorization: AUTH, ...REMOTE_HEADERS } });
      const cookie = pickGatewayCookie(login);
      assert.ok(cookie !== null);
      const res = await fetch(`${gw.base}${STATE}`, { headers: { cookie, ...REMOTE_HEADERS } });
      assert.equal(res.status, 200);
      assert.equal((await res.json()).ok, true);
    } finally {
      await gw.dispose();
    }
  });

  it('配了访问 token 时状态里给出免密链接，且不泄露密码', async () => {
    const token = 'z'.repeat(24);
    const gw = await startGateway({ config: { accessToken: token, publicUrl: 'https://gw.example' } });
    try {
      const res = await fetch(`${gw.base}${STATE}`, { headers: { authorization: AUTH, ...REMOTE_HEADERS } });
      const body = await res.json();
      assert.equal(body.tokenLogin, true);
      assert.equal(body.loginUrl, `https://gw.example/?token=${token}`);
      assert.equal(JSON.stringify(body).includes('secret'), false);
    } finally {
      await gw.dispose();
    }
  });

  it('输错密码会累计到限速，锁定后连状态接口也回 429', async () => {
    const gw = await startGateway({ config: { password: 'right-password' } });
    try {
      for (let index = 0; index < 5; index += 1) {
        await fetch(`${gw.base}${STATE}`, {
          headers: { authorization: basicAuth('tester', `wrong-${index}`), ...REMOTE_HEADERS },
        });
      }
      const res = await fetch(`${gw.base}${STATE}`, {
        headers: { authorization: basicAuth('tester', 'right-password'), ...REMOTE_HEADERS },
      });
      assert.equal(res.status, 429);
    } finally {
      await gw.dispose();
    }
  });
});

describe('loginUrl 与多入口', () => {
  it('配置多个 publicUrl 时登录链接取第一个，不是拼接整串', async () => {
    const gw = await startGateway({
      overrides: {
        username: 'tester',
        password: 'secret',
        accessToken: 'token-abcdefghijklmnop',
        publicUrl: 'https://gw.example,https://backup.example',
      },
    });
    try {
      const res = await fetch(`${gw.base}${STATE}`, {
        headers: { authorization: basicAuth('tester', 'secret') },
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.loginUrl, 'https://gw.example/?token=token-abcdefghijklmnop');
    } finally {
      await gw.dispose();
    }
  });
});

describe('密钥缺失时不能把宿主带崩', () => {
  it('凭证文件里没有 secret 时返回 500，而不是抛到事件循环外', async () => {
    const gw = await startGateway();
    try {
      // 模拟 DSH 还没写入密钥、或正在轮换凭据文件的瞬间。
      writeFileSync(join(gw.home.home, '.credentials.yaml'), 'client-connection:\n  browser-session:\n    version: 1\n');
      const res = await fetch(`${gw.base}${STATE}`);
      assert.equal(res.status, 500);
      const body = await res.json();
      assert.equal(body.error, 'no-session-secret');
      // 宿主还活着：再打一次普通页面，应当仍然给出 HTTP 响应（500 由 admit 兜底），
      // 而不是连接被重置、进程退出。
      const again = await fetch(`${gw.base}/`);
      assert.equal(again.status, 500);
    } finally {
      await gw.dispose();
    }
  });
});
