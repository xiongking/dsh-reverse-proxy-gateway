/**
 * 转发链路：认证、请求头改造、宿主 cookie 注入、错误处理。
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';

import { startGateway, basicAuth, REMOTE_HEADERS } from './helpers/gateway.mjs';
import { verifySessionCookieValue } from '../index.mjs';

const AUTH = basicAuth('tester', 'secret');
const GATEWAY_COOKIE = 'dsh_gw';

/** 从 set-cookie 里取出网关 cookie 的 `name=value` 片段。 */
function pickGatewayCookie(res) {
  const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  for (const line of raw) {
    const first = line.split(';')[0];
    if (first.startsWith(`${GATEWAY_COOKIE}=`)) return first;
  }
  return null;
}

describe('认证', () => {
  let gw;

  before(async () => {
    gw = await startGateway({ host: { body: 'host-ok', headers: { 'content-type': 'text/plain; charset=utf-8' } } });
  });

  after(async () => {
    await gw.dispose();
  });

  it('无凭据返回 401 并带 WWW-Authenticate', async () => {
    const res = await fetch(`${gw.base}/`, { headers: { ...REMOTE_HEADERS } });
    assert.equal(res.status, 401);
    assert.match(String(res.headers.get('www-authenticate')), /^Basic realm="DSH"/);
    assert.equal(await res.text(), '需要认证');
  });

  it('Basic 正确时放行并下发网关 cookie', async () => {
    const res = await fetch(`${gw.base}/`, { headers: { authorization: AUTH, ...REMOTE_HEADERS } });
    assert.equal(res.status, 200);
    assert.equal(await res.text(), 'host-ok');
    const cookie = pickGatewayCookie(res);
    assert.notEqual(cookie, null, '应下发 dsh_gw');
  });

  it('密码错误返回 401', async () => {
    const res = await fetch(`${gw.base}/`, {
      headers: { authorization: basicAuth('tester', 'wrong'), ...REMOTE_HEADERS },
    });
    assert.equal(res.status, 401);
  });

  it('用户名错误返回 401', async () => {
    const res = await fetch(`${gw.base}/`, {
      headers: { authorization: basicAuth('nobody', 'secret'), ...REMOTE_HEADERS },
    });
    assert.equal(res.status, 401);
  });

  it('已有有效网关 cookie 时无需再带 Basic', async () => {
    const first = await fetch(`${gw.base}/`, { headers: { authorization: AUTH, ...REMOTE_HEADERS } });
    const cookie = pickGatewayCookie(first);
    await first.text();

    const second = await fetch(`${gw.base}/`, { headers: { cookie, ...REMOTE_HEADERS } });
    assert.equal(second.status, 200);
    assert.equal(await second.text(), 'host-ok');
  });

  it('伪造的网关 cookie 不放行', async () => {
    const forged = `${GATEWAY_COOKIE}=${Date.now() + 86400000}.deadbeef`;
    const res = await fetch(`${gw.base}/`, { headers: { cookie: forged, ...REMOTE_HEADERS } });
    assert.equal(res.status, 401);
  });

  it('网关 cookie 的 SameSite 与 HttpOnly 属性齐全', async () => {
    const res = await fetch(`${gw.base}/`, { headers: { authorization: AUTH, ...REMOTE_HEADERS } });
    await res.text();
    const raw = (res.headers.getSetCookie ? res.headers.getSetCookie() : []).join(';');
    assert.match(raw, /HttpOnly/);
    assert.match(raw, /SameSite=Lax/);
    assert.match(raw, /Max-Age=\d+/);
  });

  it('未配置 password 时 Basic 一律不放行（只能走 token）', async () => {
    const noPass = await startGateway({ config: { password: '', accessToken: 'tok-only' } });
    try {
      const res = await fetch(`${noPass.base}/`, {
        headers: { authorization: basicAuth('tester', 'secret'), ...REMOTE_HEADERS },
      });
      assert.equal(res.status, 401);

      const viaToken = await fetch(`${noPass.base}/?token=tok-only`, {
        headers: { ...REMOTE_HEADERS },
        redirect: 'manual',
      });
      assert.equal(viaToken.status, 303);
    } finally {
      await noPass.dispose();
    }
  });
});

describe('固定 token 免密链接', () => {
  const TOKEN = 'tok-abcdef';

  it('token 正确时种 cookie 并 303 跳回根路径', async () => {
    const gw = await startGateway({ config: { accessToken: TOKEN } });
    try {
      const res = await fetch(`${gw.base}/?token=${TOKEN}`, { headers: { ...REMOTE_HEADERS }, redirect: 'manual' });
      assert.equal(res.status, 303);
      assert.equal(res.headers.get('location'), '/');
      assert.notEqual(pickGatewayCookie(res), null);
    } finally {
      await gw.dispose();
    }
  });

  it('token 错误时仍要求认证', async () => {
    const gw = await startGateway({ config: { accessToken: TOKEN } });
    try {
      const res = await fetch(`${gw.base}/?token=wrong`, { headers: { ...REMOTE_HEADERS }, redirect: 'manual' });
      assert.equal(res.status, 401);
    } finally {
      await gw.dispose();
    }
  });

  it('未配置 accessToken 时忽略 token 参数', async () => {
    const gw = await startGateway();
    try {
      const res = await fetch(`${gw.base}/?token=anything`, { headers: { ...REMOTE_HEADERS }, redirect: 'manual' });
      assert.equal(res.status, 401);
    } finally {
      await gw.dispose();
    }
  });
});

describe('请求头改造', () => {
  let gw;

  before(async () => {
    gw = await startGateway();
  });

  after(async () => {
    await gw.dispose();
  });

  it('Host 被改写为上游回环 authority', async () => {
    await fetch(`${gw.base}/some/path`, { headers: { authorization: AUTH, ...REMOTE_HEADERS } });
    assert.equal(gw.host.last().headers.host, `127.0.0.1:${gw.host.port}`);
  });

  it('转发时注入一条可验签的宿主会话 cookie', async () => {
    await fetch(`${gw.base}/`, { headers: { authorization: AUTH, ...REMOTE_HEADERS } });
    const cookie = gw.host.last().headers.cookie || '';
    const signed = cookie
      .split(';')
      .map((part) => part.trim())
      .filter((part) => part.startsWith('dsh-auth-'))
      .map((part) => part.slice(part.indexOf('=') + 1));
    assert.equal(signed.length, 1, '必须且只能有一条宿主会话 cookie');
    assert.equal(verifySessionCookieValue(signed[0], gw.home.secret), true);
  });

  it('浏览器自带的宿主会话 cookie 被丢弃，只留现签的那条', async () => {
    await fetch(`${gw.base}/`, {
      headers: {
        authorization: AUTH,
        cookie: 'dsh-auth-stale=v1.a.b; keepme=1; dsh_gw=whatever',
        ...REMOTE_HEADERS,
      },
    });
    const cookie = gw.host.last().headers.cookie || '';
    assert.equal(cookie.includes('dsh-auth-stale'), false);
    assert.equal(cookie.includes('keepme=1'), true, '无关 cookie 应保留');
    assert.equal(cookie.includes('dsh_gw='), false, '网关自己的 cookie 不该转发给宿主');
  });

  it('发往宿主的请求不带 Origin / Referer', async () => {
    await fetch(`${gw.base}/`, {
      headers: {
        authorization: AUTH,
        origin: 'https://dsh.example.com',
        referer: 'https://dsh.example.com/',
        ...REMOTE_HEADERS,
      },
    });
    const headers = gw.host.last().headers;
    assert.equal(headers.origin, undefined);
    assert.equal(headers.referer, undefined);
  });

  it('客户端自带的转发链头被丢掉，宿主不会被伪造来源误导', async () => {
    await fetch(`${gw.base}/`, {
      headers: {
        authorization: AUTH,
        'x-forwarded-for': '10.9.9.9',
        'x-real-ip': '10.9.9.9',
      },
    });
    const headers = gw.host.last().headers;
    assert.equal(headers['x-forwarded-for'], undefined);
    assert.equal(headers['x-real-ip'], undefined);
  });

  it('浏览器自己伪造的对端标记被丢弃后重新写入', async () => {
    await fetch(`${gw.base}/`, {
      headers: { authorization: AUTH, 'x-dsh-rpg-peer': 'local', ...REMOTE_HEADERS },
    });
    assert.equal(gw.host.last().headers['x-dsh-rpg-peer'], 'remote');
  });

  it('本机访问时不标记为 remote', async () => {
    await fetch(`${gw.base}/`, { headers: { authorization: AUTH } });
    assert.equal(gw.host.last().headers['x-dsh-rpg-peer'], undefined);
  });

  it('宿主下发的 set-cookie 被剔除（签给回环 authority，公网无用）', async () => {
    gw.host.setRespond(() => ({
      status: 200,
      headers: { 'content-type': 'text/plain', 'set-cookie': 'hostsession=abc; Path=/' },
      payload: Buffer.from('ok'),
    }));
    const res = await fetch(`${gw.base}/`, { headers: { authorization: AUTH } });
    await res.text();
    const cookies = (res.headers.getSetCookie ? res.headers.getSetCookie() : []).join(';');
    assert.equal(cookies.includes('hostsession'), false, '宿主的 set-cookie 不该透出去');
  });
});

describe('错误处理', () => {
  it('上游连不上时返回 502', async () => {
    const gw = await startGateway();
    await gw.host.close();
    try {
      const res = await fetch(`${gw.base}/`, { headers: { authorization: AUTH } });
      assert.equal(res.status, 502);
    } finally {
      await gw.dispose();
    }
  });

  it('上游返回 500 时状态码与正文原样透传', async () => {
    const gw = await startGateway();
    try {
      gw.host.setRespond(() => ({
        status: 500,
        headers: { 'content-type': 'text/plain' },
        payload: Buffer.from('boom'),
      }));
      const res = await fetch(`${gw.base}/`, { headers: { authorization: AUTH } });
      assert.equal(res.status, 500);
      assert.equal(await res.text(), 'boom');
    } finally {
      await gw.dispose();
    }
  });

  it('缺少宿主会话密钥时给出 500 与可读原因', async () => {
    const gw = await startGateway();
    try {
      // 删掉 credentials，让 cookieKey() 抛错
      const { writeFile } = await import('node:fs/promises');
      const { join } = await import('node:path');
      await writeFile(join(gw.home.home, '.credentials.yaml'), 'nothing here', 'utf8');
      const res = await fetch(`${gw.base}/`, { headers: { authorization: AUTH } });
      assert.equal(res.status, 500);
      assert.match(await res.text(), /会话密钥/);
    } finally {
      await gw.dispose();
    }
  });
});

describe('失败限速', () => {
  it('连续输错密码达到阈值后返回 429 并带 retry-after', async () => {
    const gw = await startGateway({ config: { password: 'right-password' } });
    try {
      // 阈值是 5 次：前 4 次回 401，第 5 次当场锁定并回 429。
      for (let index = 0; index < 4; index += 1) {
        const res = await fetch(`${gw.base}/`, {
          headers: { authorization: basicAuth('tester', `wrong-${index}`), ...REMOTE_HEADERS },
        });
        assert.equal(res.status, 401, `第 ${index + 1} 次错误应当是 401`);
      }
      const tripped = await fetch(`${gw.base}/`, {
        headers: { authorization: basicAuth('tester', 'wrong-4'), ...REMOTE_HEADERS },
      });
      assert.equal(tripped.status, 429);
      assert.ok(Number(tripped.headers.get('retry-after')) > 0);

      // 锁定期间即使密码正确也进不来。
      const blocked = await fetch(`${gw.base}/`, {
        headers: { authorization: basicAuth('tester', 'right-password'), ...REMOTE_HEADERS },
      });
      assert.equal(blocked.status, 429);
      assert.match(await blocked.text(), /频繁/);
    } finally {
      await gw.dispose();
    }
  });

  it('不带任何凭据的裸握手不计数，连刷也不会被锁', async () => {
    const gw = await startGateway();
    try {
      for (let index = 0; index < 8; index += 1) {
        const res = await fetch(`${gw.base}/`, { headers: { ...REMOTE_HEADERS } });
        assert.equal(res.status, 401);
      }
      const ok = await fetch(`${gw.base}/`, { headers: { authorization: AUTH, ...REMOTE_HEADERS } });
      assert.equal(ok.status, 200);
    } finally {
      await gw.dispose();
    }
  });
});

describe('流式与长连接', () => {
  it('POST 正文原样转发到上游', async () => {
    const gw = await startGateway();
    try {
      const payload = JSON.stringify({ hello: 'world' });
      const res = await fetch(`${gw.base}/api/echo`, {
        method: 'POST',
        headers: { authorization: AUTH, 'content-type': 'application/json' },
        body: payload,
      });
      await res.text();
      assert.equal(gw.host.last().method, 'POST');
      assert.equal(gw.host.last().body.toString('utf8'), payload);
    } finally {
      await gw.dispose();
    }
  });

  it('查询串与路径原样带到上游', async () => {
    const gw = await startGateway();
    try {
      await fetch(`${gw.base}/a/b?x=1&y=2`, { headers: { authorization: AUTH } });
      assert.equal(gw.host.last().url, '/a/b?x=1&y=2');
    } finally {
      await gw.dispose();
    }
  });
});
