/**
 * 配置读写接口 `/coopanion/reverse-proxy-gateway/config`。
 *
 * 这是唯一能改网关自身设置的入口：字段校验挡的是「把网关改成敞开」的写法，
 * 所以每个字段的合法/非法两侧都要钉住，接口层面的错误码同理。
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { createServer } from 'node:http';
import { join } from 'node:path';

import { startGateway, basicAuth, REMOTE_HEADERS } from './helpers/gateway.mjs';

const CONFIG = '/coopanion/reverse-proxy-gateway/config';
const AUTH = basicAuth('tester', 'secret');

/** 配置路由挂在宿主 webServer 上，直连宿主最贴近真实调用。 */
const hostBase = (gw) => `http://127.0.0.1:${gw.host.port}`;

/** 以 Basic 身份发一次配置请求。 */
async function post(gw, body, { headers = {}, raw = false } = {}) {
  const res = await fetch(`${hostBase(gw)}${CONFIG}`, {
    method: 'POST',
    headers: {
      authorization: AUTH,
      'content-type': 'application/json',
      ...headers,
    },
    body: raw ? body : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

async function get(gw, headers = {}) {
  const res = await fetch(`${hostBase(gw)}${CONFIG}`, { headers: { authorization: AUTH, ...headers } });
  return { status: res.status, body: await res.json().catch(() => null) };
}

describe('配置接口：入口与错误码', () => {
  it('未认证 401', async () => {
    const gw = await startGateway();
    try {
      const res = await fetch(`${hostBase(gw)}${CONFIG}`, { headers: { ...REMOTE_HEADERS } });
      assert.equal(res.status, 401);
      assert.equal((await res.json()).error, 'unauthorized');
    } finally {
      await gw.dispose();
    }
  });

  it('DELETE 返回 405', async () => {
    const gw = await startGateway();
    try {
      const res = await fetch(`${hostBase(gw)}${CONFIG}`, { method: 'DELETE', headers: { authorization: AUTH } });
      assert.equal(res.status, 405);
      assert.equal((await res.json()).error, 'method-not-allowed');
    } finally {
      await gw.dispose();
    }
  });

  it('非 JSON 的 Content-Type 返回 415', async () => {
    const gw = await startGateway();
    try {
      const result = await post(gw, 'username=evil', { headers: { 'content-type': 'text/plain' }, raw: true });
      assert.equal(result.status, 415);
      assert.equal(result.body.error, 'unsupported-media-type');
    } finally {
      await gw.dispose();
    }
  });

  it('未知字段返回 400 unknown-field', async () => {
    const gw = await startGateway();
    try {
      const result = await post(gw, { nope: 1 });
      assert.equal(result.status, 400);
      assert.equal(result.body.error, 'unknown-field');
      assert.match(String(result.body.message), /nope/);
    } finally {
      await gw.dispose();
    }
  });

  it('空补丁返回 400 empty-patch', async () => {
    const gw = await startGateway();
    try {
      const result = await post(gw, {});
      assert.equal(result.status, 400);
      assert.equal(result.body.error, 'empty-patch');
    } finally {
      await gw.dispose();
    }
  });

  it('把密码与 token 同时清空返回 400 no-credential', async () => {
    const gw = await startGateway();
    try {
      const result = await post(gw, { password: '', accessToken: '' });
      assert.equal(result.status, 400);
      assert.equal(result.body.error, 'no-credential');
    } finally {
      await gw.dispose();
    }
  });

  it('只清密码、保留 token 是允许的', async () => {
    const gw = await startGateway({ config: { accessToken: 'k'.repeat(20) } });
    try {
      const result = await post(gw, { password: '' });
      assert.equal(result.status, 200);
      assert.equal(result.body.config.settings.hasPassword, false);
      assert.equal(result.body.config.settings.accessToken, 'k'.repeat(20));
    } finally {
      await gw.dispose();
    }
  });

  it('GET 返回本机标记与白名单外的敏感字段', async () => {
    const gw = await startGateway();
    try {
      const { status, body } = await get(gw);
      assert.equal(status, 200);
      assert.equal(body.local, true, '回环来源应判为本机');
      assert.equal(body.settings.hasPassword, true);
      assert.deepEqual(body.restartKeys, ['port', 'listen']);
      // 密码本身永远不回传，只回 hasPassword。
      assert.equal(JSON.stringify(body).includes('secret'), false);
    } finally {
      await gw.dispose();
    }
  });

  it('网关转发过来的远程请求 local 为 false', async () => {
    const gw = await startGateway();
    try {
      // 判定依据是网关写下的 x-dsh-rpg-peer，而不是 x-forwarded-for：
      // 后者可以被任意客户端伪造，前者只有网关自己会写。
      const { body } = await get(gw, { 'x-dsh-rpg-peer': 'remote' });
      assert.equal(body.local, false);
    } finally {
      await gw.dispose();
    }
  });

  it('只带 x-forwarded-for 不足以被判为远程', async () => {
    const gw = await startGateway();
    try {
      const { body } = await get(gw, { 'x-forwarded-for': '203.0.113.9' });
      assert.equal(body.local, true);
    } finally {
      await gw.dispose();
    }
  });
});

describe('配置接口：字段校验', () => {
  const cases = [
    { key: 'enabled', good: [true, false], bad: [1, 'true', null] },
    { key: 'username', good: ['dsh', 'a', 'x'.repeat(64), '  trimmed  '], bad: ['', 'x'.repeat(65), 'has space', 'has:colon', 42] },
    // 注意：空串本身是合法值（表示关掉密码登录），但单独提交会触发 no-credential，
    // 那是跨字段规则，另有专项用例覆盖，这里只测字段自身的边界。
    { key: 'password', good: ['p'.repeat(8), 'p'.repeat(128), '有中文的密码也可以'], bad: ['short', 'p'.repeat(129), 42, null] },
    { key: 'accessToken', good: ['', 't'.repeat(16), 'abc-DEF_123456789'], bad: ['short', 't'.repeat(129), 'has space', 'has.dot', 42] },
    // 布尔要单独拒绝：Number(true) === 1 会让它悄悄通过「≥1」这条。
    { key: 'cookieDays', good: [1, 30, 3650], bad: [0, 3651, 'abc', null, true, false] },
    { key: 'switchMode', good: ['local', 'always', 'never'], bad: ['LOCAL', '', 'sometimes', 1] },
    { key: 'confirmToggle', good: [true, false], bad: ['true', 0] },
    { key: 'remotePicker', good: [true, false], bad: ['true', 0] },
    { key: 'browseRoot', good: ['', '/Users', '/', '  /tmp  '], bad: ['relative/path', 'x'.repeat(4097), 42] },
    { key: 'port', good: [1024, 3080, 65535], bad: [1023, 65536, 'abc', null, true] },
    { key: 'listen', good: ['0.0.0.0', '::', 'localhost', '192.168.1.20'], bad: ['', 'example.com', '0.0.0.0:80', 42] },
  ];

  for (const { key, good, bad } of cases) {
    it(`${key} 接受合法值、拒绝非法值`, async () => {
      for (const value of good) {
        const gw = await startGateway();
        try {
          const result = await post(gw, { [key]: value });
          assert.equal(result.status, 200, `${key}=${JSON.stringify(value)} 应被接受，实际 ${result.status} ${JSON.stringify(result.body)}`);
        } finally {
          await gw.dispose();
        }
      }
      for (const value of bad) {
        const gw = await startGateway();
        try {
          const result = await post(gw, { [key]: value });
          assert.equal(result.status, 400, `${key}=${JSON.stringify(value)} 应被拒绝`);
          assert.match(String(result.body.error), /^(bad-|invalid-)/, `${key} 的错误码应是 bad-/invalid- 前缀`);
        } finally {
          await gw.dispose();
        }
      }
    });
  }

  it('publicUrl 接受单个与多个入口，并归一化为逗号分隔', async () => {
    const gw = await startGateway();
    try {
      const single = await post(gw, { publicUrl: 'https://a.example' });
      assert.equal(single.status, 200);
      assert.equal(single.body.config.settings.publicUrl, 'https://a.example');

      const multi = await post(gw, { publicUrl: ' https://a.example , https://b.example ' });
      assert.equal(multi.status, 200);
      assert.equal(multi.body.config.settings.publicUrl, 'https://a.example,https://b.example');

      const cleared = await post(gw, { publicUrl: '' });
      assert.equal(cleared.status, 200);
      assert.equal(cleared.body.config.settings.publicUrl, '');
    } finally {
      await gw.dispose();
    }
  });

  it('publicUrl 拒绝非 http(s) 与空协议', async () => {
    for (const value of ['ftp://a.example', 'a.example', 'http://', 'javascript:alert(1)']) {
      const gw = await startGateway();
      try {
        const result = await post(gw, { publicUrl: value });
        assert.equal(result.status, 400, `${value} 应被拒绝`);
        assert.equal(result.body.error, 'bad-url');
      } finally {
        await gw.dispose();
      }
    }
  });

  it('publicUrl 的错误信息带上具体出错的那一项', async () => {
    const gw = await startGateway();
    try {
      const result = await post(gw, { publicUrl: 'https://ok.example,ftp://bad.example' });
      assert.equal(result.status, 400);
      assert.match(String(result.body.message), /ftp:\/\/bad\.example/);
    } finally {
      await gw.dispose();
    }
  });
});

describe('配置接口：落盘与热应用', () => {
  it('保存后写入覆盖文件，权限 600', async () => {
    const gw = await startGateway();
    try {
      const result = await post(gw, { username: 'newuser', cookieDays: 7 });
      assert.equal(result.status, 200);
      assert.equal(result.body.config.settings.username, 'newuser');
      assert.equal(result.body.config.settings.cookieDays, 7);

      const raw = readFileSync(join(gw.home.home, '.dsh-reverse-proxy-gateway.json'), 'utf8');
      const saved = JSON.parse(raw);
      assert.equal(saved.username, 'newuser');
      assert.equal(saved.cookieDays, 7);
    } finally {
      await gw.dispose();
    }
  });

  it('改 port 会标记 restartRequired，不立即换端口', async () => {
    const gw = await startGateway();
    try {
      const result = await post(gw, { port: 3999 });
      assert.equal(result.status, 200);
      assert.equal(result.body.restartRequired, true);
      assert.ok(result.body.config.restartKeys.includes('port'));
      // 仍在原端口服务
      const again = await get(gw);
      assert.equal(again.status, 200);
    } finally {
      await gw.dispose();
    }
  });

  it('改 switchMode 这类不需要重启的字段不标记重启', async () => {
    const gw = await startGateway();
    try {
      const result = await post(gw, { switchMode: 'never' });
      assert.equal(result.status, 200);
      assert.notEqual(result.body.restartRequired, true);
      assert.equal(result.body.config.settings.switchMode, 'never');
    } finally {
      await gw.dispose();
    }
  });

  it('一次提交多个字段全部生效', async () => {
    const gw = await startGateway();
    try {
      const result = await post(gw, { username: 'multi', cookieDays: 90, switchMode: 'always', confirmToggle: false });
      assert.equal(result.status, 200);
      assert.equal(result.body.config.settings.username, 'multi');
      assert.equal(result.body.config.settings.cookieDays, 90);
      assert.equal(result.body.config.settings.switchMode, 'always');
      assert.equal(result.body.config.settings.confirmToggle, false);
    } finally {
      await gw.dispose();
    }
  });

  it('坏 JSON 请求体不会崩服务', async () => {
    const gw = await startGateway();
    try {
      const result = await post(gw, '{"username":', { raw: true });
      assert.ok(result.status >= 400 && result.status < 500, `实际 ${result.status}`);
      const after = await get(gw);
      assert.equal(after.status, 200, '服务应仍然可用');
    } finally {
      await gw.dispose();
    }
  });

  it('关掉开关时立刻销毁已建立的连接，不留 keep-alive 尾巴', async () => {
    const gw = await startGateway();
    try {
      const socket = connect(gw.port, '127.0.0.1');
      const closed = new Promise((resolve) => socket.once('close', () => resolve(true)));
      socket.on('error', () => {});
      await new Promise((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
      });
      // 发一个保活请求，让连接进入 keep-alive 空闲状态。
      socket.write(
        'GET / HTTP/1.1\r\nHost: gw.example\r\nConnection: keep-alive\r\n' +
          `Authorization: ${AUTH}\r\n\r\n`,
      );
      await new Promise((resolve) => socket.once('data', resolve));

      const result = await post(gw, { enabled: false });
      assert.equal(result.status, 200);

      const timedOut = await Promise.race([
        closed,
        new Promise((resolve) => setTimeout(() => resolve(false), 2000)),
      ]);
      assert.equal(timedOut, true, '关掉开关后连接应被主动断开');
    } finally {
      await gw.dispose();
    }
  });

  it('端口抢不到时，保存结果里带着原因', async () => {
    // 曾经的实现只把 EADDRINUSE 写进宿主日志，界面上永远只有一句「未监听」。
    // 现在最后一次监听失败的原因会随配置一起返回。
    const gw = await startGateway();
    const port = gw.port;
    let blocker = null;
    try {
      await post(gw, { enabled: false });
      blocker = createServer(() => {});
      await new Promise((resolve) => blocker.listen(port, '127.0.0.1', resolve));
      const data = await post(gw, { enabled: true });
      assert.equal(data.status, 200);
      assert.equal(data.body.config.runtime.listening, false);
      assert.match(String(data.body.config.runtime.listenError), /已被占用/);
    } finally {
      if (blocker) await new Promise((resolve) => blocker.close(resolve));
      await gw.dispose();
    }
  });

  it('重新打开开关后，响应里的状态已经是监听中', async () => {
    // 不等监听就回答的话，boundPort 还是 null，用户刚打开开关就看到「未监听」。
    const gw = await startGateway();
    try {
      await post(gw, { enabled: false });
      const data = await post(gw, { enabled: true });
      assert.equal(data.status, 200);
      assert.equal(data.body.config.runtime.listening, true);
      assert.equal(data.body.config.runtime.listenError, null);
    } finally {
      await gw.dispose();
    }
  });
});
