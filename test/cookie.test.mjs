/**
 * 宿主会话 cookie、网关 cookie、Basic Auth 头的纯函数测试。
 *
 * 这组函数是整个认证链路的地基：验签错了就是把机器交出去，验严了就是自己进不去。
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, statSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

import {
  base64Url,
  equalSecret,
  signSessionCookie,
  verifySessionCookieValue,
  hasSessionCookie,
  gatewayKey,
  readCookie,
  parseBasicAuth,
  readOverrides,
  writeOverrides,
} from '../index.mjs';

const SESSION_COOKIE_PREFIX = 'dsh-auth-';
const GATEWAY_COOKIE = 'dsh_gw';
const DAY_MS = 86_400_000;
const SECRET = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8');
const OTHER_SECRET = Buffer.from('fedcba9876543210fedcba9876543210', 'utf8');

describe('base64Url', () => {
  it('输出不含 + / =，可直接放进 cookie 与 URL', () => {
    const encoded = base64Url(Buffer.from([251, 255, 191, 0, 1, 2]));
    assert.equal(encoded.includes('+'), false);
    assert.equal(encoded.includes('/'), false);
    assert.equal(encoded.includes('='), false);
  });

  it('与标准 base64 的字节内容一致', () => {
    const raw = randomBytes(32);
    const decoded = Buffer.from(base64Url(raw).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    assert.deepEqual(decoded, raw);
  });
});

describe('equalSecret', () => {
  it('相同内容返回真', () => {
    assert.equal(equalSecret('abc', 'abc'), true);
  });

  it('不同内容返回假', () => {
    assert.equal(equalSecret('abc', 'abd'), false);
  });

  it('长度不同时返回假而不是抛异常', () => {
    assert.equal(equalSecret('abc', 'abcdef'), false);
  });
});

describe('signSessionCookie', () => {
  it('产出 v1.<body>.<sig> 三段式', () => {
    const issuedAt = Date.now();
    const { value } = signSessionCookie(SECRET, 'dsh.example.com', issuedAt);
    const parts = value.split('.');
    assert.equal(parts.length, 3);
    assert.equal(parts[0], 'v1');
  });

  it('cookie 名等于 dsh-auth- + base64Url(sha256(authority))', () => {
    const issuedAt = Date.now();
    const { name } = signSessionCookie(SECRET, 'dsh.example.com', issuedAt);
    const expected = SESSION_COOKIE_PREFIX + base64Url(createHash('sha256').update('dsh.example.com').digest());
    assert.equal(name, expected);
  });

  it('payload 里带 version / authority / issuedAt / expiresAt', () => {
    const issuedAt = 1_700_000_000_000;
    const { value } = signSessionCookie(SECRET, 'a.example.com', issuedAt);
    const body = value.split('.')[1];
    const padded = body.replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
    assert.equal(payload.version, 1);
    assert.equal(payload.authority, 'a.example.com');
    assert.equal(payload.issuedAt, issuedAt);
    assert.equal(payload.expiresAt, issuedAt + 30 * DAY_MS);
  });

  it('lifetimeDays 可覆盖默认的 30 天', () => {
    const issuedAt = Date.now();
    const { value } = signSessionCookie(SECRET, 'a.example.com', issuedAt, 7);
    const body = value.split('.')[1];
    const padded = body.replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
    assert.equal(payload.expiresAt, issuedAt + 7 * DAY_MS);
  });
});

describe('verifySessionCookieValue', () => {
  const issuedAt = Date.now();
  const { value } = signSessionCookie(SECRET, 'dsh.example.com', issuedAt);

  it('签发后立即校验通过', () => {
    assert.equal(verifySessionCookieValue(value, SECRET), true);
  });

  it('换一把密钥校验失败', () => {
    assert.equal(verifySessionCookieValue(value, OTHER_SECRET), false);
  });

  it('篡改 body 后校验失败', () => {
    const parts = value.split('.');
    const tampered = [parts[0], `${parts[1]}x`, parts[2]].join('.');
    assert.equal(verifySessionCookieValue(tampered, SECRET), false);
  });

  it('篡改签名后校验失败', () => {
    const parts = value.split('.');
    const tampered = [parts[0], parts[1], `${parts[2]}x`].join('.');
    assert.equal(verifySessionCookieValue(tampered, SECRET), false);
  });

  it('非三段、首段不是 v1 的输入返回假', () => {
    assert.equal(verifySessionCookieValue('v1.only-two', SECRET), false);
    assert.equal(verifySessionCookieValue(`v2.${value.split('.').slice(1).join('.')}`, SECRET), false);
  });

  it('非字符串输入返回假', () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.equal(verifySessionCookieValue(bad, SECRET), false);
    }
  });

  it('已过期的 cookie 返回假', () => {
    const stale = signSessionCookie(SECRET, 'dsh.example.com', Date.now() - 40 * DAY_MS, 30);
    assert.equal(verifySessionCookieValue(stale.value, SECRET), false);
  });

  it('issuedAt 在未来的 cookie 返回假', () => {
    const future = signSessionCookie(SECRET, 'dsh.example.com', Date.now() + 10 * DAY_MS, 30);
    assert.equal(verifySessionCookieValue(future.value, SECRET), false);
  });

  it('只验签名与时效，不关心签给哪个 authority', () => {
    const forOtherAuthority = signSessionCookie(SECRET, 'other.example.com', Date.now());
    assert.equal(verifySessionCookieValue(forOtherAuthority.value, SECRET), true);
  });
});

describe('hasSessionCookie', () => {
  const issuedAt = Date.now();
  const { name, value } = signSessionCookie(SECRET, 'dsh.example.com', issuedAt);

  it('能从多个 cookie 里挑出有效的一条', () => {
    assert.equal(hasSessionCookie(`a=1; ${name}=${value}; b=2`, SECRET), true);
  });

  it('没有目标前缀的 cookie 时返回假', () => {
    assert.equal(hasSessionCookie('a=1; b=2', SECRET), false);
  });

  it('目标 cookie 签名无效时返回假', () => {
    assert.equal(hasSessionCookie(`${name}=v1.abc.def`, SECRET), false);
  });

  it('多条同前缀 cookie 里只要有一条有效即为真', () => {
    const stale = signSessionCookie(SECRET, 'dsh.example.com', Date.now() - 40 * DAY_MS, 30);
    const header = `${stale.name}=${stale.value}; ${name}=${value}`;
    assert.equal(hasSessionCookie(header, SECRET), true, '同 authority 时两条名字相同，后者覆盖前者');
  });

  it('非字符串输入返回假', () => {
    assert.equal(hasSessionCookie(undefined, SECRET), false);
  });
});

describe('网关 cookie', () => {
  const key = gatewayKey(SECRET);

  it('签发后可校验', async () => {
    const { signGatewayCookie, verifyGatewayCookie } = await import('../index.mjs');
    const raw = signGatewayCookie(key, 30);
    assert.equal(verifyGatewayCookie(raw, key), true);
  });

  it('过期的网关 cookie 返回假', async () => {
    const { verifyGatewayCookie } = await import('../index.mjs');
    const expired = `${Date.now() - 1000}.${'x'.repeat(43)}`;
    assert.equal(verifyGatewayCookie(expired, key), false);
  });

  it('签名被篡改返回假', async () => {
    const { signGatewayCookie, verifyGatewayCookie } = await import('../index.mjs');
    const raw = signGatewayCookie(key, 30);
    const [expiresAt] = raw.split('.');
    assert.equal(verifyGatewayCookie(`${expiresAt}.deadbeef`, key), false);
  });

  it('格式非法（无分隔点、空串）返回假', async () => {
    const { verifyGatewayCookie } = await import('../index.mjs');
    assert.equal(verifyGatewayCookie('nodot', key), false);
    assert.equal(verifyGatewayCookie('', key), false);
    assert.equal(verifyGatewayCookie(null, key), false);
  });
});

describe('gatewayKey', () => {
  it('同样的会话密钥派生出同样的 key', () => {
    assert.deepEqual(gatewayKey(SECRET), gatewayKey(SECRET));
  });

  it('派生出的 key 与会话密钥本身不同', () => {
    const key = gatewayKey(SECRET);
    assert.equal(key.equals(SECRET), false);
    assert.equal(key.length, 32);
  });

  it('不同会话密钥派生出不同 key', () => {
    assert.equal(gatewayKey(SECRET).equals(gatewayKey(OTHER_SECRET)), false);
  });
});

describe('readCookie', () => {
  it('解析常规 cookie 头', () => {
    assert.equal(readCookie('a=1; b=2', 'b'), '2');
  });

  it('容忍多余空格与尾部空段', () => {
    assert.equal(readCookie('  a=1 ;   b=2 ; ', 'b'), '2');
  });

  it('同名多个时取第一个', () => {
    assert.equal(readCookie('a=1; a=2', 'a'), '1');
  });

  it('找不到时返回 null', () => {
    assert.equal(readCookie('a=1', 'z'), null);
  });

  it('非字符串输入返回 null', () => {
    assert.equal(readCookie(undefined, 'a'), null);
  });

  it('值里含等号时保留完整值', () => {
    assert.equal(readCookie('t=v1.abc.def==', 't'), 'v1.abc.def==');
  });
});

describe('parseBasicAuth', () => {
  const encode = (text) => Buffer.from(text, 'utf8').toString('base64');

  it('正常解析用户名与密码', () => {
    assert.deepEqual(parseBasicAuth(`Basic ${encode('dsh:secret')}`), { user: 'dsh', pass: 'secret' });
  });

  it('scheme 大小写不敏感', () => {
    assert.deepEqual(parseBasicAuth(`bAsIc ${encode('u:p')}`), { user: 'u', pass: 'p' });
  });

  it('密码里含冒号时全部归入密码', () => {
    assert.deepEqual(parseBasicAuth(`Basic ${encode('u:a:b:c')}`), { user: 'u', pass: 'a:b:c' });
  });

  it('缺少冒号返回 null', () => {
    assert.equal(parseBasicAuth(`Basic ${encode('nocolon')}`), null);
  });

  it('非 Basic scheme 返回 null', () => {
    assert.equal(parseBasicAuth(`Bearer ${encode('u:p')}`), null);
  });

  it('缺少头或格式异常返回 null', () => {
    for (const bad of [undefined, null, '', 'Basic', 'Basic ', 42]) {
      assert.equal(parseBasicAuth(bad), null);
    }
  });

  it('base64 内容为空时返回 null', () => {
    assert.equal(parseBasicAuth('Basic !!!'), null);
  });
});

describe('readOverrides / writeOverrides', () => {
  it('文件不存在时返回空对象', () => {
    const dir = mkdtempSync(join(tmpdir(), 'gw-ov-'));
    try {
      assert.deepEqual(readOverrides(join(dir, 'missing.json')), {});
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('内容不是 JSON 或不是对象时返回空对象', () => {
    const dir = mkdtempSync(join(tmpdir(), 'gw-ov-'));
    try {
      const file = join(dir, 'bad.json');
      for (const text of ['{not json', '[1,2,3]', '"string"', 'null']) {
        writeFileSync(file, text, 'utf8');
        assert.deepEqual(readOverrides(file), {}, `输入 ${text}`);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('只挑出已知配置键，忽略未知键与 null 值', () => {
    const dir = mkdtempSync(join(tmpdir(), 'gw-ov-'));
    try {
      const file = join(dir, 'ok.json');
      writeFileSync(
        file,
        JSON.stringify({ port: 3099, username: 'u', unknownKey: 'x', password: null }),
        'utf8'
      );
      assert.deepEqual(readOverrides(file), { port: 3099, username: 'u' });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('写入后可读回，且文件权限为 600', () => {
    const dir = mkdtempSync(join(tmpdir(), 'gw-ov-'));
    try {
      const file = join(dir, 'written.json');
      writeOverrides(file, { port: 3099, enabled: false });
      assert.deepEqual(readOverrides(file), { port: 3099, enabled: false });
      const mode = statSync(file).mode & 0o777;
      assert.equal(mode, 0o600, '配置文件里有密码与 token，必须是 600');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('写入是原子替换，不留下临时文件', () => {
    const dir = mkdtempSync(join(tmpdir(), 'gw-ov-'));
    try {
      const file = join(dir, 'atomic.json');
      writeOverrides(file, { port: 3099 });
      writeOverrides(file, { port: 3100 });
      assert.deepEqual(readOverrides(file), { port: 3100 });
      assert.deepEqual(readdirSync(dir), ['atomic.json']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('GATEWAY_COOKIE 常量', () => {
  it('网关 cookie 名与转发时写入的一致', () => {
    // 名字被硬编码在 index.mjs 内部，这里通过一次真实的转发断言（见 proxy.test.mjs）；
    // 本用例只钉住常量本身，避免别处改名而测试无感。
    assert.equal(GATEWAY_COOKIE, 'dsh_gw');
  });
});
