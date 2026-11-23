/**
 * 网关登录 cookie 与「吊销」语义。
 *
 * 这一组回答一个问题：改了密码、换了 token、点了「退出所有登录」之后，
 * 之前发出去的 cookie 到底还认不认。认，就等于密码改了也没用。
 */
import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  credentialTag,
  cookieKeyFor,
  signGatewayCookie,
  verifyGatewayCookie,
  readEpoch,
  writeEpoch,
  base64Url,
} from '../index.mjs';

const SECRET = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8');
const TAG = credentialTag('dsh', 'secret-password', '');
const KEY = cookieKeyFor(SECRET, `${TAG}.epoch-a`);

function keyFor({ username = 'dsh', password = 'secret-password', token = '', epoch = 'epoch-a' } = {}) {
  return cookieKeyFor(SECRET, `${credentialTag(username, password, token)}.${epoch}`);
}

describe('credentialTag', () => {
  it('同一组凭据稳定，改动任一项都变', () => {
    const base = credentialTag('dsh', 'p1', 't1');
    assert.equal(credentialTag('dsh', 'p1', 't1'), base);
    assert.notEqual(credentialTag('dsh2', 'p1', 't1'), base);
    assert.notEqual(credentialTag('dsh', 'p2', 't1'), base);
    assert.notEqual(credentialTag('dsh', 'p1', 't2'), base);
  });

  it('字段拼接不会因为内容挪位而撞车', () => {
    assert.notEqual(credentialTag('ab', 'c', ''), credentialTag('a', 'bc', ''));
  });

  it('输出是可用于派生密钥的定长十六进制串', () => {
    assert.match(credentialTag('dsh', 'p', ''), /^[0-9a-f]{64}$/);
  });
});

describe('cookieKeyFor', () => {
  it('指纹或世代变化都会换 key', () => {
    const base = cookieKeyFor(SECRET, 'a');
    assert.notEqual(cookieKeyFor(SECRET, 'b'), base);
    assert.notEqual(cookieKeyFor(Buffer.from('fedcba9876543210fedcba9876543210', 'utf8'), 'a'), base);
  });
});

describe('signGatewayCookie / verifyGatewayCookie', () => {
  it('往返可验，三段式且带 v2 前缀', () => {
    const value = signGatewayCookie(KEY, 30, TAG);
    const parts = value.split('.');
    assert.equal(parts.length, 3);
    assert.equal(parts[0], 'v2');
    assert.equal(verifyGatewayCookie(value, KEY, TAG), true);
  });

  it('载荷里有签发时间与到期时间，且不含明文凭据', () => {
    const value = signGatewayCookie(KEY, 30, TAG);
    const body = value.split('.')[1];
    const payload = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    assert.ok(Number.isFinite(payload.exp));
    assert.ok(Number.isFinite(payload.iat));
    assert.equal(payload.exp - payload.iat, 30 * 86_400_000);
    assert.equal(payload.tag, TAG);
    assert.equal(value.includes('secret-password'), false);
  });

  it('改动载荷任一字节都验不过', () => {
    const value = signGatewayCookie(KEY, 30, TAG);
    const [prefix, body, signature] = value.split('.');
    const flipped = body.slice(0, -2) + (body.slice(-2) === 'AA' ? 'BB' : 'AA');
    assert.equal(verifyGatewayCookie(`${prefix}.${flipped}.${signature}`, KEY, TAG), false);
  });

  it('改动签名验不过', () => {
    const value = signGatewayCookie(KEY, 30, TAG);
    const [prefix, body, signature] = value.split('.');
    const flipped = signature.slice(0, -2) + (signature.slice(-2) === 'AA' ? 'BB' : 'AA');
    assert.equal(verifyGatewayCookie(`${prefix}.${body}.${flipped}`, KEY, TAG), false);
  });

  it('过期即失效', () => {
    const expired = signGatewayCookie(KEY, -1, TAG);
    assert.equal(verifyGatewayCookie(expired, KEY, TAG), false);
  });

  it('旧的 v1 格式（只有到期毫秒）一律不认', () => {
    const legacy = `${Date.now() + 86_400_000}.${base64Url(Buffer.from('x'))}`;
    assert.equal(verifyGatewayCookie(legacy, KEY, TAG), false);
  });

  it('git 里那种没有 v2 前缀的三段式也不认', () => {
    assert.equal(verifyGatewayCookie('v1.a.b', KEY, TAG), false);
  });

  it('非字符串输入返回 false', () => {
    for (const value of [null, undefined, 42, {}, []]) {
      assert.equal(verifyGatewayCookie(value, KEY, TAG), false);
    }
  });

  it('指纹不同的 cookie 在同一个 key 下也验不过（纵深防御）', () => {
    const otherTag = credentialTag('dsh', 'another-password', '');
    const value = signGatewayCookie(cookieKeyFor(SECRET, `${otherTag}.epoch-a`), 30, otherTag);
    assert.equal(verifyGatewayCookie(value, KEY, TAG), false);
  });
});

describe('吊销语义', () => {
  it('改密码后旧 cookie 失效', () => {
    const before = signGatewayCookie(keyFor({ password: 'old-password' }), 30, credentialTag('dsh', 'old-password', ''));
    const afterKey = keyFor({ password: 'new-password' });
    const afterTag = credentialTag('dsh', 'new-password', '');
    assert.equal(verifyGatewayCookie(before, afterKey, afterTag), false);
  });

  it('改 token 后旧 cookie 失效', () => {
    const oldTag = credentialTag('dsh', 'secret-password', '');
    const before = signGatewayCookie(keyFor({ token: '' }), 30, oldTag);
    const newTag = credentialTag('dsh', 'secret-password', 'brand-new-token');
    assert.equal(verifyGatewayCookie(before, keyFor({ token: 'brand-new-token' }), newTag), false);
  });

  it('轮换世代后旧 cookie 失效，但凭据不变', () => {
    const before = signGatewayCookie(keyFor({ epoch: 'epoch-a' }), 30, TAG);
    assert.equal(verifyGatewayCookie(before, keyFor({ epoch: 'epoch-b' }), TAG), false);
    // 世代没动时仍然有效，确认失效确实来自轮换而不是别的。
    assert.equal(verifyGatewayCookie(before, keyFor({ epoch: 'epoch-a' }), TAG), true);
  });
});

describe('世代文件', () => {
  const dir = mkdtempSync(join(tmpdir(), 'rpg-epoch-'));

  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('文件不存在时返回 null', () => {
    assert.equal(readEpoch(join(dir, 'missing.json')), null);
  });

  it('写入后可读回，权限 600', () => {
    const file = join(dir, 'sessions.json');
    writeEpoch(file, 'epoch-value-0123456789');
    assert.equal(readEpoch(file), 'epoch-value-0123456789');
    assert.equal(statSync(file).mode & 0o777, 0o600);
    const parsed = JSON.parse(readFileSync(file, 'utf8'));
    assert.equal(parsed.epoch, 'epoch-value-0123456789');
  });

  it('内容坏掉或世代过短时当作没有', () => {
    const file = join(dir, 'bad.json');
    writeEpoch(file, 'short');
    assert.equal(readEpoch(file), null);
  });
});
