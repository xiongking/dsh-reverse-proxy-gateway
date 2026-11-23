/**
 * 来源判定与审计、多入口解析。
 *
 * `isLoopbackPeer` / `isRemotePeerRequest` 决定「这次请求算不算远程」——它同时管着
 * 目录选择器要不要注入、以及写给宿主的 `x-dsh-rpg-peer` 头，判错会让本机也被当成远程。
 * `appendAudit` 与 `publicUrlList` 是安全改造新增的两个纯函数，逻辑最容易在后续改动里退化。
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, statSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { isLoopbackPeer, isTrustedProxyPeer, isRemotePeerRequest, appendAudit, publicUrlList } from '../index.mjs';

describe('isLoopbackPeer', () => {
  it('识别回环地址的各种写法', () => {
    for (const address of ['127.0.0.1', '::1', '127.1.2.3', '127.0.0.53', '::ffff:127.0.0.1', '::ffff:127.9.9.9']) {
      assert.equal(isLoopbackPeer(address), true, address);
    }
  });

  it('大小写与空白不影响判定', () => {
    assert.equal(isLoopbackPeer('  ::FFFF:127.0.0.1  '), true);
    assert.equal(isLoopbackPeer('::FFFF:127.0.0.1'), true);
  });

  it('公网与内网地址都不算回环', () => {
    for (const address of ['203.0.113.9', '10.0.0.5', '192.168.1.20', '172.16.0.1', '8.8.8.8']) {
      assert.equal(isLoopbackPeer(address), false, address);
    }
  });

  it('只认 127. 前缀，其他 127 开头的边界不误判', () => {
    assert.equal(isLoopbackPeer('127.example.com'), true, 'RFC 不要求，但字符串前缀按实现视为回环');
    assert.equal(isLoopbackPeer('128.0.0.1'), false);
    assert.equal(isLoopbackPeer('2127.0.0.1'), false);
  });

  it('非字符串输入一律不算回环', () => {
    for (const value of [undefined, null, 0, 127, {}, [], true]) {
      assert.equal(isLoopbackPeer(value), false, String(value));
    }
  });
});

describe('isTrustedProxyPeer', () => {
  it('回环地址算可信', () => {
    for (const address of ['127.0.0.1', '::1', '127.1.2.3', '::ffff:127.0.0.1']) {
      assert.equal(isTrustedProxyPeer(address), true, address);
    }
  });

  it('私有网段算可信', () => {
    for (const address of ['10.0.0.5', '192.168.1.10', '172.16.0.1', '172.31.255.254', '169.254.1.1', '100.64.0.1']) {
      assert.equal(isTrustedProxyPeer(address), true, address);
    }
  });

  it('公网地址不可信，即使写成 IPv4-mapped', () => {
    for (const address of ['203.0.113.7', '8.8.8.8', '::ffff:203.0.113.7', '172.32.0.1', '100.128.0.1']) {
      assert.equal(isTrustedProxyPeer(address), false, address);
    }
  });

  it('非法输入一律不可信', () => {
    for (const value of [undefined, null, '', 'not-an-ip', '::2']) {
      assert.equal(isTrustedProxyPeer(value), false, String(value));
    }
  });
});

describe('isRemotePeerRequest', () => {
  const remote = (remoteAddress) => ({ headers: {}, socket: { remoteAddress } });

  it('没有请求对象时不算远程', () => {
    assert.equal(isRemotePeerRequest(null), false);
    assert.equal(isRemotePeerRequest(undefined), false);
  });

  it('宿主标记头优先：带 x-dsh-rpg-peer: remote 就算远程', () => {
    assert.equal(isRemotePeerRequest({ headers: { 'x-dsh-rpg-peer': 'remote' }, socket: { remoteAddress: '127.0.0.1' } }), true);
  });

  it('标记头是别的值时不生效', () => {
    assert.equal(isRemotePeerRequest({ headers: { 'x-dsh-rpg-peer': 'local' }, socket: { remoteAddress: '127.0.0.1' } }), false);
    assert.equal(isRemotePeerRequest({ headers: { 'x-dsh-rpg-peer': 'REMOTE' }, socket: { remoteAddress: '127.0.0.1' } }), false);
  });

  it('回环对端不是远程', () => {
    assert.equal(isRemotePeerRequest(remote('127.0.0.1')), false);
    assert.equal(isRemotePeerRequest(remote('::1')), false);
  });

  it('公网对端是远程', () => {
    assert.equal(isRemotePeerRequest(remote('203.0.113.9')), true);
    assert.equal(isRemotePeerRequest(remote('192.168.1.20')), true);
  });

  it('拿不到对端地址时不算远程（宁可不注入）', () => {
    assert.equal(isRemotePeerRequest({ headers: {} }), false);
    assert.equal(isRemotePeerRequest({ headers: {}, socket: {} }), false);
    assert.equal(isRemotePeerRequest({ socket: { remoteAddress: undefined } }), false);
  });
});

describe('publicUrlList', () => {
  it('逗号分隔', () => {
    assert.deepEqual(publicUrlList('https://a.example,https://b.example'), ['https://a.example', 'https://b.example']);
  });

  it('空白分隔（空格、换行、制表）', () => {
    assert.deepEqual(publicUrlList('https://a.example  https://b.example\nhttps://c.example\t'), [
      'https://a.example',
      'https://b.example',
      'https://c.example',
    ]);
  });

  it('混合分隔与多余分隔符', () => {
    assert.deepEqual(publicUrlList(' https://a.example ,, https://b.example , '), ['https://a.example', 'https://b.example']);
  });

  it('数组输入会去掉空项并 trim', () => {
    assert.deepEqual(publicUrlList([' https://a.example ', '', 'https://b.example', '   ']), ['https://a.example', 'https://b.example']);
  });

  it('数组里非字符串项被丢弃', () => {
    assert.deepEqual(publicUrlList(['https://a.example', 42, null, { url: 'x' }]), ['https://a.example']);
  });

  it('空串、纯空白、非字符串类型都得到空数组', () => {
    assert.deepEqual(publicUrlList(''), []);
    assert.deepEqual(publicUrlList('   '), []);
    assert.deepEqual(publicUrlList(undefined), []);
    assert.deepEqual(publicUrlList(null), []);
    assert.deepEqual(publicUrlList(42), []);
    assert.deepEqual(publicUrlList({}), []);
  });

  it('单个地址原样返回', () => {
    assert.deepEqual(publicUrlList('https://dsh.example.com/'), ['https://dsh.example.com/']);
  });
});

describe('appendAudit', () => {
  let dir;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'rpg-audit-'));
  });
  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('写入一行 JSON，带自动时间戳，权限 600', () => {
    const file = join(dir, 'a.log');
    assert.equal(appendAudit(file, { event: 'login-ok', user: 'tester' }), true);
    const lines = readFileSync(file, 'utf8').trim().split('\n');
    assert.equal(lines.length, 1);
    const entry = JSON.parse(lines[0]);
    assert.equal(entry.event, 'login-ok');
    assert.equal(entry.user, 'tester');
    assert.match(String(entry.ts), /^\d{4}-\d{2}-\d{2}T/);
    assert.equal(statSync(file).mode & 0o777, 0o600);
  });

  it('连续追加，每次一行', () => {
    const file = join(dir, 'b.log');
    appendAudit(file, { event: 'one' });
    appendAudit(file, { event: 'two' });
    appendAudit(file, { event: 'three' });
    const entries = readFileSync(file, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
    assert.deepEqual(entries.map((entry) => entry.event), ['one', 'two', 'three']);
  });

  it('调用方给的 ts 覆盖自动时间戳', () => {
    const file = join(dir, 'c.log');
    appendAudit(file, { event: 'fixed', ts: '2020-01-01T00:00:00.000Z' });
    assert.equal(JSON.parse(readFileSync(file, 'utf8').trim()).ts, '2020-01-01T00:00:00.000Z');
  });

  it('超过 5MB 时轮转为 .1 并重新开始', () => {
    const file = join(dir, 'd.log');
    const big = 'x'.repeat(5 * 1024 * 1024 + 10);
    writeFileSync(file, big, 'utf8');
    assert.equal(appendAudit(file, { event: 'after-rotate' }), true);
    assert.equal(existsSync(`${file}.1`), true);
    assert.equal(statSync(`${file}.1`).size, big.length);
    const entries = readFileSync(file, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
    assert.deepEqual(entries.map((entry) => entry.event), ['after-rotate']);
  });

  it('轮转保留三代，最老的一代被覆盖', () => {
    const file = join(dir, 'e.log');
    const filler = 'y'.repeat(5 * 1024 * 1024 + 10);
    writeFileSync(file, filler, 'utf8');
    appendAudit(file, { event: 'first' });
    assert.equal(statSync(`${file}.1`).size, filler.length, '第一次轮转把旧文件整体换出');

    writeFileSync(file, 'z'.repeat(5 * 1024 * 1024 + 10), 'utf8');
    appendAudit(file, { event: 'second' });
    assert.equal(existsSync(`${file}.2`), true, '上一代被挤到 .2 而不是被丢掉');
    assert.equal(statSync(`${file}.1`).size, 5 * 1024 * 1024 + 10);
    assert.equal(JSON.parse(readFileSync(file, 'utf8').trim()).event, 'second');

    writeFileSync(file, 'w'.repeat(5 * 1024 * 1024 + 10), 'utf8');
    appendAudit(file, { event: 'third' });
    assert.equal(existsSync(`${file}.3`), true);
    assert.equal(existsSync(`${file}.4`), false, '只留三代');
  });

  it('写不进去时返回 false 而不抛错', () => {
    assert.equal(appendAudit(join(dir, 'no-such-dir', 'x.log'), { event: 'x' }), false);
    assert.equal(appendAudit('', { event: 'x' }), false);
  });

  it('条目里的特殊字符不会破坏 JSONL 结构', () => {
    const file = join(dir, 'f.log');
    appendAudit(file, { event: 'weird', detail: 'line1\nline2 "quoted" \\backslash' });
    const lines = readFileSync(file, 'utf8').trim().split('\n');
    assert.equal(lines.length, 1);
    assert.equal(JSON.parse(lines[0]).detail, 'line1\nline2 "quoted" \\backslash');
  });
});
