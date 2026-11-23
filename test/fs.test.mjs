/**
 * 远程目录选择器的服务端接口：列目录与建目录。
 *
 * 这里直接打 HTTP，因为越界判定、符号链接过滤、错误文案都是闭包内的实现。
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, symlink, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { startGateway, basicAuth, REMOTE_HEADERS } from './helpers/gateway.mjs';

const AUTH = basicAuth('tester', 'secret');
const LIST = '/__dshgw/fs/list';
const MKDIR = '/__dshgw/fs/mkdir';

/** 发 JSON 请求；默认带认证与远程来源头。 */
async function call(gw, path, options = {}) {
  const headers = { authorization: AUTH, ...REMOTE_HEADERS, ...(options.headers || {}) };
  const res = await fetch(`${gw.base}${path}`, {
    method: options.method || 'GET',
    headers,
    body: options.body,
    redirect: 'manual',
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: res.status, json, text, headers: res.headers };
}

function names(listing) {
  return listing.entries.map((entry) => entry.name);
}

describe('列目录', () => {
  let gw;
  let root;
  let outside;

  before(async () => {
    // macOS 上 /var 指向 /private/var，接口返回的是 realpath 之后的路径，期望值也要归一。
    root = await realpath(await mkdtemp(join(tmpdir(), 'rpg-list-')));
    outside = await realpath(await mkdtemp(join(tmpdir(), 'rpg-out-')));

    // 根下：两个目录 + 一个文件 + 一个指向根内的链接 + 一个指向根外的链接
    await mkdir(join(root, 'zebra'));
    await mkdir(join(root, 'alpha'));
    await writeFile(join(root, 'note.txt'), 'x', 'utf8');
    await mkdir(join(outside, 'secret'));
    await symlink(join(root, 'alpha'), join(root, 'link-inside'));
    await symlink(join(outside, 'secret'), join(root, 'link-outside'));
    await symlink(join(root, 'note.txt'), join(root, 'link-to-file'));

    gw = await startGateway({ config: { browseRoot: root } });
  });

  after(async () => {
    await gw.dispose();
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  });

  it('不传 path 时落在浏览范围内（家目录不在根内，退回根）', async () => {
    const res = await call(gw, LIST);
    assert.equal(res.status, 200);
    assert.equal(res.json.ok, true);
    assert.equal(res.json.path, root);
    assert.equal(res.json.root, root);
    assert.equal(res.json.parent, null, '已经贴着根，没有上一级');
  });

  it('只返回目录，不返回普通文件', async () => {
    const res = await call(gw, LIST);
    const list = names(res.json);
    assert.equal(list.includes('note.txt'), false);
    assert.equal(list.includes('zebra'), true);
  });

  it('按名称排序', async () => {
    const res = await call(gw, LIST);
    assert.deepEqual(names(res.json), ['alpha', 'link-inside', 'zebra']);
  });

  it('指向根内的符号链接保留，指向根外的被过滤', async () => {
    const res = await call(gw, LIST);
    const list = names(res.json);
    assert.equal(list.includes('link-inside'), true);
    assert.equal(list.includes('link-outside'), false, '逃出浏览范围的链接不能出现');
    assert.equal(list.includes('link-to-file'), false, '指向文件的链接不是可进入的目录');
  });

  it('进入子目录后 parent 指向上一层', async () => {
    const res = await call(gw, `${LIST}?path=${encodeURIComponent(join(root, 'alpha'))}`);
    assert.equal(res.status, 200);
    assert.equal(res.json.path, join(root, 'alpha'));
    assert.equal(res.json.parent, root);
    assert.deepEqual(res.json.entries, []);
  });

  it('路径超出浏览根时拒绝', async () => {
    const res = await call(gw, `${LIST}?path=${encodeURIComponent(outside)}`);
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'fs-failed');
    assert.match(res.json.message, /超出浏览范围/);
  });

  it('路径不存在时给出可读原因', async () => {
    const res = await call(gw, `${LIST}?path=${encodeURIComponent(join(root, 'nope'))}`);
    assert.equal(res.status, 400);
    assert.match(res.json.message, /目录不存在/);
  });

  it('用 .. 绕行同样被拒', async () => {
    const res = await call(gw, `${LIST}?path=${encodeURIComponent(join(root, '..'))}`);
    assert.equal(res.status, 400);
    assert.match(res.json.message, /超出浏览范围/);
  });

  it('非 GET 方法被拒', async () => {
    const res = await call(gw, LIST, { method: 'POST' });
    assert.equal(res.status, 405);
    assert.equal(res.json.error, 'method-not-allowed');
  });

  it('未认证时 401', async () => {
    const res = await call(gw, LIST, { headers: { authorization: '' } });
    assert.equal(res.status, 401);
  });

  it('跨站来源被拒', async () => {
    const res = await call(gw, LIST, { headers: { origin: 'https://evil.example.net' } });
    assert.equal(res.status, 403);
    assert.equal(res.text, '跨站请求被拒绝');
  });

  it('Sec-Fetch-Site: cross-site 被拒', async () => {
    const res = await call(gw, LIST, { headers: { 'sec-fetch-site': 'cross-site' } });
    assert.equal(res.status, 403);
  });

  it('remotePicker 关闭时这些接口不再由网关接管', async () => {
    const off = await startGateway({
      config: { remotePicker: false, browseRoot: root },
      host: { body: 'host', headers: { 'content-type': 'text/plain' } },
    });
    try {
      const res = await call(off, LIST);
      assert.equal(res.status, 200);
      assert.equal(res.text, 'host', '应回落到宿主的转发链路');
    } finally {
      await off.dispose();
    }
  });
});

describe('建目录', () => {
  let gw;
  let root;

  before(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'rpg-mkdir-')));
    await mkdir(join(root, 'parent'));
    gw = await startGateway({ config: { browseRoot: root } });
  });

  after(async () => {
    await gw.dispose();
    await rm(root, { recursive: true, force: true });
  });

  function mkdirReq(payload) {
    return call(gw, MKDIR, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
  }

  it('正常创建并返回新路径', async () => {
    const res = await mkdirReq({ path: root, name: 'fresh' });
    assert.equal(res.status, 200);
    assert.equal(res.json.ok, true);
    assert.equal(res.json.path, join(root, 'fresh'));

    const listing = await call(gw, LIST);
    assert.equal(names(listing.json).includes('fresh'), true);
  });

  it('同名目录已存在时报错', async () => {
    const res = await mkdirReq({ path: root, name: 'fresh' });
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'mkdir-failed');
    assert.match(res.json.message, /同名目录已存在/);
  });

  it('目录名为空时报错', async () => {
    const res = await mkdirReq({ path: root, name: '   ' });
    assert.equal(res.status, 400);
    assert.match(res.json.message, /不能为空/);
  });

  it('目录名带路径分隔符时报错', async () => {
    const res = await mkdirReq({ path: root, name: 'a/b' });
    assert.equal(res.status, 400);
    assert.match(res.json.message, /路径分隔符/);
  });

  it('目录名是 .. 时报错', async () => {
    const res = await mkdirReq({ path: root, name: '..' });
    assert.equal(res.status, 400);
    assert.match(res.json.message, /目录名非法/);
  });

  it('父目录超出浏览范围时拒绝', async () => {
    const res = await mkdirReq({ path: tmpdir(), name: 'escape' });
    assert.equal(res.status, 400);
    assert.match(res.json.message, /超出浏览范围/);
  });

  it('父目录不存在时报错', async () => {
    const res = await mkdirReq({ path: join(root, 'ghost'), name: 'x' });
    assert.equal(res.status, 400);
    assert.match(res.json.message, /目录不存在/);
  });

  it('非 POST 方法被拒', async () => {
    const res = await call(gw, MKDIR);
    assert.equal(res.status, 405);
  });

  it('跨站请求被拒', async () => {
    const res = await call(gw, MKDIR, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://evil.example.net' },
      body: JSON.stringify({ path: root, name: 'x' }),
    });
    assert.equal(res.status, 403);
  });
});
