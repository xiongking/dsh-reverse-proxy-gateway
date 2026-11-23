/**
 * HTML 注入与压缩处理 —— 通过真实 HTTP 观察，因为这两个函数是 apply() 的闭包。
 *
 * 关注点：什么时候插脚本、插在哪里、插入后 content-length 与 content-encoding 是否自洽。
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';

import { startGateway, basicAuth, REMOTE_HEADERS } from './helpers/gateway.mjs';

const AUTH = basicAuth('tester', 'secret');
const PICKER_PATH = '/__dshgw/picker.js';

/** 发一次请求；默认带 Basic 认证与远程来源头。 */
async function get(gw, path = '/', options = {}) {
  const headers = { authorization: AUTH, accept: 'text/html', ...(options.headers || {}) };
  if (options.remote !== false) Object.assign(headers, REMOTE_HEADERS);
  return fetch(`${gw.base}${path}`, { headers, redirect: 'manual', method: options.method || 'GET' });
}

describe('HTML 注入', () => {
  let gw;

  before(async () => {
    gw = await startGateway({ host: { body: '<html><head><title>t</title></head><body>hi</body></html>' } });
  });

  after(async () => {
    await gw.dispose();
  });

  it('远程访问时把脚本插在 </head> 之前', async () => {
    const res = await get(gw);
    const html = await res.text();
    assert.match(html, /<script src="\/__dshgw\/picker\.js\?v=[0-9a-f]{10}"><\/script><\/head>/);
  });

  it('脚本地址带内容版本号，改动脚本后能绕过缓存', async () => {
    const html = await (await get(gw)).text();
    assert.match(html, /\?v=[0-9a-f]{10}/);
  });

  it('本机访问时完全不注入', async () => {
    const res = await fetch(`${gw.base}/`, { headers: { authorization: AUTH, accept: 'text/html' } });
    const html = await res.text();
    assert.equal(html.includes(PICKER_PATH), false);
  });

  it('remotePicker 关闭时不注入', async () => {
    const local = await startGateway({
      config: { remotePicker: false },
      host: { body: '<html><head></head></html>' },
    });
    try {
      const html = await (await get(local)).text();
      assert.equal(html.includes(PICKER_PATH), false);
    } finally {
      await local.dispose();
    }
  });

  it('注入后 content-length 与实际正文一致', async () => {
    const res = await get(gw);
    const html = await res.text();
    assert.equal(Number(res.headers.get('content-length')), Buffer.byteLength(html, 'utf8'));
  });

  it('注入后不再声称压缩', async () => {
    const res = await get(gw);
    await res.text();
    assert.equal(res.headers.get('content-encoding'), null);
  });

  it('非 HTML 响应不注入', async () => {
    gw.host.setRespond(() => ({
      status: 200,
      headers: { 'content-type': 'application/json', 'content-length': '2' },
      payload: Buffer.from('{}'),
    }));
    const res = await get(gw);
    assert.equal(await res.text(), '{}');
  });

  it('页面已含脚本时不重复注入', async () => {
    gw.host.setRespond(() => {
      const body = `<html><head><script src="${PICKER_PATH}?v=old"></script></head></html>`;
      return {
        status: 200,
        headers: { 'content-type': 'text/html', 'content-length': String(Buffer.byteLength(body)) },
        payload: Buffer.from(body),
      };
    });
    const html = await (await get(gw)).text();
    assert.equal(html.split(PICKER_PATH).length - 1, 1);
  });

  it('没有 head 的完整文档把脚本放在最前面', async () => {
    gw.host.setRespond(() => {
      const body = '<html><body><div>x</div></body></html>';
      return {
        status: 200,
        headers: { 'content-type': 'text/html', 'content-length': String(Buffer.byteLength(body)) },
        payload: Buffer.from(body),
      };
    });
    const html = await (await get(gw)).text();
    assert.equal(html.startsWith('<script'), true);
  });

  it('HTML 片段不注入（接口也会返回 text/html，往片段里塞 script 没有意义）', async () => {
    gw.host.setRespond(() => {
      const body = '<div>fragment</div>';
      return {
        status: 200,
        headers: { 'content-type': 'text/html', 'content-length': String(Buffer.byteLength(body)) },
        payload: Buffer.from(body),
      };
    });
    const html = await (await get(gw)).text();
    assert.equal(html, '<div>fragment</div>');
    assert.equal(html.includes(PICKER_PATH), false);
  });

  it('只有 DOCTYPE 没有 <html> 也算文档', async () => {
    gw.host.setRespond(() => {
      const body = '<!DOCTYPE html><head></head><body>x</body>';
      return {
        status: 200,
        headers: { 'content-type': 'text/html', 'content-length': String(Buffer.byteLength(body)) },
        payload: Buffer.from(body),
      };
    });
    const html = await (await get(gw)).text();
    assert.equal(html.includes(PICKER_PATH), true);
  });

  it('有 <head> 但没有 </head> 时插在 <head> 之后', async () => {
    gw.host.setRespond(() => {
      const body = '<html><head><meta charset="utf-8"><body>x</body></html>';
      return {
        status: 200,
        headers: { 'content-type': 'text/html', 'content-length': String(Buffer.byteLength(body)) },
        payload: Buffer.from(body),
      };
    });
    const html = await (await get(gw)).text();
    assert.match(html, /<head><script src="\/__dshgw\/picker\.js\?v=[0-9a-f]{10}"><\/script><meta charset="utf-8">/);
  });
});

describe('无正文响应不注入', () => {
  let gw;

  before(async () => {
    gw = await startGateway({ host: { body: '<html><head></head></html>' } });
  });

  after(async () => {
    await gw.dispose();
  });

  it('HEAD 请求不注入也不产生正文', async () => {
    const res = await get(gw, '/', { method: 'HEAD' });
    const text = await res.text();
    assert.equal(res.status, 200);
    assert.equal(text, '');
  });

  it('204 响应不注入', async () => {
    gw.host.setRespond(() => ({ status: 204, headers: {}, payload: Buffer.alloc(0) }));
    const res = await get(gw);
    await res.text();
    assert.equal(res.status, 204);
  });

  it('304 响应不注入', async () => {
    gw.host.setRespond(() => ({ status: 304, headers: {}, payload: Buffer.alloc(0) }));
    const res = await get(gw);
    await res.text();
    assert.equal(res.status, 304);
  });
});

describe('压缩正文', () => {
  for (const encoding of ['gzip', 'deflate', 'br']) {
    it(`${encoding} 压缩的 HTML 能解压后注入，并去掉 content-encoding`, async () => {
      const gw = await startGateway({
        host: {
          body: '<html><head><title>z</title></head><body>c</body></html>',
          encoding,
        },
      });
      try {
        const res = await get(gw);
        const html = await res.text();
        assert.equal(res.status, 200);
        assert.equal(res.headers.get('content-encoding'), null, '注入后必须是明文');
        assert.equal(html.includes(PICKER_PATH), true, `解压后的正文里应有脚本标签（${encoding}）`);
        assert.equal(Number(res.headers.get('content-length')), Buffer.byteLength(html, 'utf8'));
      } finally {
        await gw.dispose();
      }
    });
  }

  it('无法解压的压缩正文原样返回，不让页面挂掉', async () => {
    const gw = await startGateway();
    try {
      const garbage = Buffer.from('this is not gzip at all');
      gw.host.setRespond(() => ({
        status: 200,
        headers: {
          'content-type': 'text/html',
          'content-encoding': 'gzip',
          'content-length': String(garbage.length),
        },
        payload: garbage,
      }));
      // 用 node:http 直取原始字节：undici 的 fetch 会自动解压，这里要看的正是未解压的透传。
      const res = await rawGet(gw.port, '/', { authorization: AUTH, accept: 'text/html', ...REMOTE_HEADERS });
      assert.equal(res.status, 200);
      assert.equal(res.body.includes(PICKER_PATH), false, '解不开就放弃注入');
      assert.equal(res.body.toString('utf8'), 'this is not gzip at all');
      assert.equal(Number(res.headers['content-length']), res.body.length);
    } finally {
      await gw.dispose();
    }
  });
});

describe('选择器脚本本身', () => {
  let gw;

  before(async () => {
    gw = await startGateway({ config: { browseRoot: '/' } });
  });

  after(async () => {
    await gw.dispose();
  });

  it('同源请求能取到脚本，且带版本号', async () => {
    const res = await fetch(`${gw.base}${PICKER_PATH}`, {
      headers: { authorization: AUTH, accept: 'text/javascript', ...REMOTE_HEADERS },
    });
    const body = await res.text();
    assert.equal(res.status, 200);
    assert.match(String(res.headers.get('content-type')), /javascript/);
    assert.equal(body.includes('上一级'), true);
    assert.match(String(res.headers.get('etag')), /^"[0-9a-f]{10}"$/);
  });

  it('未认证时取不到脚本', async () => {
    const res = await fetch(`${gw.base}${PICKER_PATH}`, { headers: { ...REMOTE_HEADERS } });
    assert.equal(res.status, 401);
  });

  it('跨站来源取脚本被拒', async () => {
    const res = await fetch(`${gw.base}${PICKER_PATH}`, {
      headers: {
        authorization: AUTH,
        ...REMOTE_HEADERS,
        origin: 'https://evil.example.net',
      },
    });
    assert.equal(res.status, 403);
  });
});

/** 走 node:http 取原始响应字节，绕过 fetch 的自动解压。 */
function rawGet(port, path, headers) {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: '127.0.0.1', port, path, method: 'GET', headers },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) })
        );
        res.on('error', reject);
      }
    );
    req.on('error', reject);
    req.end();
  });
}
