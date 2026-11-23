/**
 * 跨站来源校验。
 *
 * 网关自己的 `/__dshgw/*` 接口绕开宿主路由，因此拿不到宿主的 Host/Origin 围栏。
 * 缺了这层，用户登录网关后，任何网页都能带着网关 cookie 跨站调用它们（列举目录、建目录）。
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { crossSiteRejection } from '../index.mjs';

/** 造一个最小 req：只用 headers。 */
const req = (headers) => ({ headers });

const PUBLIC_URL = 'https://dsh.example.com:8443/';

describe('crossSiteRejection', () => {
  it('无 Origin 且未声明 cross-site 时放行（非浏览器客户端、同源 GET）', () => {
    assert.equal(crossSiteRejection(req({ host: 'dsh.example.com:8443' }), ''), null);
  });

  it('Origin 与 Host 同源时放行', () => {
    const headers = { host: 'dsh.example.com:8443', origin: 'https://dsh.example.com:8443' };
    assert.equal(crossSiteRejection(req(headers), ''), null);
  });

  it('Origin 与 Host 不同源时拒绝', () => {
    const headers = { host: 'dsh.example.com:8443', origin: 'https://evil.example.net' };
    assert.equal(crossSiteRejection(req(headers), ''), 'origin-mismatch');
  });

  it('Sec-Fetch-Site: cross-site 时拒绝（挡住不带 Origin 的 <img>/<script>）', () => {
    const headers = { host: 'dsh.example.com:8443', 'sec-fetch-site': 'cross-site' };
    assert.equal(crossSiteRejection(req(headers), ''), 'sec-fetch-site');
  });

  it('Sec-Fetch-Site: same-origin 时放行', () => {
    const headers = { host: 'dsh.example.com:8443', 'sec-fetch-site': 'same-origin' };
    assert.equal(crossSiteRejection(req(headers), ''), null);
  });

  it('Sec-Fetch-Site: same-site 时按同源放行（同站不同子域不拦截）', () => {
    const headers = { host: 'dsh.example.com', 'sec-fetch-site': 'same-site' };
    assert.equal(crossSiteRejection(req(headers), ''), null);
  });

  it('cross-site 优先于 Origin 判断：两者都存在时按 cross-site 拒绝', () => {
    const headers = {
      host: 'dsh.example.com',
      origin: 'https://dsh.example.com',
      'sec-fetch-site': 'cross-site',
    };
    assert.equal(crossSiteRejection(req(headers), ''), 'sec-fetch-site');
  });

  it('Origin 不是合法 URL 时拒绝', () => {
    assert.equal(crossSiteRejection(req({ host: 'a.example.com', origin: 'not a url' }), ''), 'bad-origin');
  });

  it('Origin: null 时拒绝（沙箱 iframe 与部分重定向会这样发）', () => {
    assert.equal(crossSiteRejection(req({ host: 'a.example.com', origin: 'null' }), ''), 'bad-origin');
  });

  it('Origin 非 http(s) 协议时拒绝', () => {
    for (const origin of ['file:///etc/passwd', 'chrome-extension://abcdef', 'data:text/html,x']) {
      assert.equal(crossSiteRejection(req({ host: 'a.example.com', origin }), ''), 'bad-origin', origin);
    }
  });

  it('有 Origin 但没有 Host 时拒绝', () => {
    assert.equal(crossSiteRejection(req({ origin: 'https://a.example.com' }), ''), 'missing-host');
  });

  it('Host 无法组成 URL 时拒绝', () => {
    assert.equal(crossSiteRejection(req({ host: ':::', origin: 'https://a.example.com' }), ''), 'bad-host');
  });

  it('Host 省略端口时用 Origin 的 scheme 补齐后比较', () => {
    const headers = { host: 'dsh.example.com', origin: 'https://dsh.example.com' };
    assert.equal(crossSiteRejection(req(headers), ''), null);
  });

  it('Host 与 Origin 端口不同时拒绝', () => {
    const headers = { host: 'dsh.example.com:3080', origin: 'https://dsh.example.com:8443' };
    assert.equal(crossSiteRejection(req(headers), ''), 'origin-mismatch');
  });

  it('配置了 publicUrl 时，Origin 等于 publicUrl 的 authority 即放行（反代改写了 Host）', () => {
    // 真实链路：公网域名 -> 路由器/隧道 -> 网关，Host 可能被改成 127.0.0.1:3080。
    const headers = { host: '127.0.0.1:3080', origin: 'https://dsh.example.com:8443' };
    assert.equal(crossSiteRejection(req(headers), PUBLIC_URL), null);
  });

  it('配置了 publicUrl 也不能放过外站 Origin', () => {
    const headers = { host: '127.0.0.1:3080', origin: 'https://evil.example.net' };
    assert.equal(crossSiteRejection(req(headers), PUBLIC_URL), 'origin-mismatch');
  });

  it('publicUrl 为空时不启用兜底，仍按 Host 比较', () => {
    const headers = { host: '127.0.0.1:3080', origin: 'https://dsh.example.com:8443' };
    assert.equal(crossSiteRejection(req(headers), ''), 'origin-mismatch');
  });

  it('publicUrl 本身不合法时忽略兜底而不是抛错', () => {
    const headers = { host: 'a.example.com', origin: 'https://a.example.com' };
    assert.equal(crossSiteRejection(req(headers), 'not-a-url'), null);
  });

  it('headers 为空对象时按放行处理', () => {
    assert.equal(crossSiteRejection({}, ''), null);
  });

  it('Origin 为空串等同于没有 Origin', () => {
    assert.equal(crossSiteRejection(req({ host: 'a.example.com', origin: '' }), ''), null);
  });
});
