import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { startGateway, basicAuth, REMOTE_HEADERS } from './helpers/gateway.mjs';
import { verifySessionCookieValue, SESSION_COOKIE_PREFIX } from '../index.mjs';

const STATE = '/coopanion/reverse-proxy-gateway/state';

describe('宿主会话 cookie 寿命跟随宿主配置', () => {
  it('宿主把 cookieMaxAgeDays 调小时，签出的寿命跟着变短', async () => {
    const gw = await startGateway({ hostCookieMaxAgeMs: 2 * 86_400_000 });
    try {
      const res = await fetch(`${gw.base}${STATE}`, { headers: { authorization: basicAuth('tester', 'secret') } });
      assert.equal((await res.json()).sessionCookie.lifetimeDays, 2);
    } finally { await gw.dispose(); }
  });

  it('读不到宿主配置时退回默认 30 天', async () => {
    const gw = await startGateway();
    try {
      const res = await fetch(`${gw.base}${STATE}`, { headers: { authorization: basicAuth('tester', 'secret') } });
      assert.equal((await res.json()).sessionCookie.lifetimeDays, 30);
    } finally { await gw.dispose(); }
  });

  it('注入给宿主的 cookie 寿命不超过宿主上限', async () => {
    // 宿主校验里有一条「寿命超过 cookieMaxAgeDays 即作废」，超了就是整页 401。
    const gw = await startGateway({ hostCookieMaxAgeMs: 3 * 86_400_000 });
    try {
      const res = await fetch(`${gw.base}/`, {
        headers: { authorization: basicAuth('tester', 'secret'), ...REMOTE_HEADERS },
      });
      assert.equal(res.status, 200);
      const seen = gw.host.requests.at(-1);
      const pair = String(seen.headers.cookie || '')
        .split('; ')
        .find((item) => item.startsWith(SESSION_COOKIE_PREFIX));
      assert.ok(pair, '应当注入了宿主会话 cookie');

      const value = pair.slice(pair.indexOf('=') + 1);
      assert.equal(verifySessionCookieValue(value, gw.home.secret), true, 'cookie 应当可验签');

      const body = value.split('.')[1];
      const payload = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
      assert.equal((payload.expiresAt - payload.issuedAt) / 86_400_000, 3);
    } finally {
      await gw.dispose();
    }
  });
});
