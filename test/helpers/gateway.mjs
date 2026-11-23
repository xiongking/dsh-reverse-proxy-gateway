/**
 * 起一套完整的被测链路：假 DSH_HOME + 假宿主 + 假 ctx + 真实网关。
 *
 * 用法：
 *   const gw = await startGateway({ config: { password: 'p' } });
 *   ... 对 http://127.0.0.1:${gw.port} 发请求 ...
 *   await gw.dispose();
 */
import { apply } from '../../index.mjs';
import { makeTmpHome, pickPort, waitForPort } from './tmp-home.mjs';
import { makeCtx } from './fake-ctx.mjs';
import { makeFakeHost } from './fake-host.mjs';

const DEFAULT_CONFIG = {
  enabled: true,
  listen: '127.0.0.1',
  username: 'tester',
  password: 'secret',
  accessToken: '',
  cookieDays: 30,
  publicUrl: '',
  switchMode: 'local',
  confirmToggle: true,
  remotePicker: true,
  browseRoot: '',
};

/**
 * @param {object} [options]
 * @param {object} [options.config] 合并进默认网关配置
 * @param {object} [options.overrides] 写入覆盖文件的内容（模拟界面保存过的值）
 * @param {object} [options.host] 传给 makeFakeHost 的响应默认值
 * @param {number} [options.hostCookieMaxAgeMs] 模拟宿主 cookieMaxAgeDays（毫秒）
 */
export async function startGateway(options = {}) {
  const home = await makeTmpHome({ overrides: options.overrides });
  // 先建路由表：假宿主和假 ctx 共用同一张，宿主才能把 /coopanion/... 派回插件。
  const routes = new Map();
  const host = await makeFakeHost({ ...(options.host || {}), routeTable: routes });

  // pickPort() 是「借一个空闲端口再释放」，释放到网关真正监听之间有窗口，
  // 并行跑多个测试文件时可能被别人抢走。撞上就换个端口重来，别让用例偶然变红。
  let lastError = null;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const port = await pickPort();
    const { ctx, dispose } = makeCtx({
      upstreamPort: host.port,
      routes,
      hostCookieMaxAgeMs: options.hostCookieMaxAgeMs,
    });

    apply(ctx, { ...DEFAULT_CONFIG, port, ...(options.config || {}) });

    if (await waitForPort(port)) {
      return {
        port,
        host,
        routes,
        home,
        base: `http://127.0.0.1:${port}`,
        async dispose() {
          dispose();
          await host.close();
          await home.cleanup();
        },
      };
    }

    dispose();
    lastError = new Error(`网关没有在 127.0.0.1:${port} 上监听`);
  }

  await host.close();
  await home.cleanup();
  throw lastError;
}

/** 拼 Basic Auth 头。 */
export function basicAuth(user, pass) {
  return 'Basic ' + Buffer.from(`${user}:${pass}`, 'utf8').toString('base64');
}

/** 模拟「从公网经反代进来」的请求头（网关据此判定为远程访问）。 */
export const REMOTE_HEADERS = { 'x-forwarded-for': '203.0.113.7' };
