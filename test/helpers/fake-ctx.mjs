/**
 * 假的 cordis ctx —— 只实现 `apply()` 真正用到的部分。
 *
 * 实测依赖面（对 index.mjs 的 apply 做静态统计得出）：
 *   ctx.inject            ×1（注入 ['webServer']）
 *   ctx.get('connection') ×1（读宿主 cookieMaxAgeDays，读不到退回默认）
 *   scoped.webServer      ×2（读 listenedPort / server.address() / config.port / register）
 *   scoped.effect         ×4（挂载路由、注册 dispose）
 * 其余一概不碰，所以这里不需要模拟整个宿主。
 */

/**
 * @param {object} options
 * @param {number} options.upstreamPort 假宿主的端口，网关会转发到这里
 * @param {number} [options.hostCookieMaxAgeMs] 模拟宿主的 cookieMaxAgeDays（毫秒），不传则模拟「读不到」
 * @returns {{ctx: object, routes: Map<string, Function>, dispose: () => void}}
 */
export function makeCtx(options) {
  const upstreamPort = options.upstreamPort;
  // 允许外部传进来一张表：假宿主需要用它把 /coopanion/... 的请求派回插件自己的处理器。
  const routes = options.routes || new Map();
  const hostCookieMaxAgeMs = options.hostCookieMaxAgeMs;
  const disposers = [];
  let injected = false;

  const webServer = {
    listenedPort: upstreamPort,
    config: { port: upstreamPort },
    server: {
      address: () => ({ address: '127.0.0.1', family: 'IPv4', port: upstreamPort }),
    },
    register(route) {
      routes.set(route.path, route.handler);
      return () => routes.delete(route.path);
    },
  };

  const ctx = {
    // 真实宿主上取 connection 服务，插件用它读会话寿命上限。
    // 不传 hostCookieMaxAgeMs 时返回 undefined，覆盖「读不到就退回默认」那条分支。
    get(name) {
      if (name !== 'connection') return undefined;
      if (hostCookieMaxAgeMs === undefined) return undefined;
      return { browserAuth: { maxAgeMilliseconds: hostCookieMaxAgeMs } };
    },
    // 不给 logger，让 log() 退到 stderr；测试想静音就传一个假 logger。
    inject(deps, callback) {
      if (injected) throw new Error('ctx.inject 被调用了两次');
      injected = true;
      const scoped = {
        webServer,
        effect(fn) {
          const disposer = fn();
          if (typeof disposer === 'function') disposers.push(disposer);
          return () => {};
        },
      };
      const result = callback(scoped);
      if (typeof result === 'function') disposers.push(result);
      return () => {};
    },
  };

  return {
    ctx,
    routes,
    /** 按注册逆序释放，释放后网关停止监听。 */
    dispose() {
      while (disposers.length > 0) {
        const disposer = disposers.pop();
        try {
          disposer();
        } catch {}
      }
    },
  };
}
