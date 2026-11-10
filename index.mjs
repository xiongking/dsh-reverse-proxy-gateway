/**
 * dsh-reverse-proxy-gateway — 把 DSH 的本地 Web 服务安全地反代到公网。
 *
 * 设计要点
 * --------
 * 1. 独立监听。插件在 DSH 进程内另起一个 HTTP 服务监听 config.listen 指定的地址，
 *    不动宿主原本的随机回环端口。公网侧的路由器/隧道只需指向这个固定端口。
 *
 * 2. 自己完成认证。Basic Auth 与固定 token 链接都在这里校验，通过后下发一条
 *    「网关 cookie」，浏览器后续请求凭它直通，移动端刷新/切后台也不会再问密码。
 *
 * 3. 转发时重写 Host 为回环字面量，并注入一条由 DSH 会话密钥即时签名的 cookie。
 *    这样宿主只看到「来自本机的已认证请求」，不需要在 profile 里配置 trustedHosts，
 *    也不需要把 cookieMaxAgeDays 拉长 —— 暴露面完全收敛在本插件内部。
 *
 * 4. 支持 WebSocket 与流式响应。普通请求走 http 层转发（要改头），upgrade 请求
 *    手工拼好请求头后把两个 socket 对接。
 *
 * 安全提示：DSH 拥有整机 shell 与全盘读写权限，一旦这层网关失守，等同于交出这台机器。
 * 不要把 listen 设成 0.0.0.0 后直接暴露到公网而不加 TLS；推荐由路由器或隧道终止 TLS。
 */
import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import { connect as netConnect } from 'node:net';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { mkdir, readdir, realpath, stat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { brotliDecompressSync, gunzipSync, inflateSync } from 'node:zlib';

export const name = 'reverse-proxy-gateway';

/** 宿主会话 cookie 的名字前缀，与 DSH 内置 connection 插件保持一致。 */
const SESSION_COOKIE_PREFIX = 'dsh-auth-';
/** 本插件自己的网关 cookie 名。 */
const GATEWAY_COOKIE = 'dsh_gw';
/** 状态查询路由，走网关认证后才可读。 */
const STATE_PATH = '/coopanion/reverse-proxy-gateway/state';
/** 配置读写路由：给插件详情页的卡片用，浏览器走同源相对路径访问。 */
const CONFIG_PATH = '/coopanion/reverse-proxy-gateway/config';
/** 运行期覆盖文件（界面保存的改动），放在 ~/.dsh 下。 */
const OVERRIDE_FILE = '.dsh-reverse-proxy-gateway.json';
/** 一次配置请求体的上限，够用且能挡住明显异常的大包。 */
const MAX_CONFIG_BYTES = 8 * 1024;
/** 只有这几个字段可以在运行期改动。 */
const CONFIG_KEYS = ['enabled', 'username', 'password', 'accessToken', 'publicUrl', 'cookieDays', 'port', 'listen', 'switchMode', 'confirmToggle', 'remotePicker', 'browseRoot'];
/** 改了这些字段必须重启 DSH 才生效（监听参数在监听时就被固定了）。 */
const RESTART_KEYS = ['port', 'listen'];
/** 从 process.argv 里识别 profile 目录，用于定位 ~/.dsh。 */
const PROFILE_ARG = /[\\/]profiles[\\/]([^\\/]+)[\\/]?$/;
/**
 * 网关转发时用来标记「这次请求的对端不是本机」。
 * 宿主只能看到网关自己（永远是回环），所以「浏览器是不是从本机进来」
 * 这一事实只能由网关观察连接后传给宿主，界面据此决定开关显不显示。
 */
const PEER_HEADER = 'x-dsh-rpg-peer';
const DAY_MS = 86_400_000;
/** 注入给宿主的会话 cookie 寿命：必须 ≤ 宿主的 cookieMaxAgeDays（桌面默认 30 天）。 */
const HOST_COOKIE_DAYS = 30;

/** 远程目录浏览：脚本本身，以及它调用的两个接口。 */
const PICKER_SCRIPT_PATH = '/__dshgw/picker.js';
const FS_LIST_PATH = '/__dshgw/fs/list';
const FS_MKDIR_PATH = '/__dshgw/fs/mkdir';
/** 一次最多返回的目录条目数，防止超大目录把响应撑爆。 */
const FS_MAX_ENTRIES = 500;

/* ------------------------------------------------------------------ *
 * 配置 schema
 *
 * 宿主会用这份 schema 自动渲染插件配置表单，所以字段描述即界面文案。
 * schemastery 在 profile 的 node_modules 里（不写进 dependencies，避免被
 * 兼容性版本范围拦住）；在仓库目录这类解析不到它的环境里，模块也必须照常加载，
 * 因此解析失败时只是不导出 Config。
 * ------------------------------------------------------------------ */
const requireFromPlugin = createRequire(import.meta.url);

function profileDir() {
  for (const arg of process.argv.slice(1).reverse()) {
    if (PROFILE_ARG.test(arg)) return arg;
  }
  return null;
}

/** DSH 根目录（profile 目录的上一级），定位 credentials 用。 */
function dshHome() {
  const explicit = process.env.DSH_HOME;
  if (explicit) return explicit;
  const dir = profileDir();
  if (dir) return join(dir, '..', '..');
  return join(homedir(), '.dsh');
}

function loadSchemastery() {
  const candidates = ['@deepseek-ai/schemastery'];
  const dir = profileDir();
  if (dir) candidates.push(join(dir, 'node_modules', '@deepseek-ai', 'schemastery'));
  for (const id of candidates) {
    try {
      const loaded = requireFromPlugin(id);
      const mod = loaded && loaded.default ? loaded.default : loaded;
      if (mod && typeof mod.object === 'function') return mod;
    } catch {}
  }
  return null;
}

let Config;
try {
  const z = loadSchemastery();
  Config = z
    ? z.object({
        enabled: z.boolean().default(true).description('是否启用外部反代网关'),
        listen: z
          .string()
          .default('0.0.0.0')
          .description('网关监听的地址，例如 0.0.0.0 表示所有网卡，127.0.0.1 表示只允许本机内的反向代理连入'),
        port: z
          .number()
          .min(1024)
          .max(65535)
          .step(1)
          .default(3080)
          .description('网关监听的端口，路由器或隧道应指向这里'),
        publicUrl: z
          .string()
          .default('')
          .description('对外访问地址（含协议与端口，如 https://dsh.example.com/），仅用于拼接固定登录链接和状态展示'),
        username: z.string().default('dsh').description('Basic Auth 用户名'),
        password: z.string().default('').description('Basic Auth 密码，留空则只接受固定 token 链接'),
        accessToken: z
          .string()
          .default('')
          .description('固定登录 token：访问 publicUrl + ?token=该值 可免密登录并写入长期 cookie，留空则不启用'),
        cookieDays: z
          .number()
          .min(1)
          .max(3650)
          .step(1)
          .default(30)
          .description('网关登录 cookie 的有效天数'),
        switchMode: z
          .union([z.const('local'), z.const('always'), z.const('never')])
          .default('local')
          .description(
            '输入框下方开关的显示范围：local 仅在本机（回环地址）访问时显示，always 始终显示，never 不显示'
          ),
        confirmToggle: z
          .boolean()
          .default(true)
          .description('点击开关后是否需要二次确认，避免触屏误触直接切断远程访问'),
        remotePicker: z
          .boolean()
          .default(true)
          .description(
            '远程访问时接管「创建工作区」的目录选择：改成浏览器内的目录浏览。关闭时远程仍会调用主机的系统对话框（弹在主机屏幕上）'
          ),
        browseRoot: z
          .string()
          .default('')
          .description('远程目录浏览的根目录，留空表示当前用户的主目录；不提供这个根之外的任何路径'),
      })
    : undefined;
} catch {
  Config = undefined;
}
export { Config };

/* ------------------------------------------------------------------ *
 * 工具函数
 * ------------------------------------------------------------------ */

function log(ctx, level, message) {
  const line = '[reverse-proxy-gateway] ' + message;
  try {
    const logger = ctx && ctx.logger;
    if (logger && typeof logger[level] === 'function') {
      logger[level](line);
      return;
    }
  } catch {}
  // 没有 logger 时退化为 stderr，至少要能在启动日志里看到。
  const text = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
  try {
    text.write(line + '\n');
  } catch {}
}

function base64Url(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * 定长比较，避免 Basic Auth 与 cookie 校验被计时侧信道试探。
 * 长度不同时也对两条定长摘要做一次比较，耗时与等长情形一致。
 */
function equalSecret(left, right) {
  const a = Buffer.from(String(left), 'utf8');
  const b = Buffer.from(String(right), 'utf8');
  if (a.length !== b.length) {
    // 比较两条摘要而不是比较自身，既保持定长又不泄漏「等长前缀是否相同」。
    timingSafeEqual(
      createHash('sha256').update(a).digest(),
      createHash('sha256').update(b).digest(),
    );
    return false;
  }
  return timingSafeEqual(a, b);
}

/**
 * 读取 DSH 的浏览器会话签名密钥。
 * 该密钥由宿主写在 credentials 文件里，长期不变，因此用它派生的网关 cookie
 * 与即时签发的宿主 cookie 都能跨进程重启继续有效。
 */
function readSessionSecret() {
  const file = join(dshHome(), '.credentials.yaml');
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (error) {
    throw new Error(`读不到 ${file}：${error && error.message ? error.message : error}`);
  }
  const matched = /client-connection\/browser-session:[\s\S]{0,200}?secret:\s*"?([A-Za-z0-9_\-+/=]{40,64})"?/.exec(text);
  if (!matched) throw new Error(`${file} 里没有 client-connection/browser-session 的 secret`);
  const raw = matched[1];
  const secret = Buffer.from(raw.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (secret.length !== 32) throw new Error(`会话密钥长度异常：${secret.length} 字节（应为 32）`);
  return secret;
}

/**
 * 按 DSH 的格式签发一条宿主会话 cookie。
 * 结构与宿主 lib 内一致：v1.<base64url(JSON payload)>.<base64url(HMAC-SHA256)>，
 * payload 里必须带 version / authority / issuedAt / expiresAt 四个字段。
 */
function signSessionCookie(secret, authority, issuedAt, lifetimeDays = 30) {
  const payload = { version: 1, authority, issuedAt, expiresAt: issuedAt + lifetimeDays * DAY_MS };
  const body = base64Url(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signature = base64Url(createHmac('sha256', secret).update(body).digest());
  const cookieName = SESSION_COOKIE_PREFIX + base64Url(createHash('sha256').update(authority).digest());
  return { name: cookieName, value: `v1.${body}.${signature}` };
}

/**
 * 校验一条宿主会话 cookie 的值，只关心签名与有效期，不关心它签给哪个 authority。
 * 用途：插件挂在宿主上的路由（状态、配置）要知道「这个请求是不是已经登录过」。
 * 伪造需要宿主会话密钥，所以验签通过即等价于「登录态」。
 */
function verifySessionCookieValue(value, secret) {
  if (typeof value !== 'string') return false;
  const parts = value.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return false;
  const body = parts[1];
  const expected = base64Url(createHmac('sha256', secret).update(body).digest());
  if (!equalSecret(parts[2], expected)) return false;
  let payload;
  try {
    const padded = body.replace(/-/g, '+').replace(/_/g, '/');
    payload = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  } catch {
    return false;
  }
  if (!payload || typeof payload !== 'object') return false;
  const now = Date.now();
  if (!Number.isFinite(payload.expiresAt) || payload.expiresAt <= now) return false;
  if (Number.isFinite(payload.issuedAt) && payload.issuedAt > now) return false;
  return true;
}

/** 请求里是否带了一条有效的宿主会话 cookie（登录态）。 */
function hasSessionCookie(header, secret) {
  if (typeof header !== 'string') return false;
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const index = trimmed.indexOf('=');
    if (index <= 0) continue;
    if (!trimmed.slice(0, index).startsWith(SESSION_COOKIE_PREFIX)) continue;
    if (verifySessionCookieValue(trimmed.slice(index + 1), secret)) return true;
  }
  return false;
}

/** 网关自身的登录 cookie：<到期毫秒>.<HMAC>，密钥由会话密钥派生。 */
function gatewayKey(secret) {
  return createHmac('sha256', secret).update('dsh-reverse-proxy-gateway/cookie/v1').digest();
}

/**
 * 读取运行期覆盖（界面保存的配置）。
 * 文件不存在、内容坏掉、不是对象，一律当空覆盖 —— 配置文件才是启动基线。
 */
function readOverrides(file) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    return {};
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {};
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  const picked = {};
  for (const key of CONFIG_KEYS) {
    if (parsed[key] !== undefined && parsed[key] !== null) picked[key] = parsed[key];
  }
  return picked;
}

/** 写入覆盖文件：先写临时文件再改名，避免半截文件被读到；权限压到 600。 */
function writeOverrides(file, values) {
  const payload = `${JSON.stringify(values, null, 2)}\n`;
  const temporary = `${file}.tmp-${process.pid}`;
  writeFileSync(temporary, payload, { encoding: 'utf8', mode: 0o600 });
  renameSync(temporary, file);
}

function signGatewayCookie(key, days) {
  const expiresAt = Date.now() + days * DAY_MS;
  const signature = base64Url(createHmac('sha256', key).update(String(expiresAt)).digest());
  return `${expiresAt}.${signature}`;
}

function verifyGatewayCookie(raw, key) {
  if (typeof raw !== 'string') return false;
  const index = raw.indexOf('.');
  if (index <= 0) return false;
  const expiresAt = raw.slice(0, index);
  const signature = raw.slice(index + 1);
  const numeric = Number(expiresAt);
  if (!Number.isFinite(numeric) || numeric <= Date.now()) return false;
  const expected = base64Url(createHmac('sha256', key).update(expiresAt).digest());
  return equalSecret(signature, expected);
}

/** 从 Cookie 头里取某个名字的值。 */
function readCookie(header, wanted) {
  if (typeof header !== 'string') return null;
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    const index = trimmed.indexOf('=');
    if (index <= 0) continue;
    if (trimmed.slice(0, index) === wanted) return trimmed.slice(index + 1);
  }
  return null;
}

/** 解析 Basic Auth 头，格式非法一律返回 null。 */
function parseBasicAuth(header) {
  if (typeof header !== 'string') return null;
  const matched = /^Basic\s+(.+)$/i.exec(header.trim());
  if (!matched) return null;
  let decoded;
  try {
    decoded = Buffer.from(matched[1], 'base64').toString('utf8');
  } catch {
    return null;
  }
  const index = decoded.indexOf(':');
  if (index < 0) return null;
  return { user: decoded.slice(0, index), pass: decoded.slice(index + 1) };
}

/** 判断一个 TCP 对端地址是否属于本机回环（兼容 IPv4、IPv6 与 IPv4-mapped 写法）。 */
function isLoopbackPeer(address) {
  if (typeof address !== 'string') return false;
  const value = address.trim().toLowerCase();
  if (value === '::1' || value === '127.0.0.1') return true;
  if (value.startsWith('127.')) return true;
  if (value.startsWith('::ffff:127.')) return true;
  return false;
}

/**
 * 这次请求是不是来自非本机。
 * 网关转发时会带上 PEER_HEADER，宿主直接看到的是网关自己（回环），
 * 所以要先认这个头；没有头时按 TCP 对端地址判断（本机客户端直接访问宿主的情况）。
 */
function isRemotePeerRequest(req) {
  if (!req) return false;
  if (req.headers && req.headers[PEER_HEADER] === 'remote') return true;
  const address = req.socket && req.socket.remoteAddress;
  if (!address) return false;
  return !isLoopbackPeer(address);
}

/**
 * 远程选择器脚本的源码。
 * 只在第一次请求时读盘，之后复用；文件随包发布，路径相对本模块。
 */
let pickerSourceCache = null;
let pickerSourceStamp = 0;
let pickerVersionCache = '';
function pickerSource() {
  // 按 mtime 失效：改完脚本刷新页面就是新版，不用重启或重载插件。
  const file = new URL('./client/picker.js', import.meta.url);
  const stamp = statSync(file).mtimeMs;
  if (pickerSourceCache === null || stamp !== pickerSourceStamp) {
    pickerSourceCache = readFileSync(file, 'utf8');
    pickerSourceStamp = stamp;
    pickerVersionCache = '';
  }
  return pickerSourceCache;
}

/**
 * 脚本内容的短指纹，拼进 URL 当版本号。
 * 光靠 cache-control 不够：手机浏览器与外层反向代理都可能留着旧副本，
 * 而 URL 一变它们就必然重新取。
 */
function pickerVersion() {
  if (!pickerVersionCache) {
    pickerVersionCache = createHash('sha1').update(pickerSource()).digest('hex').slice(0, 10);
  }
  return pickerVersionCache;
}

/* ------------------------------------------------------------------ *
 * 插件主体
 * ------------------------------------------------------------------ */

export function apply(ctx, config = {}) {
  try {
    const settings = {
      enabled: config.enabled !== false,
      listen: typeof config.listen === 'string' && config.listen.trim() ? config.listen.trim() : '0.0.0.0',
      port: Number(config.port) >= 1024 && Number(config.port) <= 65535 ? Math.trunc(Number(config.port)) : 3080,
      publicUrl: typeof config.publicUrl === 'string' ? config.publicUrl : '',
      username: typeof config.username === 'string' ? config.username : 'dsh',
      password: typeof config.password === 'string' ? config.password : '',
      accessToken: typeof config.accessToken === 'string' ? config.accessToken : '',
      cookieDays: Number(config.cookieDays) >= 1 ? Math.trunc(Number(config.cookieDays)) : 30,
      switchMode:
        config.switchMode === 'always' || config.switchMode === 'never' || config.switchMode === 'local'
          ? config.switchMode
          : 'local',
      confirmToggle: config.confirmToggle !== false,
      remotePicker: config.remotePicker !== false,
      browseRoot: typeof config.browseRoot === 'string' ? config.browseRoot.trim() : '',
    };

    // 界面保存的覆盖值优先于 cordis patch；patch 只当启动基线。
    const overrideFile = join(dshHome(), OVERRIDE_FILE);
    const overrides = readOverrides(overrideFile);
    for (const key of CONFIG_KEYS) {
      if (overrides[key] !== undefined) settings[key] = overrides[key];
    }

    if (typeof ctx.inject !== 'function') {
      log(ctx, 'warn', '宿主没有 ctx.inject，网关未启动');
      return;
    }

    // 会话密钥与派生 key 惰性初始化：宿主的 credentials 文件可能还没写入。
    let cachedSecret = null;
    let cachedKey = null;
    const sessionSecret = () => {
      if (cachedSecret) return cachedSecret;
      cachedSecret = readSessionSecret();
      return cachedSecret;
    };
    const cookieKey = () => {
      if (cachedKey) return cachedKey;
      cachedKey = gatewayKey(sessionSecret());
      return cachedKey;
    };

    ctx.inject(['webServer'], (scoped) => {
      let server = null;
      let boundPort = null;
      let disposed = false;
      let starting = false;
      const routeDisposers = [];

      /** 宿主真实端口，每次连接时惰性读取，重启后自动跟上新的随机端口。 */
      const upstreamPort = () => {
        const webServer = scoped && scoped.webServer;
        const listened = Number(webServer && webServer.listenedPort);
        if (Number.isInteger(listened) && listened > 0) return listened;
        try {
          const address = webServer && webServer.server && webServer.server.address && webServer.server.address();
          if (address && typeof address === 'object' && Number(address.port) > 0) return Number(address.port);
        } catch {}
        const configured = Number(webServer && webServer.config && webServer.config.port);
        return Number.isInteger(configured) && configured > 0 ? configured : null;
      };

      /**
       * 这次请求是不是来自本机之外的浏览器。
       * 本机继续用系统对话框，行为完全不变；只有远程才需要接管。
       */
      const isRemoteViewer = (headers, peerAddress) => {
        if (!settings.remotePicker) return false;
        if (typeof peerAddress === 'string' && peerAddress && !isLoopbackPeer(peerAddress)) return true;
        // 前面若还叠了一层反代，对端是回环，只能看转发头。
        const forwarded = headers && headers['x-forwarded-for'];
        if (typeof forwarded === 'string') {
          const first = forwarded.split(',')[0].trim();
          if (first && !isLoopbackPeer(first)) return true;
        }
        return false;
      };

      /**
       * 要不要顺手把 accept-encoding 摘掉，让宿主直接给明文 HTML。
       * 这不是注入的必要条件（响应侧会解压），只是省掉一次压缩再解压。
       */
      const wantsHtmlInjection = (headers, peerAddress) => {
        if (!isRemoteViewer(headers, peerAddress)) return false;
        const accept = String((headers && headers.accept) || '');
        return accept.includes('text/html');
      };

      /** 按压缩算法解出明文；解不开返回 null，调用方原样回退。 */
      const decodeBody = (buffer, encoding) => {
        const kind = String(encoding || '').trim().toLowerCase();
        try {
          if (!kind || kind === 'identity') return buffer;
          if (kind === 'gzip' || kind === 'x-gzip') return gunzipSync(buffer);
          if (kind === 'deflate') return inflateSync(buffer);
          if (kind === 'br') return brotliDecompressSync(buffer);
        } catch {
          return null;
        }
        return null;
      };

      /** 把脚本标签插到 </head> 之前；页面没有 head 就退到最前面。 */
      const injectPickerTag = (html) => {
        if (html.includes(PICKER_SCRIPT_PATH)) return html;
        const tag = `<script src="${PICKER_SCRIPT_PATH}?v=${pickerVersion()}"></script>`;
        const close = html.search(/<\/head\s*>/i);
        if (close !== -1) return html.slice(0, close) + tag + html.slice(close);
        const open = /<head[^>]*>/i.exec(html);
        if (open) {
          const at = open.index + open[0].length;
          return html.slice(0, at) + tag + html.slice(at);
        }
        return tag + html;
      };

      /** 把浏览器请求头改造成「本机已认证请求」。 */
      const proxyHeaders = (incoming, host, peerAddress) => {
        const headers = { ...incoming };
        // 去掉一切会让宿主判定为跨站/非同源的头，认证已由网关完成。
        delete headers.origin;
        delete headers.referer;
        delete headers['sec-fetch-site'];
        delete headers['sec-fetch-mode'];
        delete headers['sec-fetch-dest'];
        delete headers['sec-fetch-user'];
        // 文档请求禁掉压缩：网关要往 HTML 里插一段脚本，压缩后就地替换不了。
        if (wantsHtmlInjection(incoming, peerAddress)) delete headers['accept-encoding'];
        // 客户端自己带的同名头一律丢弃，只认网关观察到的真实对端地址。
        delete headers[PEER_HEADER];
        if (peerAddress && !isLoopbackPeer(peerAddress)) headers[PEER_HEADER] = 'remote';
        headers.host = host;
        // 丢掉浏览器里所有宿主会话 cookie（authority 可能已过期），只放本插件现签的那一条。
        const kept = [];
        if (typeof incoming.cookie === 'string') {
          for (const part of incoming.cookie.split(';')) {
            const trimmed = part.trim();
            if (!trimmed) continue;
            if (trimmed.startsWith(SESSION_COOKIE_PREFIX) || trimmed.startsWith(GATEWAY_COOKIE + '=')) continue;
            kept.push(trimmed);
          }
        }
        try {
          const secret = sessionSecret();
          const issuedAt = Date.now();
          // 宿主会拒绝寿命超过它自己 cookieMaxAgeDays 的 cookie（桌面默认 30 天），
          // 所以这里固定按 30 天签，与 Host 侧配置解耦；浏览器里存的是网关自己的 cookie，
          // 它的寿命才由 cookieDays 决定。
          const signed = signSessionCookie(secret, host, issuedAt, HOST_COOKIE_DAYS);
          kept.push(`${signed.name}=${signed.value}`);
        } catch (error) {
          log(ctx, 'error', '签发宿主会话 cookie 失败：' + ((error && error.message) || error));
        }
        headers.cookie = kept.join('; ');
        return headers;
      };

      /** 认证通过后统一走这里。 */
      const forward = (req, res) => {
        const port = upstreamPort();
        if (port === null) {
          res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('DSH 尚未开始监听，请稍后重试');
          return;
        }
        const host = `127.0.0.1:${port}`;
        let headers;
        try {
          headers = proxyHeaders(req.headers, host, req.socket && req.socket.remoteAddress);
        } catch (error) {
          res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('网关无法读取宿主会话密钥：' + ((error && error.message) || error));
          return;
        }
        const upstream = httpRequest(
          { host: '127.0.0.1', port, method: req.method, path: req.url, headers },
          (proxied) => {
            let outHeaders;
            try {
              // 宿主下发的 set-cookie 是签给 127.0.0.1:<port> 的，落到公网浏览器里毫无用处，
              // 只会在 Cookie 存储里越堆越多，这里统一剔掉。
              outHeaders = { ...proxied.headers };
              delete outHeaders['set-cookie'];
            } catch {
              res.destroy();
              return;
            }
            const type = String(outHeaders['content-type'] || '');
            const encoding = String(outHeaders['content-encoding'] || '');
            const status = proxied.statusCode || 502;
            // 只看响应是不是 HTML，不看请求头：有的浏览器或中间代理不发 Accept。
            // 无正文的响应（HEAD、204、304）不注入，否则会凭空造出正文和错误的 content-length。
            const injectable =
              req.method !== 'HEAD' &&
              status !== 204 &&
              status !== 304 &&
              isRemoteViewer(req.headers, req.socket && req.socket.remoteAddress) &&
              type.includes('text/html');
            if (!injectable) {
              try {
                res.writeHead(status, outHeaders);
              } catch {
                res.destroy();
                return;
              }
              proxied.pipe(res);
              return;
            }
            // 注入要改写正文，只能先整段收下再发；入口 HTML 很小，不会拖慢首屏。
            const chunks = [];
            proxied.on('data', (chunk) => chunks.push(chunk));
            proxied.on('error', () => res.destroy());
            proxied.on('end', () => {
              try {
                const raw = Buffer.concat(chunks);
                // 宿主多半压过；解不开就原样吐回去，不让页面挂掉。
                const body = decodeBody(raw, encoding);
                if (body === null) {
                  delete outHeaders['transfer-encoding'];
                  outHeaders['content-length'] = String(raw.length);
                  res.writeHead(status, outHeaders);
                  res.end(raw);
                  return;
                }
                const payload = Buffer.from(injectPickerTag(body.toString('utf8')), 'utf8');
                delete outHeaders['content-encoding'];
                delete outHeaders['transfer-encoding'];
                outHeaders['content-length'] = String(payload.length);
                res.writeHead(status, outHeaders);
                res.end(payload);
              } catch {
                res.destroy();
              }
            });
          },
        );
        upstream.on('error', (error) => {
          log(ctx, 'warn', '转发失败：' + ((error && error.message) || error));
          if (!res.headersSent) {
            res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
            res.end('上游不可达');
          } else {
            res.destroy();
          }
        });
        // 客户端提前断开时别让上游请求悬着。
        req.on('aborted', () => upstream.destroy());
        res.on('close', () => upstream.destroy());
        req.pipe(upstream);
      };

      /** upgrade（WebSocket）单独处理：http 层改不了头，只能手工拼首包。 */
      const forwardUpgrade = (req, socket, head) => {
        socket.on('error', () => {});
        const port = upstreamPort();
        if (port === null) {
          socket.destroy();
          return;
        }
        const host = `127.0.0.1:${port}`;
        let headers;
        try {
          headers = proxyHeaders(req.headers, host, req.socket && req.socket.remoteAddress);
        } catch (error) {
          log(ctx, 'error', 'upgrade 签发 cookie 失败：' + ((error && error.message) || error));
          socket.destroy();
          return;
        }
        const upstream = netConnect(port, '127.0.0.1', () => {
          const lines = [`${req.method} ${req.url} HTTP/1.1`];
          for (const [key, value] of Object.entries(headers)) {
            if (value === undefined) continue;
            if (Array.isArray(value)) {
              for (const item of value) lines.push(`${key}: ${item}`);
            } else {
              lines.push(`${key}: ${value}`);
            }
          }
          upstream.write(lines.join('\r\n') + '\r\n\r\n');
          if (head && head.length > 0) upstream.write(head);
          upstream.pipe(socket);
          socket.pipe(upstream);
        });
        upstream.on('error', (error) => {
          log(ctx, 'warn', 'upgrade 上游失败：' + ((error && error.message) || error));
          socket.destroy();
        });
        socket.on('close', () => upstream.destroy());
        upstream.on('close', () => socket.destroy());
      };

      const stateBody = () => {
        const port = upstreamPort();
        const host = port === null ? null : `127.0.0.1:${port}`;
        let secretReady = false;
        try {
          sessionSecret();
          secretReady = true;
        } catch {}
        const base = settings.publicUrl || '';
        return {
          ok: true,
          enabled: settings.enabled !== false,
          listening: boundPort !== null,
          listen: settings.listen,
          port: boundPort === null ? settings.port : boundPort,
          upstreamPort: port,
          publicUrl: base,
          loginUrl: base && settings.accessToken ? `${base.replace(/\/?$/, '/').replace(/\/+$/, '/')}?token=${encodeURIComponent(settings.accessToken)}` : null,
          username: settings.username || null,
          basicAuth: Boolean(settings.password),
          tokenLogin: Boolean(settings.accessToken),
          cookieDays: settings.cookieDays,
          remotePicker: settings.remotePicker !== false,
          browseRoot: settings.browseRoot || '',
          sessionCookie: secretReady ? { lifetimeDays: HOST_COOKIE_DAYS } : null,
        };
      };

      const sendJson = (res, status, body) => {
        try {
          const payload = JSON.stringify(body);
          res.writeHead(status, {
            'content-type': 'application/json; charset=utf-8',
            'content-length': Buffer.byteLength(payload),
            'cache-control': 'no-store',
          });
          res.end(payload);
        } catch {
          try {
            res.destroy();
          } catch {}
        }
      };

      /* ---------------- 远程目录浏览 ---------------- */

      /**
       * 浏览根：显式配置优先，否则用当前用户主目录。
       * 远程只能在这个根之内上下移动，根之外一律拒绝。
       */
      const browseRootPath = () => {
        const configured = settings.browseRoot;
        return configured ? resolve(configured) : homedir();
      };

      /**
       * 判断 target 是否落在 root 之内（含 root 本身）。
       * 不用字符串前缀比较：root 是 `/` 时拼出来的 `//` 会漏判，
       * 而 `relative` 对根、盘符和跨盘都给出正确结果。
       */
      const isInside = (root, target) => {
        if (target === root) return true;
        const rel = relative(root, target);
        return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
      };

      /** 把请求里的路径收敛到根内；越界、不存在、非目录都抛错。 */
      const resolveInsideRoot = async (raw) => {
        let root;
        try {
          root = await realpath(browseRootPath());
        } catch {
          throw new Error('浏览根目录不存在：' + browseRootPath());
        }
        const wanted = typeof raw === 'string' && raw.trim() ? resolve(raw.trim()) : root;
        let real;
        try {
          real = await realpath(wanted);
        } catch {
          throw new Error('目录不存在：' + wanted);
        }
        // realpath 之后再比一次，符号链接也逃不出去。
        if (!isInside(root, real)) throw new Error('路径超出浏览范围');
        return { root, real };
      };

      /** 列一层目录，只返回子目录，不返回文件。 */
      const listDirectory = async (raw) => {
        const { root, real } = await resolveInsideRoot(raw);
        let dirents;
        try {
          dirents = await readdir(real, { withFileTypes: true });
        } catch (error) {
          throw new Error('无法读取目录：' + ((error && error.message) || error));
        }
        const entries = [];
        let truncated = false;
        for (const dirent of dirents) {
          if (entries.length >= FS_MAX_ENTRIES) {
            truncated = true;
            break;
          }
          if (!dirent.isDirectory() && !dirent.isSymbolicLink()) continue;
          const full = join(real, dirent.name);
          if (dirent.isSymbolicLink()) {
            // 跟着解析一次，确认最终仍落在根内且确实是个目录。
            try {
              const target = await realpath(full);
              if (!isInside(root, target)) continue;
              if (!(await stat(target)).isDirectory()) continue;
            } catch {
              continue;
            }
          }
          entries.push({ name: dirent.name, path: full });
        }
        entries.sort((a, b) => a.name.localeCompare(b.name, 'zh-Hans-CN'));
        return {
          path: real,
          root,
          parent: real === root ? null : dirname(real),
          entries,
          truncated,
        };
      };

      /** 在指定父目录下建一个子目录，父目录必须在根内。 */
      const createDirectory = async (parentRaw, nameRaw) => {
        const name = typeof nameRaw === 'string' ? nameRaw.trim() : '';
        if (!name) throw new Error('目录名不能为空');
        if (name === '.' || name === '..') throw new Error('目录名非法');
        if (/[\\/\0]/.test(name)) throw new Error('目录名不能含路径分隔符');
        if (name.length > 128) throw new Error('目录名过长');
        const { real } = await resolveInsideRoot(parentRaw);
        const target = join(real, name);
        try {
          await mkdir(target);
        } catch (error) {
          if (error && error.code === 'EEXIST') throw new Error('同名目录已存在');
          if (error && error.code === 'ENOENT') throw new Error('父目录不存在');
          throw new Error('创建失败：' + ((error && error.message) || error));
        }
        return target;
      };

      const handleFs = async (req, res, pathname, search) => {
        try {
          if (pathname === FS_LIST_PATH) {
            if (req.method !== 'GET' && req.method !== 'HEAD') {
              sendJson(res, 405, { ok: false, error: 'method-not-allowed', message: '只接受 GET' });
              return;
            }
            const listing = await listDirectory(search.get('path'));
            sendJson(res, 200, { ok: true, ...listing });
            return;
          }
          if (pathname === FS_MKDIR_PATH) {
            if (req.method !== 'POST') {
              sendJson(res, 405, { ok: false, error: 'method-not-allowed', message: '只接受 POST' });
              return;
            }
            readJsonBody(req, res, (payload) => {
              createDirectory(payload.path, payload.name).then(
                (created) => sendJson(res, 200, { ok: true, path: created }),
                (error) => sendJson(res, 400, { ok: false, error: 'mkdir-failed', message: (error && error.message) || String(error) }),
              );
            });
            return;
          }
          sendJson(res, 404, { ok: false, error: 'not-found', message: '未知接口' });
        } catch (error) {
          sendJson(res, 400, { ok: false, error: 'fs-failed', message: (error && error.message) || String(error) });
        }
      };

      /** 选择器脚本：认证通过后才下发。 */
      const handlePickerScript = (res) => {
        let source;
        try {
          source = pickerSource();
        } catch (error) {
          log(ctx, 'warn', `读取选择器脚本失败：${(error && error.message) || String(error)}`);
          res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('picker script unavailable');
          return;
        }
        const payload = Buffer.from(source, 'utf8');
        res.writeHead(200, {
          'content-type': 'application/javascript; charset=utf-8',
          'content-length': payload.length,
          // 带版本号的 URL 已经是新的，这里再说明一次别留副本：
          // 手机浏览器和外层反向代理都曾把旧脚本留在缓存里。
          'cache-control': 'no-store, no-cache, must-revalidate',
          pragma: 'no-cache',
          etag: `"${pickerVersion()}"`,
        });
        res.end(payload);
      };

      /**
       * 状态路由也要认证：它暴露端口和固定登录链接。
       * 三个入口都认：网关 cookie（经网关进来）、Basic Auth（本机 curl 最顺手）、
       * 宿主会话 cookie（本机从 DSH 界面直接打开宿主端口）。
       */
      const handleState = (req, res) => {
        const auth = authenticate(req);
        if (auth.ok || basicAuthOk(req) || configAuthorized(req)) {
          sendJson(res, 200, stateBody());
          return;
        }
        res.writeHead(auth.status, auth.headers);
        res.end(auth.body);
      };

      /** 读请求体，超过上限直接拒，返回 null 表示已回错误。 */
      const readJsonBody = (req, res, callback) => {
        const chunks = [];
        let size = 0;
        let done = false;
        req.on('data', (chunk) => {
          if (done) return;
          size += chunk.length;
          if (size > MAX_CONFIG_BYTES) {
            done = true;
            sendJson(res, 413, { ok: false, error: 'body-too-large', message: '请求体过大' });
            req.destroy();
            return;
          }
          chunks.push(chunk);
        });
        req.on('error', () => {
          if (done) return;
          done = true;
          sendJson(res, 400, { ok: false, error: 'body-read-failed', message: '读取请求体失败' });
        });
        req.on('end', () => {
          if (done) return;
          done = true;
          const raw = Buffer.concat(chunks).toString('utf8').trim();
          if (!raw) {
            callback({});
            return;
          }
          let parsed;
          try {
            parsed = JSON.parse(raw);
          } catch {
            sendJson(res, 400, { ok: false, error: 'bad-json', message: '请求体不是合法 JSON' });
            return;
          }
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            sendJson(res, 400, { ok: false, error: 'bad-json', message: '请求体必须是 JSON 对象' });
            return;
          }
          callback(parsed);
        });
      };

      /**
       * 单个字段的校验与规范化。返回 {value} 或 {error,message}。
       * 校验规则与 Config schema 保持一致，避免界面写进配置文件里跑不起来。
       */
      const normalizeField = (key, raw) => {
        if (key === 'enabled') {
          if (typeof raw !== 'boolean') return { error: 'bad-enabled', message: 'enabled 必须是布尔值' };
          return { value: raw };
        }
        if (key === 'username') {
          const value = typeof raw === 'string' ? raw.trim() : '';
          if (value.length < 1 || value.length > 64) return { error: 'bad-username', message: '用户名长度需在 1–64 之间' };
          if (/[:\s]/.test(value)) return { error: 'bad-username', message: '用户名不能含冒号或空白' };
          return { value };
        }
        if (key === 'password') {
          if (typeof raw !== 'string') return { error: 'bad-password', message: '密码必须是字符串' };
          // 空串表示关掉 Basic Auth，这是允许的；非空则至少 8 位。
          if (raw.length > 0 && raw.length < 8) return { error: 'bad-password', message: '密码至少 8 位（留空表示关闭密码登录）' };
          if (raw.length > 128) return { error: 'bad-password', message: '密码过长' };
          return { value: raw };
        }
        if (key === 'accessToken') {
          if (typeof raw !== 'string') return { error: 'bad-token', message: '固定 token 必须是字符串' };
          const value = raw.trim();
          if (value.length > 0 && value.length < 16) return { error: 'bad-token', message: '固定 token 至少 16 位（留空表示不开启）' };
          if (value.length > 128) return { error: 'bad-token', message: '固定 token 过长' };
          if (/[^A-Za-z0-9_\-]/.test(value)) return { error: 'bad-token', message: '固定 token 只能含字母、数字、下划线和短横线' };
          return { value };
        }
        if (key === 'publicUrl') {
          if (typeof raw !== 'string') return { error: 'bad-url', message: '对外地址必须是字符串' };
          const value = raw.trim();
          if (!value) return { value: '' };
          if (!/^https?:\/\/[^\s]+$/i.test(value)) return { error: 'bad-url', message: '对外地址必须以 http:// 或 https:// 开头' };
          return { value };
        }
        if (key === 'cookieDays') {
          const value = Math.trunc(Number(raw));
          if (!Number.isFinite(value) || value < 1 || value > 3650) return { error: 'bad-cookie-days', message: '登录保持天数需在 1–3650 之间' };
          return { value };
        }
        if (key === 'switchMode') {
          if (raw !== 'local' && raw !== 'always' && raw !== 'never') {
            return { error: 'bad-switch-mode', message: '开关显示范围只能是 local、always 或 never' };
          }
          return { value: raw };
        }
        if (key === 'confirmToggle') {
          if (typeof raw !== 'boolean') return { error: 'bad-confirm-toggle', message: '二次确认必须是布尔值' };
          return { value: raw };
        }
        if (key === 'remotePicker') {
          if (typeof raw !== 'boolean') return { error: 'bad-remote-picker', message: '远程目录浏览开关必须是布尔值' };
          return { value: raw };
        }
        if (key === 'browseRoot') {
          if (typeof raw !== 'string') return { error: 'bad-browse-root', message: '浏览根必须是字符串' };
          const value = raw.trim();
          if (!value) return { value: '' };
          if (value.length > 4096) return { error: 'bad-browse-root', message: '浏览根路径过长' };
          if (!value.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(value)) {
            return { error: 'bad-browse-root', message: '浏览根必须是绝对路径' };
          }
          return { value };
        }
        if (key === 'port') {
          const value = Math.trunc(Number(raw));
          if (!Number.isFinite(value) || value < 1024 || value > 65535) return { error: 'invalid-port', message: '端口需在 1024–65535 之间' };
          return { value };
        }
        if (key === 'listen') {
          if (typeof raw !== 'string') return { error: 'bad-listen', message: '监听地址必须是字符串' };
          const value = raw.trim();
          if (!value) return { error: 'bad-listen', message: '监听地址不能为空' };
          if (value === '0.0.0.0' || value === '::' || value === 'localhost') return { value };
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return { value };
          return { error: 'bad-listen', message: '监听地址只能是 IP、0.0.0.0 或 localhost' };
        }
        return { error: 'unknown-field', message: '未知字段：' + key };
      };

      /** 界面卡片用的配置视图：密码不回显，只报是否存在。 */
      const configBody = (req) => ({
        ok: true,
        /** 这次请求是不是从本机发起，界面用它决定开关显不显示。 */
        local: !isRemotePeerRequest(req),
        settings: {
          enabled: settings.enabled !== false,
          username: settings.username,
          hasPassword: Boolean(settings.password),
          accessToken: settings.accessToken,
          publicUrl: settings.publicUrl,
          cookieDays: settings.cookieDays,
          port: settings.port,
          listen: settings.listen,
          switchMode: settings.switchMode === 'always' || settings.switchMode === 'never' ? settings.switchMode : 'local',
          confirmToggle: settings.confirmToggle !== false,
          remotePicker: settings.remotePicker !== false,
          browseRoot: settings.browseRoot || '',
        },
        runtime: {
          listening: boundPort !== null,
          boundPort: boundPort,
          upstreamPort: upstreamPort(),
          loginUrl: stateBody().loginUrl,
          basicAuth: Boolean(settings.password),
          tokenLogin: Boolean(settings.accessToken),
        },
        restartKeys: RESTART_KEYS,
      });

      /**
       * 配置读写：GET 读当前值，POST 保存到覆盖文件并热应用。
       * 只挂在宿主 webServer 上（回环），并通过宿主自身的连接认证；
       * 额外要求来源是本机回环或带对的 Basic Auth，避免被同源页面之外的途径改动。
       */
      /**
       * 挂在宿主 webServer 上的路由不会被宿主的浏览器认证拦住，所以必须自己验。
       * 三种凭据任一成立即通过：
       *   1) 宿主会话 cookie —— 本机从 DSH 界面进来的请求带着它；经网关进来的请求到达
       *      宿主时带的是网关即时签好的同款 cookie，同样命中。
       *   2) 网关 cookie —— 直接打网关端口的同源页面请求。
       *   3) Basic Auth —— 本机 curl 调试用。
       * 不能用 remoteAddress 判断：本机任何进程都是回环，网关转发到宿主时也同样是回环。
       */
      const configAuthorized = (req) => {
        if (settings.password && basicAuthOk(req)) return true;
        try {
          return hasSessionCookie(req.headers.cookie, sessionSecret());
        } catch (error) {
          log(ctx, 'warn', '校验会话 cookie 失败：' + ((error && error.message) || error));
          return false;
        }
      };

      const handleConfig = (req, res) => {
        if (!configAuthorized(req)) {
          sendJson(res, 401, {
            ok: false,
            error: 'unauthorized',
            message: '需要已登录的 DSH 界面会话，或提供 Basic Auth 凭据',
          });
          return;
        }

        const method = (req.method || 'GET').toUpperCase();
        if (method === 'GET') {
          sendJson(res, 200, configBody(req));
          return;
        }
        if (method !== 'POST') {
          sendJson(res, 405, { ok: false, error: 'method-not-allowed', message: '只支持 GET 与 POST' });
          return;
        }
        // 只收 JSON：挡掉跨站页面用 text/plain 绕开 CORS 预检的写法。
        const contentType = String(req.headers['content-type'] || '').toLowerCase();
        if (!contentType.startsWith('application/json')) {
          sendJson(res, 415, {
            ok: false,
            error: 'unsupported-media-type',
            message: '请求体必须是 application/json',
          });
          return;
        }

        readJsonBody(req, res, (input) => {
          const patch = {};
          for (const key of Object.keys(input)) {
            if (!CONFIG_KEYS.includes(key)) {
              sendJson(res, 400, { ok: false, error: 'unknown-field', message: '未知字段：' + key });
              return;
            }
            const result = normalizeField(key, input[key]);
            if (result.error) {
              sendJson(res, 400, { ok: false, error: result.error, message: result.message });
              return;
            }
            patch[key] = result.value;
          }
          if (Object.keys(patch).length === 0) {
            sendJson(res, 400, { ok: false, error: 'empty-patch', message: '没有需要保存的字段' });
            return;
          }

          // 至少要留一条登录方式，否则等于把网关敞开。
          const nextPassword = patch.password !== undefined ? patch.password : settings.password;
          const nextToken = patch.accessToken !== undefined ? patch.accessToken : settings.accessToken;
          if (!nextPassword && !nextToken) {
            sendJson(res, 400, {
              ok: false,
              error: 'no-credential',
              message: '密码与固定 token 不能同时为空，否则任何人都能进来',
            });
            return;
          }

          const merged = {};
          for (const key of CONFIG_KEYS) merged[key] = settings[key];
          Object.assign(merged, patch);

          try {
            writeOverrides(overrideFile, merged);
          } catch (error) {
            sendJson(res, 500, {
              ok: false,
              error: 'persist-failed',
              message: '写入 ' + overrideFile + ' 失败：' + ((error && error.message) || error),
            });
            return;
          }

          // 热应用：认证相关字段立刻生效；监听参数留给重启。
          for (const key of CONFIG_KEYS) settings[key] = merged[key];
          // 开关与凭据是热生效的：打开且有凭据就补启动，关闭或凭据清空就停掉监听。
          // 端口/监听地址改动不走这里——已监听时 startGateway 会因 server 非空直接返回，仍需重启。
          if (canListen()) startGateway();
          else stopGateway();
          const restartRequired = Object.keys(patch).some((key) => RESTART_KEYS.includes(key));
          log(ctx, 'info', '配置已更新：' + Object.keys(patch).join('、') + (restartRequired ? '（端口/监听地址需重启 DSH 生效）' : ''));
          if (restartRequired) {
            log(ctx, 'warn', '监听参数已写入，但当前仍监听 ' + settings.listen + ':' + (boundPort === null ? settings.port : boundPort) + '，重启 DSH 后生效');
          }
          sendJson(res, 200, {
            ok: true,
            restartRequired,
            saved: Object.keys(patch),
            config: configBody(req),
          });
        });
      };

      const mount = (routePath, handler) => {
        const webServer = scoped && scoped.webServer;
        if (!webServer || typeof webServer.register !== 'function') return null;
        const route = { kind: 'exact', path: routePath, handler };
        try {
          let remove = null;
          const factory = () => {
            remove = webServer.register(route);
            return remove;
          };
          if (typeof scoped.effect === 'function') scoped.effect(factory, 'reverse-proxy-gateway:' + routePath);
          else factory();
          return typeof remove === 'function' ? remove : null;
        } catch (error) {
          log(ctx, 'warn', '挂载 ' + routePath + ' 失败：' + ((error && error.message) || error));
          return null;
        }
      };

      const setGatewayCookie = (res) => {
        const value = signGatewayCookie(cookieKey(), settings.cookieDays);
        const maxAge = settings.cookieDays * 24 * 60 * 60;
        res.setHeader('set-cookie', `${GATEWAY_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax`);
      };

      /**
       * 认证入口。
       * 顺序：网关 cookie → 固定 token → Basic Auth。
       * 任何一条通过都视为已登录。
       */
      const authenticate = (req) => {
        let key;
        try {
          key = cookieKey();
        } catch (error) {
          return {
            ok: false,
            status: 500,
            headers: { 'content-type': 'text/plain; charset=utf-8' },
            body: '网关无法读取宿主会话密钥：' + ((error && error.message) || error),
          };
        }
        if (verifyGatewayCookie(readCookie(req.headers.cookie, GATEWAY_COOKIE), key)) return { ok: true };
        return {
          ok: false,
          status: 401,
          headers: {
            'content-type': 'text/plain; charset=utf-8',
            'www-authenticate': `Basic realm="DSH", charset="UTF-8"`,
          },
          body: '需要认证',
        };
      };

      /** Basic Auth 单独判定，供状态路由复用。 */
      const basicAuthOk = (req) => {
        if (!settings.password) return false;
        const credential = parseBasicAuth(req.headers.authorization);
        return Boolean(
          credential &&
            equalSecret(credential.user, settings.username) &&
            equalSecret(credential.pass, settings.password),
        );
      };

      /** 认证通过后的分流：网关自己的接口就地处理，其余转发给宿主。 */
      const authorized = (req, res, pathname, search) => {
        if (settings.remotePicker) {
          if (pathname === PICKER_SCRIPT_PATH) {
            handlePickerScript(res);
            return;
          }
          if (pathname === FS_LIST_PATH || pathname === FS_MKDIR_PATH) {
            void handleFs(req, res, pathname, search);
            return;
          }
        }
        forward(req, res);
      };

      const handler = (req, res) => {
        let pathname = '/';
        let search = null;
        try {
          const parsed = new URL(req.url || '/', 'http://placeholder');
          pathname = parsed.pathname;
          search = parsed.searchParams;
        } catch {
          res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('请求地址非法');
          return;
        }

        if (pathname === STATE_PATH) {
          handleState(req, res);
          return;
        }

        let key;
        try {
          key = cookieKey();
        } catch (error) {
          res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('网关无法读取宿主会话密钥：' + ((error && error.message) || error));
          return;
        }

        // 1) 已有网关 cookie：直通。
        if (verifyGatewayCookie(readCookie(req.headers.cookie, GATEWAY_COOKIE), key)) {
          authorized(req, res, pathname, search);
          return;
        }

        // 2) 固定 token 链接：种 cookie 后跳回根路径，避免 token 留在地址栏和日志里。
        if (settings.accessToken && search) {
          const supplied = search.get('token');
          if (supplied !== null && equalSecret(supplied, settings.accessToken)) {
            setGatewayCookie(res);
            res.writeHead(303, { location: '/', 'cache-control': 'no-store' });
            res.end();
            return;
          }
        }

        // 3) Basic Auth：校验通过后同样种 cookie，后续不再询问。
        if (basicAuthOk(req)) {
          setGatewayCookie(res);
          authorized(req, res, pathname, search);
          return;
        }

        res.writeHead(401, {
          'content-type': 'text/plain; charset=utf-8',
          'www-authenticate': `Basic realm="DSH", charset="UTF-8"`,
          'cache-control': 'no-store',
        });
        res.end('需要认证');
      };

      const dispose = () => {
        if (disposed) return;
        disposed = true;
        for (const remove of routeDisposers) {
          try {
            remove();
          } catch {}
        }
        routeDisposers.length = 0;
        stopGateway();
      };

      try {
        if (typeof scoped.effect === 'function') scoped.effect(() => dispose, 'reverse-proxy-gateway: dispose');
      } catch (error) {
        log(ctx, 'warn', '注册 dispose 失败：' + ((error && error.message) || error));
      }

      // 状态路由挂在宿主 webServer 上，凭登录态或 Basic Auth 读取，方便本地排查。
      try {
        const stateRemove = mount(STATE_PATH, handleState);
        if (stateRemove) routeDisposers.push(stateRemove);
      } catch (error) {
        log(ctx, 'warn', '注册状态路由失败：' + ((error && error.message) || error));
      }

      // 配置读写也挂在宿主上：浏览器页面无论从网关还是本机进入，都能用同源相对路径访问。
      try {
        const configRemove = mount(CONFIG_PATH, handleConfig);
        if (configRemove) routeDisposers.push(configRemove);
      } catch (error) {
        log(ctx, 'warn', '注册配置路由失败：' + ((error && error.message) || error));
      }

      const createGateway = () => {
        const candidate = createHttpServer(handler);
        // 大文件/长连接：不主动掐断，交给操作系统。
        candidate.keepAliveTimeout = 65_000;
        candidate.headersTimeout = 70_000;
        candidate.requestTimeout = 0;
        candidate.on('upgrade', forwardUpgrade);
        candidate.on('clientError', (error, socket) => {
          try {
            if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
            else socket.destroy();
          } catch {}
          void error;
        });
        return candidate;
      };

      const listenOn = (address, port) =>
        new Promise((resolve, reject) => {
          const candidate = createGateway();
          const fail = (error) => {
            candidate.removeListener('listening', ready);
            try {
              candidate.close();
            } catch {}
            reject(error);
          };
          const ready = () => {
            candidate.removeListener('error', fail);
            candidate.on('error', (error) => {
              log(ctx, 'warn', '网关监听出错：' + ((error && error.code) || (error && error.message) || error));
            });
            resolve(candidate);
          };
          candidate.once('error', fail);
          candidate.once('listening', ready);
          candidate.listen(port, address);
        });

      /** 有凭证且开关打开才监听；关掉开关只是不监听，配置路由照旧可用。 */
      const canListen = () => settings.enabled !== false && Boolean(settings.password || settings.accessToken);

      /** 停止监听：关开关或清空全部凭据时调用。 */
      const stopGateway = () => {
        const current = server;
        server = null;
        boundPort = null;
        if (!current) return;
        try {
          current.close();
        } catch {}
        log(ctx, 'info', `网关已停止监听 ${settings.listen}:${settings.port}`);
      };

      /** 启动监听：幂等，已在监听或条件不满足时直接返回。 */
      const startGateway = () => {
        if (disposed || starting || server !== null || !canListen()) return;
        starting = true;
        listenOn(settings.listen, settings.port)
          .then((candidate) => {
            starting = false;
            if (disposed || !canListen()) {
              try {
                candidate.close();
              } catch {}
              return;
            }
            server = candidate;
            boundPort = settings.port;
            const shown = settings.listen === '0.0.0.0' || settings.listen === '::' ? '所有网卡' : settings.listen;
            log(ctx, 'info', `已监听 ${shown}:${settings.port} -> 宿主 :${upstreamPort() || '?'}（对外地址 ${settings.publicUrl || '未设置'}）`);
          })
          .catch((error) => {
            starting = false;
            if (disposed) return;
            const code = error && error.code;
            if (code === 'EADDRINUSE') {
              log(ctx, 'error', `端口 ${settings.port} 已被占用，网关未启动`);
            } else if (code === 'EACCES') {
              log(ctx, 'error', `没有权限监听 ${settings.listen}:${settings.port}`);
            } else {
              log(ctx, 'error', `监听 ${settings.listen}:${settings.port} 失败：${code || (error && error.message) || error}`);
            }
          });
      };

      if (canListen()) {
        startGateway();
      } else if (settings.enabled === false) {
        log(ctx, 'info', '配置里已关闭，网关未监听（插件页仍可打开开关）');
      } else {
        // 没有密码也没有 token 就等于把整机裸奔出去，宁可不起。
        log(ctx, 'error', 'password 与 accessToken 都为空，网关未监听（请至少配置一项）');
      }

      return dispose;
    });
  } catch (error) {
    log(ctx, 'error', 'apply 失败：' + ((error && error.message) || error));
  }
}

/** 供文档/界面展示的默认端口。 */
export const defaultPort = 3080;
/** 生成一个可直接填进配置的随机 token。 */
export function generateToken(bytes = 24) {
  return base64Url(randomBytes(bytes));
}
