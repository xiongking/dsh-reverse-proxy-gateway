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
import { appendFileSync, existsSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { mkdir, readdir, realpath, rmdir, stat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { brotliDecompressSync, gunzipSync, inflateSync } from 'node:zlib';

export const name = 'reverse-proxy-gateway';

/** 宿主会话 cookie 的名字前缀，与 DSH 内置 connection 插件保持一致。 */
export const SESSION_COOKIE_PREFIX = 'dsh-auth-';
/** 本插件自己的网关 cookie 名。 */
const GATEWAY_COOKIE = 'dsh_gw';
/** 状态查询路由，走网关认证后才可读。 */
const STATE_PATH = '/coopanion/reverse-proxy-gateway/state';
/** 配置读写路由：给插件详情页的卡片用，浏览器走同源相对路径访问。 */
const CONFIG_PATH = '/coopanion/reverse-proxy-gateway/config';
/** 运行期覆盖文件（界面保存的改动），放在 ~/.dsh 下。 */
const OVERRIDE_FILE = '.dsh-reverse-proxy-gateway.json';
/** 会话世代文件：轮换它等于吊销全部网关 cookie。 */
const EPOCH_FILE = '.dsh-reverse-proxy-gateway.sessions.json';
/** 登录审计日志（JSONL）。 */
const AUDIT_FILE = '.dsh-reverse-proxy-gateway.audit.log';
/** 审计日志单文件上限，超过就轮转一份。 */
const AUDIT_MAX_BYTES = 5 * 1024 * 1024;
/** 审计日志保留的历史代数（.1 最新，依次向后）。 */
const AUDIT_GENERATIONS = 3;
/** 「退出所有登录」路由。 */
const LOGOUT_ALL_PATH = '/coopanion/reverse-proxy-gateway/logout-all';
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
/** 注入给宿主的会话 cookie 寿命上限：宿主默认 cookieMaxAgeDays=30。 */
const HOST_COOKIE_DAYS = 30;

/**
 * 读出宿主实际配置的 cookieMaxAgeDays。
 * 宿主的会话 cookie 校验里有一条「寿命超过 cookieMaxAgeDays 即作废」，
 * 所以这里签的寿命必须 ≤ 宿主的值，否则整页 401、而用户看到的只是「密码没用了」。
 * 优先读运行中的 BrowserAuth；读不到（版本变动、字段改名）就退回默认 30。
 */
function readHostCookieDays(ctx) {
  try {
    const connection = typeof ctx.get === 'function' ? ctx.get('connection') : undefined;
    const ms = connection && connection.browserAuth && connection.browserAuth.maxAgeMilliseconds;
    if (typeof ms === 'number' && Number.isFinite(ms) && ms >= DAY_MS) {
      return Math.max(1, Math.floor(ms / DAY_MS));
    }
  } catch {}
  return HOST_COOKIE_DAYS;
}

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

/**
 * 同一台机器上可能同时跑多个 profile（各自一个宿主进程），它们共用 ~/.dsh。
 * 会话世代若共用一份，一方「退出所有登录」会把另一方也踢下线；首次启动时
 * 两边还会互相覆盖。所以文件名带上 profile，各管各的。
 */
function profileSuffix() {
  const dir = profileDir();
  if (!dir) return '';
  const name = dir.replace(/[\\/]+$/, '').split(/[\\/]/).pop() || '';
  return name ? `.${name.replace(/[^A-Za-z0-9._-]/g, '_')}` : '';
}

/** `.dsh-reverse-proxy-gateway.audit.log` → `.dsh-reverse-proxy-gateway.audit.desktop.log`。 */
function stateFileFor(base) {
  const suffix = profileSuffix();
  if (suffix === '') return base;
  const dot = base.lastIndexOf('.');
  return `${base.slice(0, dot)}${suffix}${base.slice(dot)}`;
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
            '远程访问开关的显示范围：local 仅在本机（回环地址）访问时显示，always 始终显示，never 不显示'
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
          .description('远程目录浏览的上界：留空表示当前用户的主目录。打开时总是从家目录开始，往上退到这里为止'),
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

export function base64Url(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * 追加一行登录审计。
 *
 * 只记「发生了什么、从哪来」，不记凭据本身——审计日志被读到也不该泄漏密码。
 * 写失败一律吞掉：审计不能反过来阻断认证。
 * 单文件到上限就轮转一份，防止长期运行把磁盘写满。
 */
export function appendAudit(file, entry) {
  try {
    let size = 0;
    try {
      size = statSync(file).size;
    } catch {}
    if (size > AUDIT_MAX_BYTES) {
      // 只留一代的话，一次刷屏就能把上次发生的事挤掉，而事后最想看的恰恰是
      // 「出事之前那段时间」。依次后移，最老的一代自然被覆盖。
      try {
        rmSync(`${file}.${AUDIT_GENERATIONS}`, { force: true });
      } catch {}
      for (let index = AUDIT_GENERATIONS - 1; index >= 1; index -= 1) {
        try {
          renameSync(`${file}.${index}`, `${file}.${index + 1}`);
        } catch {}
      }
      renameSync(file, `${file}.1`);
    }
    const line = `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`;
    appendFileSync(file, line, { encoding: 'utf8', mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

/**
 * 定长比较，避免 Basic Auth 与 cookie 校验被计时侧信道试探。
 * 长度不同时也对两条定长摘要做一次比较，耗时与等长情形一致。
 */
export function equalSecret(left, right) {
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
export function readSessionSecret() {
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
export function signSessionCookie(secret, authority, issuedAt, lifetimeDays = 30) {
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
export function verifySessionCookieValue(value, secret) {
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
export function hasSessionCookie(header, secret) {
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

/** 网关自身的登录 cookie，密钥由会话密钥派生（见 cookieKeyFor）。 */
export function gatewayKey(secret) {
  return createHmac('sha256', secret).update('dsh-reverse-proxy-gateway/cookie/v1').digest();
}

/**
 * 读取运行期覆盖（界面保存的配置）。
 * 文件不存在、内容坏掉、不是对象，一律当空覆盖 —— 配置文件才是启动基线。
 */
export function readOverrides(file) {
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
export function writeOverrides(file, values) {
  const payload = `${JSON.stringify(values, null, 2)}\n`;
  const temporary = `${file}.tmp-${process.pid}`;
  writeFileSync(temporary, payload, { encoding: 'utf8', mode: 0o600 });
  renameSync(temporary, file);
}

/**
 * 凭据指纹：用户名、密码、免密 token 三项任一改动都会换一个值。
 * 把它混进 cookie 密钥，改凭据就自动让所有已签发的登录失效。
 */
export function credentialTag(username, password, accessToken) {
  return createHash('sha256')
    .update([username, password, accessToken].join('\u0000'))
    .digest('hex');
}

/**
 * 网关 cookie 的签名密钥：会话密钥 → 网关专名 key → 再混入凭据指纹与会话世代。
 * 分两层是为了不改 gatewayKey 的既有语义（它同时被宿主 cookie 相关代码复用）。
 */
export function cookieKeyFor(secret, tag) {
  return createHmac('sha256', gatewayKey(secret)).update(String(tag)).digest();
}

/**
 * 签发网关登录 cookie。
 * 载荷里带上签发时间与凭据指纹：签发时间用于排查，指纹让「换了凭据的旧 cookie」
 * 在验签阶段就被挡掉，不需要等到过期。
 */
export function signGatewayCookie(key, days, tag = '') {
  const now = Date.now();
  const payload = { exp: now + days * DAY_MS, iat: now, tag: String(tag) };
  const body = base64Url(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signature = base64Url(createHmac('sha256', key).update(body).digest());
  return `v2.${body}.${signature}`;
}

export function verifyGatewayCookie(raw, key, tag = '') {
  if (typeof raw !== 'string') return false;
  const parts = raw.split('.');
  if (parts.length !== 3 || parts[0] !== 'v2') return false;
  const body = parts[1];
  const expected = base64Url(createHmac('sha256', key).update(body).digest());
  if (!equalSecret(parts[2], expected)) return false;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  } catch {
    return false;
  }
  if (!payload || typeof payload !== 'object') return false;
  const now = Date.now();
  if (!Number.isFinite(payload.exp) || payload.exp <= now) return false;
  // 容忍一分钟时钟漂移，超过就当成伪造的未来签发。
  if (Number.isFinite(payload.iat) && payload.iat > now + 60_000) return false;
  if (!equalSecret(String(payload.tag ?? ''), String(tag))) return false;
  return true;
}

/**
 * 会话世代。轮换它等于吊销此前签发的全部网关 cookie。
 * 存独立文件而不是覆盖配置：那份文件的键受 CONFIG_KEYS 白名单约束，
 * 而且不该出现在界面表单里。
 */
export function readEpoch(file) {
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8'));
    if (parsed && typeof parsed.epoch === 'string' && parsed.epoch.length >= 16) return parsed.epoch;
  } catch {}
  return null;
}

export function writeEpoch(file, epoch) {
  const temporary = `${file}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify({ epoch })}\n`, { encoding: 'utf8', mode: 0o600 });
  renameSync(temporary, file);
}

/**
 * 认证失败限速。
 *
 * 按来源计数：窗口内失败到阈值就锁一段时间，成功一次即清零。
 * 键取两个维度——TCP 对端地址与 XFF 首段——任一超限即锁：
 * 只信 XFF 会被伪造绕过，只信对端则会在前面叠一层反代时把所有人算成同一个来源。
 * 两者都计数，谁先超限谁生效。
 *
 * 同一份凭据反复失败只算一次。浏览器把 Basic 凭据按「源 + realm」缓存，并在页面
 * 的每个子资源上自动重发；改过密码之后，一次页面加载就能凑满阈值把人锁住，而锁
 * 定时不回 WWW-Authenticate，浏览器也就不会弹框让人改密码，于是形成
 * 「解锁 → 刷新 → 再锁」的死循环。真正要挡的是换着密码猜，那才会产生新摘要。
 *
 * 表必须有上界：XFF 键可以凭空伪造，不设限就等于给了一个无界的内存放大器。
 */
export function createAttemptLimiter(options = {}) {
  const maxFails = Number.isFinite(options.maxFails) ? options.maxFails : 5;
  const windowMs = Number.isFinite(options.windowMs) ? options.windowMs : 300_000;
  const lockMs = Number.isFinite(options.lockMs) ? options.lockMs : 300_000;
  const maxKeys = Number.isFinite(options.maxKeys) ? options.maxKeys : 4096;
  const sweepEvery = Number.isFinite(options.sweepEvery) ? options.sweepEvery : 256;
  const dedupeMs = Number.isFinite(options.dedupeMs) ? options.dedupeMs : 5_000;
  const now = typeof options.now === 'function' ? options.now : Date.now;
  const records = new Map();
  let sinceSweep = 0;

  const alive = (record, at) => {
    if (record === undefined || record === null) return null;
    if (record.lockedUntil > at) return record;
    if (at - record.firstAt > windowMs) return null;
    return record;
  };

  const verdict = (record, at) => {
    if (record === null || record === undefined) return { locked: false, retryAfterMs: 0 };
    if (record.lockedUntil > at) return { locked: true, retryAfterMs: record.lockedUntil - at };
    return { locked: false, retryAfterMs: 0 };
  };

  /** 清掉所有已经过期（窗口外且未锁定）的键。 */
  const sweepExpired = (at) => {
    for (const [key, record] of records) {
      if (alive(record, at) === null) records.delete(key);
    }
    sinceSweep = 0;
  };

  /** 超量时从最早插入的那头丢，直到回到上限。 */
  const trim = () => {
    let excess = records.size - maxKeys;
    if (excess <= 0) return;
    for (const key of records.keys()) {
      records.delete(key);
      excess -= 1;
      if (excess <= 0) break;
    }
  };

  return {
    /** 查某个来源当前是否被锁。 */
    check(key) {
      if (typeof key !== 'string' || key === '') return { locked: false, retryAfterMs: 0 };
      const at = now();
      return verdict(alive(records.get(key), at), at);
    },
    /**
     * 记一次失败，返回记账之后的判定。
     * fingerprint 是本次所用凭据的摘要；与上次完全相同就不再累加。
     */
    fail(key, fingerprint) {
      if (typeof key !== 'string' || key === '') return { locked: false, retryAfterMs: 0 };
      const at = now();
      sinceSweep += 1;
      if (sinceSweep >= sweepEvery) sweepExpired(at);
      const current = alive(records.get(key), at);
      const record =
        current === null ? { firstAt: at, fails: 0, lockedUntil: 0, lastPrint: '', lastPrintAt: 0 } : current;
      const print = typeof fingerprint === 'string' ? fingerprint : '';
      // 同一份凭据在很短时间内重复提交视为同一次尝试（浏览器会把缓存的凭据
      // 按子资源重发几十遍）。超出这个窗口仍然算数，否则同一个错误密码
      // 反复提交就永远撞不到阈值。
      if (print !== '' && record.lastPrint === print && at - record.lastPrintAt < dedupeMs) {
        return verdict(record, at);
      }
      record.lastPrint = print;
      record.lastPrintAt = at;
      record.fails += 1;
      if (record.fails >= maxFails) {
        record.lockedUntil = at + lockMs;
        record.fails = 0;
        record.firstAt = at;
      }
      records.set(key, record);
      // 刚插入的是最新一条，不会成为被丢的那头。
      trim();
      return verdict(records.get(key) || record, at);
    },
    /** 认证成功：清掉该来源的计数。 */
    reset(key) {
      if (typeof key === 'string' && key !== '') records.delete(key);
    },
    /** 仅用于测试与诊断。 */
    size() {
      return records.size;
    },
    /** 仅用于测试与诊断：主动清一遍过期记录。 */
    sweep() {
      sweepExpired(now());
      trim();
      return records.size;
    },
  };
}

/** 从 Cookie 头里取某个名字的值。 */
export function readCookie(header, wanted) {
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
export function parseBasicAuth(header) {
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
export function isLoopbackPeer(address) {
  if (typeof address !== 'string') return false;
  const value = address.trim().toLowerCase();
  if (value === '::1' || value === '127.0.0.1') return true;
  if (value.startsWith('127.')) return true;
  if (value.startsWith('::ffff:127.')) return true;
  return false;
}

/**
 * 判断一个 TCP 对端是不是「可信的前置代理」：回环或私有网段。
 * 只有这种对端才有资格用转发头声明来源——否则任何人都能替别人制造锁定。
 */
export function isTrustedProxyPeer(address) {
  if (isLoopbackPeer(address)) return true;
  if (typeof address !== 'string') return false;
  const value = address.trim().toLowerCase().replace(/^::ffff:/, '');
  const octets = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (!octets) return false;
  const [a, b] = [Number(octets[1]), Number(octets[2])];
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

/**
 * 这次请求是不是来自非本机。
 * 网关转发时会带上 PEER_HEADER，宿主直接看到的是网关自己（回环），
 * 所以要先认这个头；没有头时按 TCP 对端地址判断（本机客户端直接访问宿主的情况）。
 */
export function isRemotePeerRequest(req) {
  if (!req) return false;
  if (req.headers && req.headers[PEER_HEADER] === 'remote') return true;
  const address = req.socket && req.socket.remoteAddress;
  if (!address) return false;
  return !isLoopbackPeer(address);
}

/**
 * 把 publicUrl 拆成多项。
 * 支持两种写法：逗号/空白分隔的字符串（界面里就是一行文本），或者字符串数组。
 * 允许配置多个入口，是因为同一个实例常同时用「局域网 IP」和「公网域名」访问，
 * 只认一个会让另一个被当成跨站请求拒掉。
 */
export function publicUrlList(value) {
  if (Array.isArray(value)) {
    return value.filter((item) => typeof item === 'string' && item.trim() !== '').map((item) => item.trim());
  }
  if (typeof value !== 'string') return [];
  return value
    .split(/[,\s]+/)
    .map((item) => item.trim())
    .filter((item) => item !== '');
}

/**
 * 浏览器来源校验，等价于宿主的 ctx.connection.requestRejection 里的 Host/Origin 围栏。
 *
 * 网关自己的接口（/__dshgw/*）由本插件就地处理，不走宿主路由，因此拿不到宿主的
 * 那层校验。缺了它，用户在浏览器里登录网关后，任何网页都能跨站调用这些接口——
 * 浏览器会自动带上网关 cookie，于是能列举本机目录、创建目录。
 *
 * 这里只做「请求是不是本页自己发的」这一层判断，不做 Host 白名单：网关的 Host
 * 由公网域名或反代决定，本来就不在宿主的 trustedHosts 里，认证已由网关完成。
 * 返回拒绝原因，放行时返回 null。
 */
export function crossSiteRejection(req, publicUrl) {
  const headers = req.headers || {};
  // 浏览器明确声明跨站，直接拒；这一条能挡住不带 Origin 的 <img>、<script> 之类。
  if (headers['sec-fetch-site'] === 'cross-site') return 'sec-fetch-site';
  const raw = headers.origin;
  if (typeof raw !== 'string' || raw === '') return null;
  let origin;
  try {
    origin = new URL(raw);
  } catch {
    return 'bad-origin';
  }
  if (origin.protocol !== 'http:' && origin.protocol !== 'https:') return 'bad-origin';
  // 反代可能改写 Host，所以配置了 publicUrl 时把它的 authority 也算作同源。
  // 允许多个入口（局域网地址 + 公网域名同时用），逐个比对。
  for (const candidate of publicUrlList(publicUrl)) {
    try {
      if (new URL(candidate).host === origin.host) return null;
    } catch {
      // 单项不合法就跳过，不影响其它入口。
    }
  }
  const host = headers.host;
  if (typeof host !== 'string' || host === '') return 'missing-host';
  let target;
  try {
    // Host 可能省略端口，借 Origin 的 scheme 补齐后再比较 authority。
    target = new URL(`${origin.protocol}//${host}`);
  } catch {
    return 'bad-host';
  }
  return target.host === origin.host ? null : 'origin-mismatch';
}

/**
 * 远程选择器脚本的源码。
 * 只在第一次请求时读盘，之后复用；文件随包发布，路径相对本模块。
 */
let pickerSourceCache = null;
let pickerSourceStamp = 0;
let pickerVersionCache = '';
export function pickerSource() {
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
export function pickerVersion() {
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
    const sessionSecret = () => {
      if (cachedSecret) return cachedSecret;
      cachedSecret = readSessionSecret();
      return cachedSecret;
    };

    // 会话世代：轮换它即吊销全部已签发的网关 cookie。缺失时生成并落盘。
    const epochFile = join(dshHome(), stateFileFor(EPOCH_FILE));
    let epoch = null;
    const sessionEpoch = () => {
      if (epoch !== null) return epoch;
      epoch = readEpoch(epochFile);
      if (epoch === null) {
        // 文件在但读不出来（被截断、手工改坏），说明此前吊销过谁已经无法追溯；
        // 只能重新起一个世代，代价是所有设备重登。不说一声的话，用户只会
        // 看到「突然全部掉线」而无从解释。
        if (existsSync(epochFile)) {
          log(ctx, 'warn', '会话世代文件损坏，已重新生成世代，此前登录的设备需要重新登录');
        }
        epoch = base64Url(randomBytes(24));
        try {
          writeEpoch(epochFile, epoch);
        } catch (error) {
          // 写不进去也不影响本次进程内的认证，只是重启后会换一个值。
          log(ctx, 'warn', '写入会话世代失败：' + ((error && error.message) || error));
        }
      }
      return epoch;
    };
    const rotateSessionEpoch = () => {
      const next = base64Url(randomBytes(24));
      // 先写盘再赋值：写失败时不能让内存里的世代先变，否则接口回「失败」
      // 而所有会话其实已经被吊销，重启后又会从文件读回旧值、把刚踢掉的
      // 设备恢复回来。
      writeEpoch(epochFile, next);
      epoch = next;
      return epoch;
    };

    /** 当前生效的凭据指纹。改用户名/密码/免密 token 都会换一个值。 */
    const currentCredentialTag = () => credentialTag(settings.username, settings.password, settings.accessToken);

    /**
     * 网关 cookie 的密钥。
     * 每次现算而不是缓存：它依赖凭据与世代，缓存会在改配置后留下失效窗口。
     */
    const cookieKey = () => cookieKeyFor(sessionSecret(), `${currentCredentialTag()}.${sessionEpoch()}`);

    // 认证失败限速：HTTP 与 upgrade 两条路径共用同一份计数。
    const limiter = createAttemptLimiter();

    /** 取这次请求的来源标识，用于限速计数。 */
    const peerKeys = (req) => {
      const keys = [];
      const address = req.socket && req.socket.remoteAddress;
      if (typeof address === 'string' && address !== '') keys.push(`tcp:${address}`);
      // 转发头只在对端本身可信时才算数。否则任何人写一个别人的 IP 上来，
      // 连错几次就能把那个来源锁在门外——把限速变成了一件攻击工具。
      if (!isTrustedProxyPeer(address)) return keys;
      const forwarded = req.headers && req.headers['x-forwarded-for'];
      if (typeof forwarded === 'string') {
        const first = forwarded.split(',')[0].trim();
        if (first !== '') keys.push(`xff:${first}`);
      }
      return keys;
    };

    /** 任一来源维度被锁即返回锁定信息，否则 null。 */
    const lockedFor = (req) => {
      let worst = null;
      for (const key of peerKeys(req)) {
        const state = limiter.check(key);
        if (state.locked && (worst === null || state.retryAfterMs > worst.retryAfterMs)) worst = state;
      }
      return worst;
    };

    /**
     * 这次尝试所用凭据的摘要，只用于识别「是不是同一份凭据」。
     * 取 Authorization 头（或 query 上的 token）的哈希，任何地方都不留原值。
     */
    const credentialPrint = (req, search) => {
      const digest = (text) => createHash('sha256').update(text).digest('hex').slice(0, 16);
      const supplied = req && req.headers && req.headers.authorization;
      if (typeof supplied === 'string' && supplied !== '') return digest(supplied);
      if (search) {
        const token = search.get('token');
        if (token !== null) return digest(`token:${token}`);
      }
      return '';
    };

    /** 记一次认证失败，并返回是否因此进入锁定。 */
    const noteFailure = (req, search) => {
      const print = credentialPrint(req, search);
      let worst = null;
      for (const key of peerKeys(req)) {
        const state = limiter.fail(key, print);
        if (state.locked && (worst === null || state.retryAfterMs > worst.retryAfterMs)) worst = state;
      }
      return worst;
    };

    const clearFailures = (req) => {
      for (const key of peerKeys(req)) limiter.reset(key);
    };

    ctx.inject(['webServer'], (scoped) => {
      let server = null;
      let boundPort = null;
      let disposed = false;
      let starting = false;
      let listenError = null;
      const routeDisposers = [];
      // 宿主允许的最长会话寿命，启动时读一次即可：它来自静态配置，运行期不会变。
      const hostCookieDays = readHostCookieDays(ctx);

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
       * 这次请求是不是从本机之外进来的。
       * 网关前面若还叠了一层同机反代，TCP 对端是回环，只能看转发头。
       */
      const isRemotePeer = (headers, peerAddress) => {
        if (typeof peerAddress === 'string' && peerAddress && !isLoopbackPeer(peerAddress)) return true;
        const forwarded = headers && headers['x-forwarded-for'];
        if (typeof forwarded === 'string') {
          const first = forwarded.split(',')[0].trim();
          if (first && !isLoopbackPeer(first)) return true;
        }
        return false;
      };

      /**
       * 这次请求是不是来自本机之外的浏览器。
       * 本机继续用系统对话框，行为完全不变；只有远程才需要接管。
       */
      const isRemoteViewer = (headers, peerAddress) =>
        settings.remotePicker && isRemotePeer(headers, peerAddress);

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
        // 只往「完整文档」里插。宿主也有接口会返回 text/html 的片段，往片段里塞
        // <script> 既没意义（innerHTML 插入的 script 不会执行），又可能被页面
        // 用 document.write 之类的方式带进真正的文档里。
        if (!/<html[\s>]/i.test(html) && !/<!doctype\s+html/i.test(html)) return html;
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
        // 客户端自带的转发链头一并丢掉：宿主只需要 PEER_HEADER 这一个判据，
        // 留一条可以被任意伪造的 XFF 只会误导它。
        delete headers['x-forwarded-for'];
        delete headers['x-real-ip'];
        // 文档请求禁掉压缩：网关要往 HTML 里插一段脚本，压缩后就地替换不了。
        if (wantsHtmlInjection(incoming, peerAddress)) delete headers['accept-encoding'];
        // 客户端自己带的同名头一律丢弃，只认网关观察到的真实对端地址。
        delete headers[PEER_HEADER];
        if (isRemotePeer(incoming, peerAddress)) headers[PEER_HEADER] = 'remote';
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
          const signed = signSessionCookie(secret, host, issuedAt, hostCookieDays);
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

        // WebSocket 握手既不能重定向也不能弹 Basic 对话框，所以这里只认
        // 「页面登录后拿到的网关 cookie」与 query 上的固定 token。
        // 少了这一段，任何人连上端口就能拿到一条带宿主会话 cookie 的升级请求——
        // 宿主的准入检查恰恰会因为这条注入的 cookie 而放行。
        let parsed;
        try {
          parsed = new URL(req.url || '/', 'http://placeholder');
        } catch {
          socket.destroy();
          return;
        }

        const locked = lockedFor(req);
        if (locked !== null) {
          audit('upgrade-lockout', req, { retryAfter: retryAfterSeconds(locked) });
          socket.end(
            `HTTP/1.1 429 Too Many Requests\r\nretry-after: ${retryAfterSeconds(locked)}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n`,
          );
          return;
        }

        // 跨站 WebSocket 不受 CORS 约束（浏览器只做 Origin 声明），必须自己拦。
        const rejection = crossSiteRejection(req, settings.publicUrl);
        if (rejection !== null) {
          audit('upgrade-reject', req, { reason: rejection });
          log(ctx, 'warn', `upgrade 跨站被拒：${rejection}`);
          socket.destroy();
          return;
        }

        const verdict = admit(req, parsed.searchParams);
        if (verdict.status !== undefined) {
          if (credentialAttempted(req, parsed.searchParams)) {
            audit('upgrade-fail', req, {}, true);
            noteFailure(req, parsed.searchParams);
          }
          const body = Buffer.from(verdict.body, 'utf8');
          const head401 =
            verdict.status === 500
              ? `HTTP/1.1 500 Internal Server Error\r\n`
              : `HTTP/1.1 401 Unauthorized\r\nwww-authenticate: Basic realm="DSH", charset="UTF-8"\r\n`;
          socket.end(
            `${head401}content-type: text/plain; charset=utf-8\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n${verdict.body}`,
          );
          return;
        }

        const port = upstreamPort();
        if (port === null) {
          socket.destroy();
          return;
        }
        // 认证已经过了，和 HTTP 路径一样把该来源的失败计数清掉；
        // 否则「先输错几次、然后登录成功」的人会带着旧计数继续走下去。
        clearFailures(req);
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

      /**
       * 免密登录链接只能指向一个入口：配了多个 publicUrl 时取第一个，
       * 否则会拼出 `https://a,https://b/?token=…` 这种打不开的地址。
       */
      const loginUrlFor = (publicUrl, accessToken) => {
        if (!accessToken) return null;
        const first = publicUrlList(publicUrl)[0];
        if (!first) return null;
        return `${first.replace(/\/+$/, '')}/?token=${encodeURIComponent(accessToken)}`;
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
          loginUrl: loginUrlFor(base, settings.accessToken),
          username: settings.username || null,
          basicAuth: Boolean(settings.password),
          tokenLogin: Boolean(settings.accessToken),
          cookieDays: settings.cookieDays,
          remotePicker: settings.remotePicker !== false,
          browseRoot: settings.browseRoot || '',
          sessionCookie: secretReady ? { lifetimeDays: hostCookieDays } : null,
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

      /**
       * 打开选择器时落在哪：家目录在浏览范围内就从家目录开始，否则退回浏览根。
       * 这样把 browseRoot 放宽到 `/` 或 `/Users` 时，起点仍是自己的家目录，
       * 只是多了向上的几级。
       */
      const browseStartPath = () => {
        const root = browseRootPath();
        const home = homedir();
        return isInside(root, home) ? home : root;
      };

      /** 把请求里的路径收敛到根内；越界、不存在、非目录都抛错。 */
      const resolveInsideRoot = async (raw) => {
        let root;
        try {
          root = await realpath(browseRootPath());
        } catch {
          throw new Error('浏览根目录不存在：' + browseRootPath());
        }
        const explicit = typeof raw === 'string' && raw.trim();
        const wanted = explicit ? resolve(raw.trim()) : browseStartPath();
        let real;
        try {
          real = await realpath(wanted);
        } catch {
          throw new Error('目录不存在：' + wanted);
        }
        // realpath 之后再比一次，符号链接也逃不出去。
        if (!isInside(root, real)) {
          // 没指定路径时是「打开选择器」，家目录万一被链接到范围外就退回根，
          // 不至于一进来就报错；显式指定的路径仍然照常拒绝。
          if (explicit) throw new Error('路径超出浏览范围');
          real = root;
        }
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
        const { real, root } = await resolveInsideRoot(parentRaw);
        const target = join(real, name);
        try {
          await mkdir(target);
        } catch (error) {
          if (error && error.code === 'EEXIST') throw new Error('同名目录已存在');
          if (error && error.code === 'ENOENT') throw new Error('父目录不存在');
          throw new Error('创建失败：' + ((error && error.message) || error));
        }
        // 从校验父目录到真正 mkdir 之间，父目录有可能被换成指向根外的符号链接。
        // 刚建好就复核一次，越界就把这个空目录收掉再报错，别留下一个“在根外
        // 建了东西”的既成事实。
        try {
          const created = await realpath(target);
          if (!isInside(root, created)) {
            await rmdir(target).catch(() => {});
            throw new Error('路径超出浏览范围');
          }
        } catch (error) {
          if (error && error.message === '路径超出浏览范围') throw error;
          // 复核本身失败（例如刚被人删掉）不影响结果，交给下一位用户重试。
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
        // gatewayCookieOk 会读宿主会话密钥，读不到时抛错。这里必须自己兜住：
        // 抛到 handler 之外就是 uncaught exception，整个宿主进程会退出。
        let cookieOk = false;
        try {
          cookieOk = gatewayCookieOk(req);
        } catch (error) {
          sendJson(res, 500, {
            ok: false,
            error: 'no-session-secret',
            message: '网关无法读取宿主会话密钥：' + ((error && error.message) || error),
          });
          return;
        }
        if (cookieOk || basicAuthOk(req) || configAuthorized(req)) {
          clearFailures(req);
          sendJson(res, 200, stateBody());
          return;
        }
        // 提交了凭据但不对：和主入口一样计入限速，别让这里成为绕过限速的试探口。
        if (credentialAttempted(req, null)) {
          audit('state-auth-fail', req, {}, true);
          noteFailure(req, null);
        }
        res.writeHead(401, {
          'content-type': 'text/plain; charset=utf-8',
          'www-authenticate': 'Basic realm="DSH", charset="UTF-8"',
          'cache-control': 'no-store',
        });
        res.end('需要认证');
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
          const items = publicUrlList(raw);
          if (items.length === 0) return { value: '' };
          for (const item of items) {
            if (!/^https?:\/\/[^\s]+$/i.test(item)) {
              return { error: 'bad-url', message: '对外地址必须以 http:// 或 https:// 开头：' + item };
            }
          }
          // 统一成逗号分隔的单行文本，界面里就是一个输入框。
          return { value: items.join(',') };
        }
        if (key === 'cookieDays') {
          // 只认真正的数字：Number(true) === 1 会让布尔值悄悄通过。
          const value = typeof raw === 'number' ? Math.trunc(raw) : Number.NaN;
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
          // 同上：布尔与字符串都不该被 Number() 蒙混过关。
          const value = typeof raw === 'number' ? Math.trunc(raw) : Number.NaN;
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
          /** 上一次监听失败的原因，界面用它解释「为什么显示未监听」。 */
          listenError: listenError,
          upstreamPort: upstreamPort(),
          loginUrl: stateBody().loginUrl,
          basicAuth: Boolean(settings.password),
          tokenLogin: Boolean(settings.accessToken),
        },
        restartKeys: RESTART_KEYS,
      });

      /**
       * 配置读写：GET 读当前值，POST 保存到覆盖文件并热应用。
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
          const restartRequired = Object.keys(patch).some((key) => RESTART_KEYS.includes(key));
          // 等监听起来再回答：不等的话响应里 boundPort 还是旧值，
          // 用户刚打开开关就看到「未监听」，得再点一次刷新才对。
          const settled = canListen() ? startGateway() : (stopGateway(), Promise.resolve());
          void settled.then(() => {
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
        });
      };

      /**
       * 「退出所有登录」：轮换会话世代，让此前签发的网关 cookie 立即失效。
       * 不动凭据，所以不会连锁影响别处，也不需要重启。
       * 必须自己校验来源——否则任意网页发一个跨站 POST 就能把用户踢下线。
       */
      const handleLogoutAll = (req, res) => {
        // 三种身份都能吊销：网关 cookie（远程用户点按钮）、宿主界面会话（本机）、Basic Auth。
        // 只认 configAuthorized 会漏掉最主要的那条路——远程浏览器手里没有宿主 cookie。
        let signedIn = false;
        try {
          signedIn = gatewayCookieOk(req);
        } catch {}
        if (!signedIn && !configAuthorized(req)) {
          sendJson(res, 401, {
            ok: false,
            error: 'unauthorized',
            message: '需要已登录的 DSH 界面会话，或提供 Basic Auth 凭据',
          });
          return;
        }
        const method = (req.method || 'GET').toUpperCase();
        if (method !== 'POST') {
          sendJson(res, 405, { ok: false, error: 'method-not-allowed', message: '只支持 POST' });
          return;
        }
        const rejection = crossSiteRejection(req, settings.publicUrl);
        if (rejection !== null) {
          sendJson(res, 403, {
            ok: false,
            error: 'cross-site',
            message: '跨站请求被拒绝（' + rejection + '）',
          });
          return;
        }
        try {
          rotateSessionEpoch();
        } catch (error) {
          sendJson(res, 500, {
            ok: false,
            error: 'persist-failed',
            message: '轮换会话世代失败：' + ((error && error.message) || error),
          });
          return;
        }
        clearGatewayCookie(res);
        audit('logout-all', req);
        log(ctx, 'info', '已吊销全部网关登录会话');
        sendJson(res, 200, { ok: true, rotatedAt: new Date().toISOString() });
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
        const value = signGatewayCookie(cookieKey(), settings.cookieDays, currentCredentialTag());
        const maxAge = settings.cookieDays * 24 * 60 * 60;
        res.setHeader('set-cookie', `${GATEWAY_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax`);
      };

      const clearGatewayCookie = (res) => {
        res.setHeader('set-cookie', `${GATEWAY_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`);
      };

      // 登录审计：只记事件与来源，不记凭据；失败事件按来源限流，避免被刷爆磁盘。
      const auditFile = join(dshHome(), stateFileFor(AUDIT_FILE));
      const auditThrottle = new Map();
      let auditWarnedAt = 0;
      const audit = (event, req, extra = {}, throttle = false) => {
        const address = (req && req.socket && req.socket.remoteAddress) || '';
        if (throttle) {
          const now = Date.now();
          if (now - (auditThrottle.get(address) || 0) < 60_000) return;
          auditThrottle.set(address, now);
          // 节流表按来源 IP 一条，正常流量下很小；但被大量不同来源刷时会一直涨，
          // 偶尔把已经过了节流窗口的条目清掉即可，代价可忽略。
          if (auditThrottle.size > 512) {
            for (const [key, at] of auditThrottle) {
              if (now - at >= 60_000) auditThrottle.delete(key);
            }
          }
        }
        const agent = String((req && req.headers && req.headers['user-agent']) || '').slice(0, 120);
        if (!appendAudit(auditFile, { event, ip: address, ua: agent, ...extra })) {
          // 写不进去就一次都写不进去，别再按事件刷屏；复用 60 秒节流。
          const now = Date.now();
          if (now - (auditWarnedAt || 0) >= 60_000) {
            auditWarnedAt = now;
            log(ctx, 'warn', `审计日志写入失败：${auditFile}（检查该路径是否可写）`);
          }
        }
      };

      /** 网关 cookie 是否有效。密钥读取失败时抛错，由调用方转 500。 */
      const gatewayCookieOk = (req) =>
        verifyGatewayCookie(readCookie(req.headers.cookie, GATEWAY_COOKIE), cookieKey(), currentCredentialTag());

      /** 固定 token 是否匹配（免密链接）。 */
      const tokenOk = (search) => {
        if (!settings.accessToken || !search) return false;
        const supplied = search.get('token');
        return supplied !== null && equalSecret(supplied, settings.accessToken);
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

      /**
       * 准入判定：网关 cookie → 固定 token → Basic Auth。
       *
       * HTTP 与 WebSocket upgrade 共用这一份，避免两条路径分叉——upgrade 曾经
       * 完全绕过认证，等于把宿主会话直接送给了任何能连到端口的人。
       */
      const admit = (req, search) => {
        try {
          if (gatewayCookieOk(req)) return { source: 'cookie' };
        } catch (error) {
          return {
            status: 500,
            body: '网关无法读取宿主会话密钥：' + ((error && error.message) || error),
          };
        }
        if (tokenOk(search)) return { source: 'token' };
        if (basicAuthOk(req)) return { source: 'basic' };
        return { status: 401, body: '需要认证' };
      };

      /** 这次请求有没有真的提供凭据（用于区分「输错了」与「还没登录」）。 */
      const credentialAttempted = (req, search) => {
        if (typeof req.headers.authorization === 'string' && req.headers.authorization !== '') return true;
        return Boolean(search) && search.get('token') !== null;
      };

      const retryAfterSeconds = (state) => Math.max(1, Math.ceil(state.retryAfterMs / 1000));

      /** 认证通过后的分流：网关自己的接口就地处理，其余转发给宿主。 */
      const authorized = (req, res, pathname, search) => {
        if (settings.remotePicker) {
          // 这三个接口绕开宿主路由，因此要自己补上来源校验。
          if (
            pathname === PICKER_SCRIPT_PATH ||
            pathname === FS_LIST_PATH ||
            pathname === FS_MKDIR_PATH
          ) {
            const rejection = crossSiteRejection(req, settings.publicUrl);
            if (rejection !== null) {
              res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
              res.end('跨站请求被拒绝');
              return;
            }
            if (pathname === PICKER_SCRIPT_PATH) {
              handlePickerScript(res);
              return;
            }
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

        // 被锁的来源先回 429：不必再核对凭据，也就无从试探。
        const locked = lockedFor(req);
        if (locked !== null) {
          const retry = retryAfterSeconds(locked);
          res.writeHead(429, {
            'content-type': 'text/plain; charset=utf-8',
            'retry-after': String(retry),
            'cache-control': 'no-store',
          });
          res.end(`尝试过于频繁，请 ${retry} 秒后重试`);
          return;
        }

        // 状态路由也走限速与认证，但它只读、不接管后续流程。
        if (pathname === STATE_PATH) {
          handleState(req, res);
          return;
        }

        // 吊销入口自己管认证：Basic 或宿主界面会话都行，但绝不能走「种新 cookie」那条路，
        // 否则响应里会同时出现新 cookie 和清除指令，等于刚退出又登录了。
        if (pathname === LOGOUT_ALL_PATH) {
          handleLogoutAll(req, res);
          return;
        }

        const verdict = admit(req, search);
        if (verdict.status === 500) {
          res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
          res.end(verdict.body);
          return;
        }
        if (verdict.source === 'cookie') {
          authorized(req, res, pathname, search);
          return;
        }
        if (verdict.source === 'token') {
          clearFailures(req);
          audit('login-ok', req, { via: 'token' });
          setGatewayCookie(res);
          res.writeHead(303, { location: '/', 'cache-control': 'no-store' });
          res.end();
          return;
        }
        if (verdict.source === 'basic') {
          clearFailures(req);
          audit('login-ok', req, { via: 'basic', user: settings.username });
          setGatewayCookie(res);
          authorized(req, res, pathname, search);
          return;
        }

        // 失败：只有「确实提交了凭据但不对」才计数，裸 401 是浏览器的正常握手。
        if (credentialAttempted(req, search)) {
          audit('login-fail', req, { via: search && search.get('token') !== null ? 'token' : 'basic' }, true);
          const nowLocked = noteFailure(req, search);
          if (nowLocked !== null) {
            const retry = retryAfterSeconds(nowLocked);
            audit('lockout', req, { retryAfter: retry });
            res.writeHead(429, {
              'content-type': 'text/plain; charset=utf-8',
              'retry-after': String(retry),
              'cache-control': 'no-store',
            });
            res.end(`尝试过于频繁，请 ${retry} 秒后重试`);
            return;
          }
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

      // 退出所有登录：轮换会话世代，这一步之前签发的 cookie 全部作废。
      try {
        const logoutRemove = mount(LOGOUT_ALL_PATH, handleLogoutAll);
        if (logoutRemove) routeDisposers.push(logoutRemove);
      } catch (error) {
        log(ctx, 'warn', '注册退出所有登录路由失败：' + ((error && error.message) || error));
      }

      const createGateway = () => {
        const candidate = createHttpServer(handler);
        // 大文件/流式响应：不掐正文，交给对端决定什么时候结束。
        candidate.keepAliveTimeout = 65_000;
        // 只等请求头，20 秒足够；把它压短能挡掉「连上不发」的一半慢速攻击。
        candidate.headersTimeout = 20_000;
        candidate.requestTimeout = 0;
        // 上限挡住另一种慢速攻击：连上端口就不动，既不产生凭据也不触发限速。
        // 这类连接只能靠连接数封顶，否则几千条并发就能把文件描述符吃光。
        candidate.maxConnections = 512;
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
        // close() 只是不再接受新连接，已经建立的 keep-alive 连接还能活到
        // keepAliveTimeout（65 秒）。「先把网关关掉」是应急动作，不能留这个窗口。
        try {
          current.closeAllConnections?.();
        } catch {}
        log(ctx, 'info', `网关已停止监听 ${settings.listen}:${settings.port}`);
      };

      /** 启动监听：幂等，已在监听或条件不满足时直接返回。 */
      /**
       * 启动监听。返回的 promise 在成功或失败后都 resolve，
       * 好让「保存配置」这类调用方等结果再回答，而不是拿一份还没更新的状态。
       */
      const startGateway = () => {
        if (disposed || starting || server !== null || !canListen()) return Promise.resolve();
        starting = true;
        return listenOn(settings.listen, settings.port)
          .then((candidate) => {
            starting = false;
            listenError = null;
            if (disposed || !canListen()) {
              try {
                candidate.close();
                candidate.closeAllConnections?.();
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
              listenError = `端口 ${settings.port} 已被占用，网关未启动`;
            } else if (code === 'EACCES') {
              listenError = `没有权限监听 ${settings.listen}:${settings.port}`;
            } else {
              listenError = `监听 ${settings.listen}:${settings.port} 失败：${code || (error && error.message) || error}`;
            }
            log(ctx, 'error', listenError);
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
