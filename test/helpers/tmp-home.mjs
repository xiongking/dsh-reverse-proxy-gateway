/**
 * 测试用的临时 DSH_HOME。
 *
 * `apply()` 会读 `$DSH_HOME/.dsh-reverse-proxy-gateway.json` 并用它覆盖传入的配置，
 * 也会从 `$DSH_HOME/.credentials.yaml` 取宿主会话密钥。不隔离的话，本机真实配置会
 * 混进用例，表现为「本机绿、CI 红」。
 */
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

/** 造一份能被 readSessionSecret() 的正则匹配上的 credentials 内容。 */
function credentialsFile(secretBase64) {
  return [
    'client-connection/browser-session:',
    '  version: 1',
    `  secret: "${secretBase64}"`,
    '  rotatedAt: 1700000000000',
    '',
  ].join('\n');
}

/**
 * 建一个隔离的 DSH_HOME 并接管 process.env.DSH_HOME。
 *
 * @param {object} [options]
 * @param {object} [options.overrides] 写入 .dsh-reverse-proxy-gateway.json 的内容
 * @param {string} [options.secret] 指定会话密钥（base64），默认随机 32 字节
 * @returns {Promise<{home: string, secret: Buffer, cleanup: () => Promise<void>}>}
 */
export async function makeTmpHome(options = {}) {
  const home = await mkdtemp(join(tmpdir(), 'gw-test-'));
  const raw = options.secret === undefined ? randomBytes(32) : Buffer.from(options.secret, 'base64');
  const secretBase64 = raw.toString('base64');

  await writeFile(join(home, '.credentials.yaml'), credentialsFile(secretBase64), 'utf8');

  if (options.overrides !== undefined) {
    await writeFile(
      join(home, '.dsh-reverse-proxy-gateway.json'),
      JSON.stringify(options.overrides, null, 2) + '\n',
      'utf8'
    );
  }

  const previous = process.env.DSH_HOME;
  process.env.DSH_HOME = home;

  return {
    home,
    secret: raw,
    async cleanup() {
      // 只在 env 仍指向自己时恢复，避免 A 的 cleanup 把 B 刚设好的 DSH_HOME 冲掉。
      if (process.env.DSH_HOME === home) {
        if (previous === undefined) delete process.env.DSH_HOME;
        else process.env.DSH_HOME = previous;
      }
      await rm(home, { recursive: true, force: true });
    },
  };
}

/**
 * 取一个当前空闲的高位端口。
 *
 * `apply()` 对 port 有 `>= 1024` 的硬性回落（不满足就用 3080），所以不能用 0
 * 让系统分配。这里借系统分配一次再立刻释放，配合重试足够稳。
 */
export async function pickPort() {
  const { createServer } = await import('node:net');
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const port = await new Promise((resolve, reject) => {
      const probe = createServer();
      probe.once('error', reject);
      probe.listen(0, '127.0.0.1', () => {
        const address = probe.address();
        const value = address && typeof address === 'object' ? address.port : 0;
        probe.close(() => resolve(value));
      });
    });
    if (port >= 1024) return port;
  }
  throw new Error('拿不到可用端口');
}

/** 轮询等一个端口变成可连接。 */
export async function waitForPort(port, timeoutMs = 5000) {
  const { connect } = await import('node:net');
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ok = await new Promise((resolve) => {
      const socket = connect({ host: '127.0.0.1', port });
      socket.once('connect', () => {
        socket.destroy();
        resolve(true);
      });
      socket.once('error', () => {
        socket.destroy();
        resolve(false);
      });
    });
    if (ok) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
}

export { mkdir };
