## What this adds

One entry for [`xiongking/dsh-reverse-proxy-gateway`](https://github.com/xiongking/dsh-reverse-proxy-gateway), category `remote`.

```yaml
url: https://github.com/xiongking/dsh-reverse-proxy-gateway
name: xiongking/dsh-reverse-proxy-gateway
category: remote
description:
  en: 'Exposes the local DSH web UI through a fixed-port gateway with Basic Auth, optional passwordless links and a settings card, forwarding to the host loopback port with a freshly signed session cookie so no trustedHosts or cookie-lifetime setup is needed.'
  zh: '通过固定端口网关把 DSH 本地 Web 界面暴露出去：Basic Auth、可选免密链接、插件面板内的设置卡片；转发时即时签发宿主会话 cookie，无需配置 trustedHosts、也无需调整宿主 cookie 寿命。'
```

## Why it isn't a duplicate

DSH only listens on an ephemeral loopback port, and the desktop profile pins `--host 127.0.0.1 --port 0` in the launcher, so there is no supported way to put it behind a reverse proxy. The usual workaround is a config file plus a separate proxy process — this plugin replaces both with one plugin and a settings card.

Two design points that differ from a plain reverse proxy:

- **It signs the host session cookie itself.** It reads the host's own signing secret (read-only) and mints a cookie for the loopback authority on each forwarded request, then rewrites `Host` to `127.0.0.1:<port>`. The host therefore treats the request as local-and-authenticated, which means a user does **not** have to add `trustedHosts` entries or raise the host's `cookieMaxAgeDays` — both of which are config-file edits that survive awkwardly across upgrades.
- **The externally visible cookie is separate.** Browsers hold a gateway cookie whose lifetime is user-configurable; the cookie injected toward the host is kept at 30 days because the host rejects anything longer.

## Checks against the requirements

- `dsh.bundle.patch` → `./cordis.patch.yml` in `package.json`, with the patch file at the repo root. `dsh.client.platform: web` for the settings card.
- Real, working code: `index.mjs` (1510 lines, no build step, `node --check` clean), `client/client.js` (1092 lines) for the panel card and `client/picker.js` (366 lines) for the remote directory picker. No runtime dependencies.
- Repo is older than 1 day at submission time.
- `dsh-plugin` topic added.
- Dependency directions: none — the plugin has no runtime dependencies and declares no `@deepseek-ai/*` peers.

## Accuracy notes on the description

- "fixed-port gateway" — listens on a configured port (default 3080) while the host port stays ephemeral; it follows the host port automatically on restart.
- "optional passwordless links" — a token query parameter can be enabled to mint a long-lived browser cookie; disabled by default, hence "optional".
- "settings card" — registered on the `plugins.bundle.config` slot, keyed by bundle package name.
- "no trustedHosts or cookie-lifetime setup is needed" — this is the point of signing the host cookie rather than relying on the host to accept an external authority. It was verified by running the gateway against an unmodified desktop profile.
- Streaming and WebSocket: the plugin forwards upgrade requests and streams responses; note that DSH's own client uses multipart streaming over `/api` rather than WebSocket, so the upgrade path is for other clients, not a requirement of the UI.
- Remote directory picking (1.3.0): DSH picks workspace directories through a host-side seam that resolves once at boot. On a loopback-bound desktop launch it resolves to the native OS chooser, which opens on the host's screen — useless to a browser connecting through this gateway. The plugin injects a selector script into the forwarded HTML for non-loopback callers only, so `globalThis.__DSH_DIRECTORY_PICKER__` is answered in-page instead of on the host. Local windows keep the native dialog untouched: the script never overrides an existing bridge. The two new settings, `remotePicker` and `browseRoot`, control this; `browseRoot` is the ceiling a remote browser may climb to, and the picker starts at the host user's home directory regardless.

## Security posture (for the reviewer's sanity check)

- Upstream is fixed to `127.0.0.1`; it is not an open proxy and takes no upstream from the request.
- The config endpoint requires an existing DSH session cookie or Basic Auth — an unauthenticated caller cannot read or rewrite credentials. This was a real defect in 0.1.0 (the source-address check was ineffective) and is documented in `CHANGELOG.md` under 0.2.0 as a breaking change.
- No telemetry, no outbound connections other than the loopback upstream.
- Listing is not a security review, and this PR does not claim otherwise: the README states plainly that exposing DSH to the internet grants shell-level capability to anyone who gets in, and recommends keeping the surface behind an additional layer where possible.
