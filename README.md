# dsh-reverse-proxy-gateway

**English** · [简体中文](README.zh-CN.md)

Safely exposes the local web UI of [DSH (DeepSeek Harness)](https://github.com/deepseek-ai) desktop to the public internet — one plugin handles listening, authentication, session injection and port following.

Once installed, open your own domain from a phone or any computer and **you land in the same session on the same machine**, not a second instance.

## Features

- Opens a fixed port inside the DSH process, leaving the host's original ephemeral loopback port untouched
- Built-in Basic Auth and fixed-token login; a long-lived cookie is issued on success (30 days by default)
- Automatically follows the host's random port after a DSH restart — nothing to sync by hand
- Rewrites `Host` and injects the host session cookie while forwarding — **no `trustedHosts` edit and no lengthened `cookieMaxAgeDays` required**
- Supports WebSocket upgrade and streaming responses
- Remote "create workspace" uses an in-browser directory tree instead of the host's system dialog (`remotePicker`)
- Configurable from three places: the top-level settings tab, the plugin detail card, and the icon below the composer

## Stack

| Item | Notes |
|---|---|
| Language | JavaScript (plain ESM, no build step) |
| Runtime | Node.js `^22.19.0 \|\| >=24.0.0` |
| Host | DSH `^0.2.0-rc.1 \|\| ^0.2.1-rc.1 \|\| ^0.2.2-rc.1` |
| Runtime dependencies | **None** (only built-ins such as `node:http`, `node:net`, `node:crypto`, `node:fs`) |
| Server | Hand-rolled HTTP server and forwarder; `node:net` for upgrades |
| Client | Host `slots` plus `React.createElement` (no JSX, no bundler) |
| Config | `schemastery` schema, runtime override file `~/.dsh/.dsh-reverse-proxy-gateway.json` |

## Installation

**Desktop (recommended)**: Settings → Plugins → Install, and paste the git URL below.

```
git+https://github.com/xiongking/dsh-reverse-proxy-gateway.git
```

**Command line** (non-managed profiles such as `web`):

```bash
dsh plugin --profile web add "git+https://github.com/xiongking/dsh-reverse-proxy-gateway.git"
```

Restart DSH afterwards. The `desktop` profile is owned by the desktop app and cannot be managed from the command line — use the GUI.

## Quick start

### 1. Set credentials

Open **Settings → Remote access** (or the plugin detail card), enter a username and password, and save. The password needs at least 8 characters.

> Either a password or a fixed token is required, otherwise the gateway will not listen. That is deliberate — it prevents exposing an unauthenticated surface.

### 2. Check the listen address

The default is `0.0.0.0:3080`, meaning port 3080 on every local interface. Find your LAN IP:

```bash
ifconfig | grep "inet " | grep -v 127.0.0.1
```

### 3. Point your reverse proxy at this machine

A router, nginx, Caddy or Cloudflare Tunnel all work. Set the target to `LAN-IP:3080`, for example `192.168.1.10:3080`.

There is exactly one hard requirement: **keep the original `Host` header** (do not rewrite it to `127.0.0.1`), or the plugin's address check will reject the request. Terminate TLS at that layer.

### 4. Fill in the public URL

In **Settings → Remote access**, put your domain into "Public URL", for example `https://dsh.example.com`. It is only used to build passwordless links and for status display.

### 5. Log in

Open your domain in a browser and use the credentials from step 1. After one login the cookie carries you through — refreshing on a phone or switching apps will not ask again.

## Configuration

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Master switch; turning it off stops listening |
| `listen` | string | `"0.0.0.0"` | Listen address. `0.0.0.0` = all interfaces; use `127.0.0.1` when only a local proxy connects |
| `port` | number | `3080` | Listen port that your reverse proxy targets |
| `publicUrl` | string | `""` | Public URL, used only for passwordless links and status display |
| `username` | string | `"dsh"` | Basic Auth username |
| `password` | string | `""` | Basic Auth password, at least 8 characters |
| `accessToken` | string | `""` | Fixed login token; visiting `publicUrl?token=<value>` logs in without a password |
| `cookieDays` | number | `30` | Gateway cookie lifetime in days |
| `switchMode` | `"local"` \| `"always"` \| `"never"` | `"local"` | Where the composer icon appears; see below |
| `confirmToggle` | boolean | `true` | One click arms a confirmation, a second one performs the toggle |
| `remotePicker` | boolean | `true` | Let remote visitors pick workspaces in an in-page directory tree; see below |
| `browseRoot` | string | `""` | Upper bound for remote browsing; empty means the current user's home directory. The starting point is always home |

Changing `port` or `listen` requires a DSH restart; everything else takes effect on save.

UI changes are written to `~/.dsh/.dsh-reverse-proxy-gateway.json` (mode 600), which takes precedence over the static profile config.

## The icon below the composer

In the conversation view, at the right end of the row under the composer card, there is a globe icon. **Its colour is the state**:

| Colour | Meaning |
|---|---|
| Green | Enabled and listening |
| Grey | Disabled |
| Amber | Enabled but not listening (port taken, or no password and no fixed token) |

**One click toggles it**, no DSH restart needed. Hovering shows "Remote access is on" or "Remote access is off".

### Visibility (`switchMode`)

The default is `local`: the icon only appears when DSH is opened on this machine, and is **hidden** when you reach it from a phone, tablet or another computer through your domain. The reason is that a single tap on the remote side would shut the gateway down and cut the very connection you are using — easy to hit by accident on a touchscreen.

| Value | Behaviour |
|---|---|
| `local` | Shown only for local access |
| `always` | Always shown, so remote devices can toggle it too |
| `never` | Never shown (still toggleable in Settings → Remote access) |

**How "local" is decided**: on the server, from the request's origin, not guessed by the browser. When forwarding, the gateway passes the fact that "this connection came from a non-loopback address" to the host in a request header, and the host returns a `local` field from its config endpoint. The desktop client loads `dsh-app://app/`, a custom protocol, so judging by the page address alone would misclassify a local window as remote.

### Confirmation (`confirmToggle`)

On by default. With it enabled, the first click only arms: the icon turns amber and the tooltip becomes "Click again to confirm disabling remote access". A second click **within 4 seconds** performs the toggle; after that the arming is dropped.

Turn it off to go back to "one click, immediate toggle".

Both options live under Settings → Remote access → Composer switch, and apply on save.

## Remote directory browsing (`remotePicker`)

When you click "Create workspace", DSH calls the **host machine's** system directory dialog. That dialog opens on the host's screen, and nothing happens in a remote browser — on a phone or a work laptop you simply never see it.

With `remotePicker` enabled (the default), the gateway injects a small script into the forwarded page's `<head>` and takes over the host frontend's directory entry point: remote access gets an in-browser directory tree where you can walk levels, create folders, and pick a directory as the workspace.

| Access origin | Behaviour |
|---|---|
| Local (opened straight on a loopback address) | Not injected; the system dialog is used as before |
| Remote (arriving through the gateway) | Script injected; the in-page directory tree is used |

**Browse scope** is governed by `browseRoot`: empty means the current user's home directory; an absolute path narrows it or widens it to some directory. The gateway lists **subdirectories only**, never files, and every path is resolved through `realpath` before comparison — symlinks cannot escape the root, and out-of-range requests are rejected outright.

`browseRoot` sets the **upper bound only**, not the starting point: opening the tree always starts at your home directory (when home is inside the bound) and can climb up to `browseRoot`. So with it empty you start at home and there is no "up" entry; with `/Users` you can climb from home to `/Users`; with `/` you can climb all the way to the filesystem root.

The three endpoints available to remote visitors (all require gateway authentication first; unauthenticated calls get 401):

| Endpoint | Purpose |
|---|---|
| `GET /__dshgw/fs/list?path=` | List one directory level; omitting `path` lands in your home directory |
| `POST /__dshgw/fs/mkdir` | Create one subdirectory under a given parent |
| `GET /__dshgw/picker.js` | The selector script injected into the page |

Turning `remotePicker` off restores the original behaviour: remote clicks on "Create workspace" call the host's system dialog again (which is to say, you will not see it).

## Security

- DSH has **shell access to the whole machine and read/write access to every disk**. If this gateway is breached, it is equivalent to handing over the machine.
- Do not expose `0.0.0.0:3080` straight to the internet. At minimum, terminate TLS at your router or tunnel, and add another authentication layer there if you can.
- A fixed token and a password are both long-lived credentials. If either leaks, change it in the UI immediately.
- The config endpoint requires an authenticated browser session or Basic Auth; it does not accept anonymous reads or writes.
- Outbound traffic only goes to loopback, so this is not an open proxy.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| External access returns 502 / cannot connect | The plugin is not listening. Check whether `enabled` is on and whether `password` is empty in Settings; a taken port logs `EADDRINUSE` |
| External access returns 403 | Your reverse proxy rewrote the `Host` header. Set it to preserve or pass through the original `Host` |
| Logged in, then bounced back to the login page | The browser did not keep the cookie, or `cookieDays` is too small. Check for private mode or blocked cookies |
| Changed `port` but nothing happened | Port and listen address need a DSH restart |
| Icon is amber | Enabled but not listening: port taken, or both password and token are empty |
| The plugin card never appears | Host routes were not ready; restart DSH |
| Remote "Create workspace" does nothing | With `remotePicker` off, the dialog opens on the host's screen. Turn it on and remote access uses the in-page tree |
| The remote tree does not show the target directory, or cannot go further up | You are already at `browseRoot`. Widen it (for example `/Users` or `/`); the starting point is still your home directory |

## Uninstall

1. Disable or remove `dsh-reverse-proxy-gateway` in the plugin list
2. Delete `~/.dsh/.dsh-reverse-proxy-gateway.json`

## License

MIT
