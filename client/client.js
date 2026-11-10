// dsh-reverse-proxy-gateway — 浏览器半（client bundle）。
//
// 装载契约照抄已安装的真实样例（无构建链、无 JSX、无 import、无 TS 语法）：
//   window.__ModuleLoader__.load({ id: "<包名>", factory: (require) => {
//     var module = { exports: {} }; var exports = module.exports;
//     Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
//     let react = require("react");
//     ... return module.exports; } });
//
// 槽位：plugins.bundle.config，条目 key 是 bundle 包名（不是 row id），
// 宿主用它把卡片认到「包含的组件」里那条 bundle 上。
window.__ModuleLoader__.load({
	id: "dsh-reverse-proxy-gateway",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

		let react = require("react");

		const NS = "dsh-reverse-proxy-gateway";
		const BUNDLE_SLOT = "plugins.bundle.config";
		const CONFIG_URL = "/coopanion/reverse-proxy-gateway/config";
		// 设置面板导航里的一级条目（左侧 section 列表），与插件详情页卡片共用同一个面板。
		const SETTINGS_SECTION_SLOT = "settings.section";
		// 一级条目的导航图标。宿主按 row id 匹配，id 必须与 section 的 id 一致。
		const SECTION_ICON_SLOT = "settings.section.icon";
		// 输入框卡片下方那一行（与宿主的 ActivityPill / UsagePill 同一行）的右端。
		// 该容器是 align-items:center 的居中 flex，宽度=内容宽，光靠 marginLeft:auto
		// 推不到最右；由下面注入的 DOCK_CSS 把容器撑满、把本条目绝对定位到右端。
		const COMPOSER_DOCK_SLOT = "conversation.composer.dock";
		// 注入样式只认这一个属性，避免影响宿主自己的条目。
		const ENTRY_ATTR = "data-dsh-rpg-entry";
		const STYLE_ID = "dsh-reverse-proxy-gateway-dock-style";
		const DOCK_CSS =
			"[data-composer-dock]{width:100%;position:relative}" +
			"[data-composer-dock] > [" +
			ENTRY_ATTR +
			"]{position:absolute;right:10px;top:50%;transform:translateY(-50%);display:inline-flex}" +
			"[data-composer-dock] > [" +
			ENTRY_ATTR +
			"][data-dsh-rpg-empty]{display:none}";

		const ERROR_TEXT = {
			"bad-username": "用户名需 1–64 位，且不能含冒号或空白。",
			"bad-password": "密码至少 8 位；留空表示关闭密码登录。",
			"bad-token": "固定 token 至少 16 位，只能含字母、数字、下划线和短横线。",
			"bad-url": "对外地址必须以 http:// 或 https:// 开头。",
			"bad-cookie-days": "登录保持天数需在 1–3650 之间。",
			"invalid-port": "端口需在 1024–65535 之间。",
			"bad-listen": "监听地址只能是 IP、0.0.0.0 或 localhost。",
			"no-credential": "密码与固定 token 不能同时为空。",
			"persist-failed": "写入配置文件失败，改动没有保存。",
			"forbidden": "这个接口只允许本机访问。",
			"unknown-field": "提交了未知字段，请刷新页面重试。",
			"bad-json": "宿主没能解析这次请求，请重试一次。"
		};
		const NETWORK_TEXT = "宿主路由未就绪，可能需要重启 DSH 才能启用本页。";

		const S = {
			panel: {
				display: "flex",
				flexDirection: "column",
				gap: "8px",
				padding: "10px 12px",
				borderRadius: "8px",
				border: "1px solid rgba(127,127,127,0.24)",
				background: "rgba(127,127,127,0.06)",
				color: "currentColor",
				fontSize: "12px",
				lineHeight: 1.4,
				maxWidth: "760px",
				boxSizing: "border-box"
			},
			// 设置页的一级 section 自带容器与内边距，这里只去掉卡片外框，其余排版不变。
			embedPanel: {
				display: "flex",
				flexDirection: "column",
				gap: "8px",
				padding: "0",
				border: "none",
				background: "transparent",
				color: "currentColor",
				fontSize: "12px",
				lineHeight: 1.4,
				maxWidth: "760px",
				boxSizing: "border-box"
			},
			head: { display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" },
			title: { fontSize: "13px", fontWeight: 600 },
			muted: { opacity: 0.62, fontSize: "11px" },
			group: {
				display: "flex",
				flexDirection: "column",
				gap: "5px",
				paddingTop: "5px",
				borderTop: "1px solid rgba(127,127,127,0.16)"
			},
			groupTitle: { fontSize: "11px", fontWeight: 600, opacity: 0.62, letterSpacing: "0.02em" },
			row: { display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" },
			label: { flex: "0 0 66px", fontSize: "11px", opacity: 0.72 },
			input: {
				flex: "1 1 200px",
				minWidth: "140px",
				padding: "3px 7px",
				borderRadius: "5px",
				border: "1px solid rgba(127,127,127,0.3)",
				background: "rgba(127,127,127,0.08)",
				color: "inherit",
				font: "inherit",
				fontSize: "12px",
				boxSizing: "border-box"
			},
			code: {
				flex: "1 1 260px",
				minWidth: "180px",
				padding: "3px 7px",
				borderRadius: "5px",
				border: "1px solid rgba(127,127,127,0.2)",
				background: "rgba(127,127,127,0.1)",
				fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
				fontSize: "11px",
				wordBreak: "break-all",
				cursor: "text",
				userSelect: "all"
			},
			button: {
				padding: "3px 12px",
				borderRadius: "5px",
				border: "1px solid transparent",
				background: "rgba(80,130,255,0.85)",
				color: "#fff",
				font: "inherit",
				fontSize: "12px",
				cursor: "pointer"
			},
			ghost: {
				padding: "3px 9px",
				borderRadius: "5px",
				border: "1px solid rgba(127,127,127,0.3)",
				background: "transparent",
				color: "inherit",
				font: "inherit",
				fontSize: "12px",
				cursor: "pointer"
			},
			badge: {
				padding: "0 6px",
				borderRadius: "999px",
				fontSize: "10px",
				border: "1px solid rgba(127,127,127,0.3)"
			},
			// 输入框工具行里的图标按钮。尺寸对齐宿主的图标按钮（28px 见方），
			// 悬停背景与宿主的 interactive-bg-hover 一致，和旁边的模型选择器齐高。
			iconButton: {
				display: "inline-flex",
				alignItems: "center",
				justifyContent: "center",
				width: "24px",
				height: "24px",
				padding: 0,
				flex: "0 0 auto",
				borderRadius: "var(--dsw-radius-sm, 6px)",
				border: "none",
				background: "transparent",
				cursor: "pointer"
			},
			iconButtonHover: {
				background: "var(--dsw-alias-interactive-bg-hover, rgba(127,127,127,0.12))"
			},
			// 插槽根节点：只作为定位锚点，本身不占位（绝对定位由 DOCK_CSS 施加）。
			dockSlot: { display: "inline-flex", alignItems: "center" }
		};

		const h = react.createElement;

		// ——— 端点访问：只碰本插件一个路由，全部 same-origin ———

		async function readConfig() {
			const response = await fetch(CONFIG_URL, {
				method: "GET",
				credentials: "same-origin",
				headers: { accept: "application/json" }
			});
			if (!response.ok) throw new Error("config-http-" + response.status);
			const data = await response.json();
			if (!data || data.ok !== true) throw new Error("config-bad-body");
			return data;
		}

		async function saveConfig(patch) {
			const response = await fetch(CONFIG_URL, {
				method: "POST",
				credentials: "same-origin",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(patch)
			});
			let data = null;
			try {
				data = await response.json();
			} catch (error) {
				data = null;
			}
			if (response.ok && data && data.ok === true) return { ok: true, data: data };
			return {
				ok: false,
				status: response.status,
				code: data && typeof data.error === "string" ? data.error : null,
				message: data && typeof data.message === "string" ? data.message : null
			};
		}

		function randomToken() {
			const bytes = new Uint8Array(18);
			try {
				window.crypto.getRandomValues(bytes);
			} catch (error) {
				for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
			}
			let text = "";
			for (let i = 0; i < bytes.length; i++) text += bytes[i].toString(16).padStart(2, "0");
			return text;
		}

		function randomPassword() {
			const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
			const bytes = new Uint8Array(20);
			try {
				window.crypto.getRandomValues(bytes);
			} catch (error) {
				for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
			}
			let text = "";
			for (let i = 0; i < bytes.length; i++) text += alphabet[bytes[i] % alphabet.length];
			return text;
		}

		function noticeStyle(tone) {
			const palette = {
				ok: "rgba(60,160,90,0.16)",
				error: "rgba(200,70,70,0.16)",
				note: "rgba(127,127,127,0.14)"
			};
			return {
				padding: "4px 8px",
				borderRadius: "5px",
				fontSize: "11px",
				background: palette[tone] || palette.note,
				wordBreak: "break-word"
			};
		}

		function copyText(text, done) {
			try {
				if (navigator.clipboard && navigator.clipboard.writeText) {
					navigator.clipboard.writeText(text).then(
						() => done(true),
						() => done(false)
					);
					return;
				}
			} catch (error) {
				// 落到下面的兜底路径
			}
			try {
				const area = document.createElement("textarea");
				area.value = text;
				area.setAttribute("readonly", "");
				area.style.position = "fixed";
				area.style.opacity = "0";
				document.body.appendChild(area);
				area.select();
				const ok = document.execCommand("copy");
				document.body.removeChild(area);
				done(ok);
			} catch (error) {
				done(false);
			}
		}

		function Copyable(props) {
			const [label, setLabel] = react.useState("复制");
			const value = props.value || "";
			return h(
				"div",
				{ style: S.row },
				h("span", { style: S.label }, props.label),
				h("code", { style: S.code, title: value }, value || "—"),
				h(
					"button",
					{
						type: "button",
						style: S.ghost,
						disabled: !value,
						onClick: () => {
							copyText(value, (ok) => {
								setLabel(ok ? "已复制" : "复制失败");
								window.setTimeout(() => setLabel("复制"), 1600);
							});
						}
					},
					label
				)
			);
		}

		function RemoteGatewayPanel(props) {
			const embed = Boolean(props && props.embed);
			const rootStyle = embed ? S.embedPanel : S.panel;
			const [snapshot, setSnapshot] = react.useState(null);
			const [loading, setLoading] = react.useState(true);
			const [loadError, setLoadError] = react.useState(null);
			const [busy, setBusy] = react.useState(false);
			const [notice, setNotice] = react.useState(null);

			const [username, setUsername] = react.useState("");
			const [password, setPassword] = react.useState("");
			const [token, setToken] = react.useState("");
			const [publicUrl, setPublicUrl] = react.useState("");
			const [cookieDays, setCookieDays] = react.useState("30");
			const [port, setPort] = react.useState("3080");
			const [listen, setListen] = react.useState("0.0.0.0");
			const [switchMode, setSwitchMode] = react.useState("local");
			const [confirmToggle, setConfirmToggle] = react.useState(true);
			const [remotePicker, setRemotePicker] = react.useState(true);
			const [browseRoot, setBrowseRoot] = react.useState("");

			const applySnapshot = react.useCallback((data) => {
				setSnapshot(data);
				const settings = (data && data.settings) || {};
				setUsername(settings.username || "");
				setPassword("");
				setToken(settings.accessToken || "");
				setPublicUrl(settings.publicUrl || "");
				setCookieDays(String(settings.cookieDays == null ? 30 : settings.cookieDays));
				// 输入框回显的是「配置值」，不是「当前实际监听的端口」：改了端口但未重启时，
				// 实际监听仍是旧端口，用 boundPort 回显会让人以为改动没保存。
				setPort(String(settings.port == null ? 3080 : settings.port));
				setListen(settings.listen || "0.0.0.0");
				setSwitchMode(settings.switchMode === "always" || settings.switchMode === "never" ? settings.switchMode : "local");
				setConfirmToggle(settings.confirmToggle !== false);
				setRemotePicker(settings.remotePicker !== false);
				setBrowseRoot(settings.browseRoot || "");
			}, []);

			const load = react.useCallback(() => {
				setLoading(true);
				setLoadError(null);
				readConfig().then(
					(data) => {
						applySnapshot(data);
						setLoading(false);
					},
					(error) => {
						setLoadError(NETWORK_TEXT);
						setLoading(false);
						void error;
					}
				);
			}, [applySnapshot]);

			react.useEffect(() => {
				load();
			}, [load]);

			const submit = () => {
				if (busy) return;
				const patch = {};
				const settings = (snapshot && snapshot.settings) || {};
				if (username !== (settings.username || "")) patch.username = username;
				if (password) patch.password = password;
				if (token !== (settings.accessToken || "")) patch.accessToken = token;
				if (publicUrl !== (settings.publicUrl || "")) patch.publicUrl = publicUrl;
				const days = Math.trunc(Number(cookieDays));
				if (Number.isFinite(days) && days !== settings.cookieDays) patch.cookieDays = days;
				const portNumber = Math.trunc(Number(port));
				const runtimePort = (snapshot && snapshot.runtime && snapshot.runtime.boundPort) || settings.port;
				if (Number.isFinite(portNumber) && portNumber !== runtimePort) patch.port = portNumber;
				if (listen !== settings.listen) patch.listen = listen;
				if (switchMode !== (settings.switchMode || "local")) patch.switchMode = switchMode;
				if (confirmToggle !== (settings.confirmToggle !== false)) patch.confirmToggle = confirmToggle;
				if (remotePicker !== (settings.remotePicker !== false)) patch.remotePicker = remotePicker;
				if (browseRoot.trim() !== (settings.browseRoot || "")) patch.browseRoot = browseRoot.trim();

				if (Object.keys(patch).length === 0) {
					setNotice({ tone: "note", text: "没有改动。" });
					return;
				}

				setBusy(true);
				setNotice(null);
				saveConfig(patch).then(
					(result) => {
						setBusy(false);
						if (!result.ok) {
							const text = ERROR_TEXT[result.code] || result.message || "保存失败（HTTP " + result.status + "）。";
							setNotice({ tone: "error", text: text });
							return;
						}
						const data = result.data;
						applySnapshot(data.config);
						setNotice(
							data.restartRequired
								? { tone: "note", text: "已保存。端口/监听地址的改动需要重启 DSH 后生效，其余设置已即时生效。" }
								: { tone: "ok", text: "已保存，设置已即时生效。" }
						);
					},
					(error) => {
						setBusy(false);
						setNotice({ tone: "error", text: NETWORK_TEXT });
						void error;
					}
				);
			};

			if (loading && snapshot === null) {
				return h("div", { style: rootStyle }, h("div", { style: S.muted }, "正在读取网关状态…"));
			}

			if (snapshot === null) {
				return h(
					"div",
					{ style: rootStyle },
					h("div", { style: S.head }, h("span", { style: S.title }, "远程访问网关")),
					h("div", { style: noticeStyle("note") }, loadError || NETWORK_TEXT),
					h("div", { style: S.row }, h("button", { type: "button", style: S.ghost, onClick: load }, "重试"))
				);
			}

			const runtime = snapshot.runtime || {};
			const settings = snapshot.settings || {};
			const listening = runtime.listening === true;
			const loginUrl = runtime.loginUrl || "";

			const targetText = (settings.listen || "?") + ":" + (runtime.boundPort || settings.port || "?") +
				" → 宿主 :" + (runtime.upstreamPort == null ? "?" : runtime.upstreamPort);

			return h(
				"div",
				{ style: rootStyle },
				h(
					"div",
					{ style: S.head },
					h("span", { style: S.title }, "远程访问网关"),
					h(
						"span",
						{ style: Object.assign({}, S.badge, { borderColor: listening ? "rgba(60,160,90,0.6)" : "rgba(200,70,70,0.6)" }) },
						listening ? "监听中" : "未监听"
					),
					h("span", { style: S.muted }, targetText)
				),

				// 组一：对外可访问的地址。只读项只在确实有值时出现，避免占一行空白。
				h(
					"div",
					{ style: S.group },
					h("div", { style: S.groupTitle }, "访问地址"),
					h(
						"div",
						{ style: S.row },
						h("span", { style: S.label }, "对外地址"),
						h("input", {
							style: S.input,
							value: publicUrl,
							placeholder: "https://dsh.example.com/",
							title: "路由器或隧道对外暴露的完整地址，含协议与端口",
							onChange: (event) => setPublicUrl(event.target.value)
						})
					),
					h(
						"div",
						{ style: S.row },
						h("span", { style: S.label }, "固定 token"),
						h("input", {
							style: S.input,
							value: token,
							placeholder: "留空则只用用户名密码登录",
							title: "访问对外地址加 ?token=该值可免密登录，留空表示不开启",
							onChange: (event) => setToken(event.target.value)
						}),
						h(
							"button",
							{
								type: "button",
								style: S.ghost,
								onClick: () => setToken(randomToken())
							},
							"随机生成"
						)
					),
					loginUrl
						? h(Copyable, { label: "免密链接", value: loginUrl })
						: null
				),

				// 组二：登录凭据。
				h(
					"div",
					{ style: S.group },
					h("div", { style: S.groupTitle }, "登录凭据"),
					h(
						"div",
						{ style: S.row },
						h("span", { style: S.label }, "用户名"),
						h("input", {
							style: S.input,
							value: username,
							placeholder: "dsh",
							onChange: (event) => setUsername(event.target.value)
						})
					),
					h(
						"div",
						{ style: S.row },
						h("span", { style: S.label }, "密码"),
						h("input", {
							style: S.input,
							type: "password",
							value: password,
							placeholder: settings.hasPassword ? "已设置（留空表示不改）" : "尚未设置",
							onChange: (event) => setPassword(event.target.value)
						}),
						h(
							"button",
							{
								type: "button",
								style: S.ghost,
								onClick: () => {
									const generated = randomPassword();
									setPassword(generated);
									setNotice({ tone: "note", text: "已生成新密码：" + generated + "（点保存后生效，请立刻记下来）" });
								}
							},
							"随机生成"
						)
					),
					h(
						"div",
						{ style: S.row },
						h("span", { style: S.label }, "保持天数"),
						h("input", {
							style: S.input,
							type: "number",
							min: 1,
							max: 3650,
							value: cookieDays,
							title: "浏览器记住登录状态的天数，1–3650",
							onChange: (event) => setCookieDays(event.target.value)
						}),
						h("span", { style: S.muted }, "天")
					)
				),

				// 组三：监听位置。端口与监听地址改动后要重启 DSH 才生效。
				h(
					"div",
					{ style: S.group },
					h("div", { style: S.groupTitle }, "监听"),
					h(
						"div",
						{ style: S.row },
						h("span", { style: S.label }, "监听地址"),
						h("input", {
							style: S.input,
							value: listen,
							placeholder: "0.0.0.0",
							title: "网关绑定的本机地址，路由器或隧道应指向这里",
							onChange: (event) => setListen(event.target.value)
						})
					),
					h(
						"div",
						{ style: S.row },
						h("span", { style: S.label }, "端口"),
						h("input", {
							style: S.input,
							type: "number",
							min: 1024,
							max: 65535,
							value: port,
							title: "路由器或隧道指向这个端口；修改后需重启 DSH",
							onChange: (event) => setPort(event.target.value)
						})
					)
				),

				// 组四：输入框下方的那个开关怎么显示、点了要不要确认。
				h(
					"div",
					{ style: S.group },
					h("div", { style: S.groupTitle }, "输入框开关"),
					h(
						"div",
						{ style: S.row },
						h("span", { style: S.label }, "显示范围"),
						h(
							"select",
							{
								style: S.input,
								value: switchMode,
								title: "仅本机＝只有从 127.0.0.1 / localhost 访问 DSH 时才显示这个开关",
								onChange: (event) => setSwitchMode(event.target.value)
							},
							h("option", { value: "local" }, "仅本机访问时显示"),
							h("option", { value: "always" }, "始终显示"),
							h("option", { value: "never" }, "不显示")
						)
					),
					h(
						"div",
						{ style: S.row },
						h("span", { style: S.label }, "二次确认"),
						h("input", {
							type: "checkbox",
							checked: confirmToggle,
							title: "开启后，点一下只是待确认，再点一下才真正切换——触屏设备上防止误触",
							onChange: (event) => setConfirmToggle(Boolean(event.target.checked))
						}),
						h("span", { style: S.muted }, "点击后需再点一次才切换，防误触")
					)
				),

				// 组五：远程访问时，「创建工作区」的目录选择走哪条路。
				h(
					"div",
					{ style: S.group },
					h("div", { style: S.groupTitle }, "远程目录浏览"),
					h(
						"div",
						{ style: S.row },
						h("span", { style: S.label }, "接管选择"),
						h("input", {
							type: "checkbox",
							checked: remotePicker,
							title: "开启后，远程浏览器点「创建工作区」会弹出网页内的目录树；关闭则仍调用主机的系统对话框（弹在主机屏幕上，远程看不见）",
							onChange: (event) => setRemotePicker(Boolean(event.target.checked))
						}),
						h("span", { style: S.muted }, "远程用自己的目录树，本机仍用系统对话框")
					),
					h(
						"div",
						{ style: S.row },
						h("span", { style: S.label }, "浏览根"),
						h("input", {
							style: S.input,
							value: browseRoot,
							placeholder: "留空表示当前用户主目录",
							title: "远程只能在这个目录之内浏览与新建，越界一律拒绝",
							onChange: (event) => setBrowseRoot(event.target.value)
						})
					)
				),

				notice === null
					? null
					: h(
							"div",
							{ style: noticeStyle(notice.tone), role: notice.tone === "error" ? "alert" : "status" },
							notice.text
						),

				h(
					"div",
					{ style: S.row },
					h("button", { type: "button", style: S.button, disabled: busy, onClick: submit }, busy ? "保存中…" : "保存"),
					h("button", { type: "button", style: S.ghost, disabled: busy, onClick: load }, "刷新"),
					h("span", { style: S.muted }, "端口/监听地址改动需重启 DSH")
				)
			);
		}

		// 设置面板导航里的一级条目。设置页内容区自带标题与滚动容器，
		// 所以这里只渲染去掉外框的同一个面板。
		function RemoteGatewaySection() {
			return h(RemoteGatewayPanel, { embed: true });
		}

		// 宿主内置组件（图标、Menu、Modal）都从 ui-primitives 取。
		// 取不到时各自降级，不让整个条目挂掉：图标回退内联 SVG，菜单回退成直接切换。
		let primitives = null;
		let primitivesResolved = false;
		function ui() {
			if (!primitivesResolved) {
				primitivesResolved = true;
				try {
					primitives = require("@deepseek-ai/dsh-client-ui-primitives");
				} catch (error) {
					primitives = null;
				}
			}
			return primitives;
		}

		// 宿主的 composer dock 是居中容器，插槽条目本身到不了右端。
		// 这里只注入一条作用域很窄的样式（选择器都锚在 data-composer-dock 与
		// 本条目自己的 data 属性上），把容器撑满、把本条目绝对定位到右端；
		// 绝对定位不参与 flex 布局，宿主的 ActivityPill / UsagePill / ContextMeter 位置不变。
		function installDockStyle() {
			if (typeof document === "undefined" || !document || !document.head || typeof document.createElement !== "function") {
				return function () {};
			}
			const existing = document.getElementById(STYLE_ID);
			if (existing !== null) return function () {};
			const style = document.createElement("style");
			style.id = STYLE_ID;
			style.textContent = DOCK_CSS;
			document.head.appendChild(style);
			return function () {
				if (style.parentNode) style.parentNode.removeChild(style);
			};
		}

		// 宿主导出里按名字取一个组件；没有就返回 null，由调用方决定降级方式。
		function hostComponent(name) {
			const api = ui();
			const component = api && api[name];
			return typeof component === "function" ? component : null;
		}

		// 设置导航图标与输入框里的入口图标共用地球图标。优先取宿主内置的
		// IconGlobeOutlineMedium（描边粗细、留白与旁边的「账户」「模型」天然一致），
		// 若宿主没有导出它（版本差异），回退到同形的内联 SVG，画面不变。
		// 宿主的图标工厂只接受 size/className，颜色靠外层 span 的 currentColor 继承。
		function globeIcon(size) {
			const Icon = hostComponent("IconGlobeOutlineMedium");
			if (Icon !== null) {
				return h(Icon, { size: size });
			}
			return h(
				"svg",
				{
					width: size,
					height: size,
					viewBox: "0 0 16 16",
					fill: "none",
					stroke: "currentColor",
					strokeWidth: 1.3,
					"aria-hidden": "true",
					style: { flex: "0 0 auto", display: "block" }
				},
				h("path", {
					d: "M7.99986 14.0887C11.3626 14.0887 14.0886 11.3627 14.0886 7.99998C14.0886 4.63727 11.3626 1.91125 7.99986 1.91125C4.63715 1.91125 1.91113 4.63727 1.91113 7.99998C1.91113 11.3627 4.63715 14.0887 7.99986 14.0887Z"
				}),
				h("path", { d: "M2.34619 8H13.6538", strokeLinecap: "square" }),
				h("path", {
					d: "M7.99976 14.0889C9.23509 14.0889 10.1743 11.3629 10.1743 8.00006C10.1743 4.63739 9.23509 1.91138 7.99976 1.91138"
				}),
				h("path", {
					d: "M7.99973 14.0889C6.76445 14.0889 5.8252 11.3629 5.8252 8.00006C5.8252 4.63739 6.76445 1.91138 7.99973 1.91138"
				})
			);
		}

		// 设置面板左侧导航的地球图标，宿主按 row id 匹配本条目。
		function RemoteGatewayIcon(props) {
			const size = (props && props.size) || 16;
			return globeIcon(size);
		}

		// 输入框下方那行最右端的地球图标：图标颜色就是开关状态
		// （绿=已开启且在监听，灰=已关闭，橙=已开启但没监听，半透明灰=首帧还没读到）。
		// 点击直接切换开关，不弹菜单；真正启停由服务端在保存配置时就地完成，不需要重启 DSH。
		// 悬停提示按开关的两种语义状态给，未监听与读取中各给一句更具体的。
		const STATUS_TITLE = {
			on: "远程访问已开启",
			off: "远程访问已关闭",
			warn: "远程访问已开启，但网关没有监听",
			idle: "正在读取远程访问状态"
		};
		// 关闭态用灰色（不用红色）：红在宿主里表示危险操作，这里只是"没开"。
		const STATUS_COLOR = { on: "#3fb950", off: "rgba(127,127,127,0.55)", warn: "#d29922", idle: "rgba(127,127,127,0.55)" };
		// 待确认态用琥珀色，和"已开启但没监听"同色但语义由提示文案区分。
		const ARMED_COLOR = "#d29922";
		// 确认窗口：点第一下之后这么多毫秒内再点才算确认，超时自动撤销。
		const CONFIRM_WINDOW_MS = 4000;

		// 当前页面是不是从本机打开的。回环地址一律算本机；
		// 局域网 IP、反向代理域名、隧道域名都算远程。
		// 兜底判断：只用在这一版服务端没有给出 local 字段时。
		// 原则是"宁可显示也不误藏"——只有明确认得是外部地址才判远程。
		function isLocalAccess() {
			try {
				const location = window.location || {};
				const protocol = String(location.protocol || "").toLowerCase();
				const host = String(location.hostname || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
				// 非 http(s) 协议（Electron 自定义协议、file: 等）都是本机窗口。
				if (protocol !== "http:" && protocol !== "https:") return true;
				// 拿不到主机名时不做判断，按本机处理。
				if (!host) return true;
				if (host === "localhost" || host === "::1" || host === "0.0.0.0") return true;
				// 127.0.0.0/8 全是回环。
				if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
				return false;
			} catch {
				return true;
			}
		}

		function gatewayStatus(state) {
			if (state.loading) return "idle";
			if (!state.enabled) return "off";
			return state.listening ? "on" : "warn";
		}

		function RemoteGatewayEntry() {
			const [state, setState] = react.useState({
				loading: true,
				enabled: true,
				listening: false,
				hasCredential: true,
				switchMode: "local",
				confirmToggle: true,
				local: true
			});
			const [busy, setBusy] = react.useState(false);
			const [hover, setHover] = react.useState(false);
			const [error, setError] = react.useState(null);
			// 二次确认：armed 为真表示"已点第一下、等待确认"。
			const [armed, setArmed] = react.useState(false);

			const refresh = react.useCallback(() => {
				readConfig().then(
					(data) => {
						const settings = (data && data.settings) || {};
						const runtime = (data && data.runtime) || {};
						setState({
							loading: false,
							enabled: settings.enabled !== false,
							listening: runtime.listening === true,
							hasCredential: Boolean(settings.hasPassword || settings.accessToken),
							switchMode: settings.switchMode === "always" || settings.switchMode === "never" ? settings.switchMode : "local",
							confirmToggle: settings.confirmToggle !== false,
							// local 由服务端按请求来源判定（-1 表示拿不到，交给浏览器侧兜底）。
							local: typeof data.local === "boolean" ? data.local : isLocalAccess()
						});
					},
					() => {
						// 读不到配置（未登录、宿主路由未就绪）时不让开关变成危险的空操作。
						setState({
							loading: false,
							enabled: true,
							listening: false,
							hasCredential: true,
							switchMode: "local",
							confirmToggle: true,
							local: isLocalAccess()
						});
					}
				);
			}, []);

			react.useEffect(() => {
				refresh();
			}, [refresh]);

			// 待确认状态最多维持 CONFIRM_WINDOW_MS，避免一直挂在"再点一次"上。
			react.useEffect(() => {
				if (!armed) return undefined;
				const timer = window.setTimeout(() => setArmed(false), CONFIRM_WINDOW_MS);
				return () => window.clearTimeout(timer);
			}, [armed]);

			const commitToggle = react.useCallback(() => {
				setBusy(true);
				setError(null);
				setArmed(false);
				saveConfig({ enabled: !state.enabled }).then((result) => {
					setBusy(false);
					if (!result.ok) {
						setError(result.message || NETWORK_TEXT);
						return;
					}
					refresh();
				});
			}, [state.enabled, refresh]);

			const toggle = react.useCallback(() => {
				if (busy || state.loading) return;
				// 需要二次确认时，第一下只进入待确认，不真的切换。
				if (state.confirmToggle && !armed) {
					setArmed(true);
					return;
				}
				commitToggle();
			}, [busy, state.loading, state.confirmToggle, armed, commitToggle]);

			// 按显示范围决定渲染不渲染。注意这是组件内部判断而非不注册槽位，
			// 因为显示范围可以随时改，注册一次就能跟着配置走。
			// state.local 由服务端按请求来源判定，比浏览器侧猜 hostname 可靠。
			if (state.switchMode === "never") return null;
			if (state.switchMode === "local" && state.local === false) return null;

			const status = gatewayStatus(state);
			const on = state.enabled;
			// 悬停提示：默认两句由开关状态决定；异常与读取中给更具体的说明。
			let title = STATUS_TITLE[status];
			if (error) title = error;
			else if (status === "warn") {
				title = state.hasCredential
					? "远程访问已开启，但网关没有监听（端口被占用或启动失败）"
					: "远程访问已开启，但还没设置密码或固定 token，网关不会监听";
			}
			if (busy) title = "正在切换远程访问…";
			else if (armed) title = on ? "再点一次确认关闭远程访问" : "再点一次确认开启远程访问";

			const activeColor = armed ? ARMED_COLOR : STATUS_COLOR[status];

			const buttonProps = {
				type: "button",
				style: hover && !state.loading ? Object.assign({}, S.iconButton, S.iconButtonHover) : S.iconButton,
				disabled: state.loading,
				"aria-label": title,
				"aria-pressed": on,
				// 直接切换（或进入待确认），不弹菜单。
				onClick: toggle,
				onMouseEnter: function () {
					setHover(true);
				},
				onMouseLeave: function () {
					setHover(false);
				}
			};

			// 悬停提示优先用宿主的 Tooltip，和下方这行自带的统计 pill 观感一致；
			// 拿不到时才退回原生 title（Electron 里延迟长、样式也不统一）。
			const Tooltip = hostComponent("Tooltip");
			if (Tooltip === null) buttonProps.title = title;

			const button = h(
				"button",
				buttonProps,
				// 颜色挂在 span 上，图标内部走 currentColor 继承。
				h("span", { style: { display: "inline-flex", color: activeColor } }, globeIcon(16))
			);

			// 这一行贴在视口底部，提示往上弹；dock 容器会裁切子元素，所以 portal 到 body。
			const trigger = Tooltip === null
				? button
				: h(Tooltip, { label: title, side: "top", portal: true, maxWidth: 320 }, button);

			// 根节点带 data 属性，交给 DOCK_CSS 定位到那一行的右端。
			const slotProps = { style: S.dockSlot };
			slotProps[ENTRY_ATTR] = "";

			return h("span", slotProps, trigger);
		}

		const name = "reverse-proxy-gateway";
		// 只声明 slots：卡片只挂一个槽位，不需要 locale / configForms。
		const inject = ["slots"];

		let contributions = [];

		let dockStyleRemove = null;

		function disposeContributions() {
			const pending = contributions;
			contributions = [];
			for (let i = 0; i < pending.length; i++) {
				try {
					pending[i]();
				} catch (error) {
					console.warn("reverse-proxy-gateway: 旧条目卸载失败", error);
				}
			}
			if (dockStyleRemove !== null) {
				try {
					dockStyleRemove();
				} catch (error) {
					console.warn("reverse-proxy-gateway: 注入样式移除失败", error);
				}
				dockStyleRemove = null;
			}
		}

		function apply(ctx) {
			try {
				if (!react || typeof react.createElement !== "function") {
					console.warn("reverse-proxy-gateway: 客户端没有 react，插件卡片未注册");
					return;
				}
				if (!ctx || !ctx.slots || typeof ctx.slots.inject !== "function" || typeof ctx.slots.register !== "function") {
					console.warn("reverse-proxy-gateway: 客户端没有 slots 服务，插件卡片未注册");
					return;
				}

				const entry = {
					name: BUNDLE_SLOT,
					key: NS,
					inject: function () {
						return {};
					}
				};

				disposeContributions();

				let registration = null;
				try {
					registration = ctx.slots.inject(BUNDLE_SLOT, function () {
						return ctx.slots.register(entry, RemoteGatewayPanel);
					});
				} catch (error) {
					registration = null;
					console.warn("reverse-proxy-gateway: " + BUNDLE_SLOT + " 条目注册失败", error);
				}
				if (typeof registration === "function") contributions.push(registration);

				// 设置面板左侧导航的一级条目。inject 是惰性的：只有设置面板被打开、
				// 该槽位确实被消费时才注册，未打开设置页不产生任何渲染开销。
				let sectionRegistration = null;
				try {
					sectionRegistration = ctx.slots.inject(SETTINGS_SECTION_SLOT, function () {
						return ctx.slots.register(
							{
								name: SETTINGS_SECTION_SLOT,
								id: NS,
								order: 50,
								// 导航文案用 thunk，语言切换时设置壳会重新解析并重绘。
								label: function () {
									return "远程访问";
								},
								inject: function () {
									return {};
								}
							},
							RemoteGatewaySection
						);
					});
				} catch (error) {
					sectionRegistration = null;
					console.warn("reverse-proxy-gateway: " + SETTINGS_SECTION_SLOT + " 条目注册失败", error);
				}
				if (typeof sectionRegistration === "function") contributions.push(sectionRegistration);

				// 设置面板左侧导航的地球图标，id 必须与下面的 section id 相同。
				let iconRegistration = null;
				try {
					iconRegistration = ctx.slots.inject(SECTION_ICON_SLOT, function () {
						return ctx.slots.register({ name: SECTION_ICON_SLOT, id: NS }, RemoteGatewayIcon);
					});
				} catch (error) {
					iconRegistration = null;
					console.warn("reverse-proxy-gateway: " + SECTION_ICON_SLOT + " 条目注册失败", error);
				}
				if (typeof iconRegistration === "function") contributions.push(iconRegistration);

				// 输入框下方那一行右端的图标入口，跟随会话区渲染。
				// 定位到右端靠这条注入样式实现，所以注册前先装好。
				try {
					dockStyleRemove = installDockStyle();
				} catch (error) {
					dockStyleRemove = null;
					console.warn("reverse-proxy-gateway: 注入样式失败", error);
				}

				let entryRegistration = null;
				try {
					entryRegistration = ctx.slots.inject(COMPOSER_DOCK_SLOT, function () {
						return ctx.slots.register(
							{
								name: COMPOSER_DOCK_SLOT,
								id: NS,
								order: 50,
								label: function () {
									return "远程访问";
								},
								inject: function () {
									return {};
								}
							},
							RemoteGatewayEntry
						);
					});
				} catch (error) {
					entryRegistration = null;
					console.warn("reverse-proxy-gateway: " + COMPOSER_DOCK_SLOT + " 条目注册失败", error);
				}
				if (typeof entryRegistration === "function") contributions.push(entryRegistration);

				return disposeContributions;
			} catch (error) {
				console.warn("reverse-proxy-gateway: 插件卡片注册失败", error);
				return undefined;
			}
		}

		exports.apply = apply;
		exports.inject = inject;
		exports.name = name;
		return module.exports;
	}
});
