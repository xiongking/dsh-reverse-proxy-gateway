// dsh-reverse-proxy-gateway — 远程目录浏览器。
//
// 这个文件不是插件 bundle，而是网关在转发宿主页面时插进 <head> 的同步脚本。
// 它只做一件事：在 __DSH_DIRECTORY_PICKER__ 尚未定义时接管它，
// 让「创建工作区」在远程浏览器里弹出自绘目录树，而不是去调主机的系统对话框。
//
// 宿主前端读取这个全局对象的方式（见 dsh-client-ui-workspace）：
//   const desktop = globalThis.__DSH_DIRECTORY_PICKER__;
//   const pick = desktop === void 0 ? () => ctx.uiWorkspace.pickDirectory() : () => desktop.pick();
// 所以只要它存在且带 pick()，宿主就不会再走 directoryPicker/pick 那条 RPC。
//
// 约定：pick() 返回 Promise<string | null>，取消时为 null，与系统对话框一致。
(function () {
  'use strict';

  if (globalThis.__DSH_DIRECTORY_PICKER__) return;

  var API = '/__dshgw/fs';
  var NS = 'gw-picker';
  var STYLE_ID = NS + '-style';
  var current = null;

  var CSS = [
    '.' + NS + '-overlay{position:fixed;inset:0;z-index:2147483000;display:flex;align-items:center;',
    'justify-content:center;padding:24px;background:rgba(0,0,0,.55);font:13px/1.5 -apple-system,',
    'BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif}',
    '.' + NS + '{width:min(640px,100%);max-height:min(600px,100%);display:flex;flex-direction:column;',
    'border-radius:12px;overflow:hidden;background:#1b1e23;color:#e8e8ea;',
    'border:1px solid rgba(255,255,255,.12);box-shadow:0 24px 64px rgba(0,0,0,.5)}',
    '.' + NS + '-head{display:flex;align-items:center;gap:12px;padding:14px 16px;',
    'border-bottom:1px solid rgba(255,255,255,.08)}',
    '.' + NS + '-title{flex:1;font-weight:600;font-size:14px}',
    '.' + NS + '-x{appearance:none;border:0;background:transparent;color:inherit;opacity:.6;',
    'cursor:pointer;font-size:18px;line-height:1;padding:2px 6px;border-radius:6px}',
    '.' + NS + '-x:hover{opacity:1;background:rgba(255,255,255,.08)}',
    '.' + NS + '-crumbs{display:flex;flex-wrap:wrap;gap:2px;padding:10px 16px 6px;font-size:12px;opacity:.85}',
    '.' + NS + '-crumb{appearance:none;border:0;background:transparent;color:inherit;cursor:pointer;',
    'padding:2px 4px;border-radius:4px;font:inherit}',
    '.' + NS + '-crumb:hover{background:rgba(127,127,127,.2)}',
    '.' + NS + '-sep{opacity:.4;padding:2px 0}',
    '.' + NS + '-list{flex:1;overflow:auto;padding:4px 8px;min-height:180px}',
    '.' + NS + '-row{display:flex;align-items:center;gap:8px;width:100%;appearance:none;border:0;',
    'background:transparent;color:inherit;cursor:pointer;text-align:left;padding:8px 10px;',
    'border-radius:7px;font:inherit}',
    '.' + NS + '-row:hover{background:rgba(127,127,127,.16)}',
    '.' + NS + '-up{opacity:.75;margin-bottom:2px;border-bottom:1px solid rgba(127,127,127,.16);',
    'border-radius:7px 7px 0 0}',
    '.' + NS + '-up .' + NS + '-name{font-size:13px}',
    '.' + NS + '-icon{opacity:.55;flex:none}',
    '.' + NS + '-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
    '.' + NS + '-empty,.gw-picker-error{padding:24px 12px;text-align:center;opacity:.6}',
    '.' + NS + '-error{color:#ff8080;opacity:1}',
    '.' + NS + '-foot{display:flex;align-items:center;gap:8px;padding:12px 16px;',
    'border-top:1px solid rgba(255,255,255,.08)}',
    '.' + NS + '-path{flex:1;font-size:12px;opacity:.55;overflow:hidden;text-overflow:ellipsis;',
    'white-space:nowrap;direction:rtl;text-align:left}',
    '.' + NS + '-btn{appearance:none;border:1px solid rgba(255,255,255,.16);background:transparent;',
    'color:inherit;cursor:pointer;padding:7px 14px;border-radius:7px;font:inherit;white-space:nowrap}',
    '.' + NS + '-btn:hover{background:rgba(127,127,127,.18)}',
    '.' + NS + '-btn[data-primary]{background:#4b6cf7;border-color:#4b6cf7;color:#fff}',
    '.' + NS + '-btn[data-primary]:hover{background:#3f5ee0}',
    '.' + NS + '-btn:disabled{opacity:.45;cursor:default}',
    '.' + NS + '-new{display:none;gap:8px;padding:0 16px 12px}',
    '.' + NS + '-new[data-open]{display:flex}',
    '.' + NS + '-input{flex:1;appearance:none;border:1px solid rgba(127,127,127,.4);background:rgba(0,0,0,.2);',
    'color:inherit;padding:7px 10px;border-radius:7px;font:inherit;min-width:0}',
    '@media (prefers-color-scheme:light){.' + NS + '{background:#fff;color:#1c1c1e;',
    'border-color:rgba(0,0,0,.12);box-shadow:0 24px 64px rgba(0,0,0,.24)}',
    '.' + NS + '-head,.' + NS + '-foot{border-color:rgba(0,0,0,.08)}',
    '.' + NS + '-btn{border-color:rgba(0,0,0,.16)}',
    '.' + NS + '-input{background:#fff}}'
  ].join('');

  function injectStyle() {
    if (document.getElementById(STYLE_ID)) return;
    var style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = CSS;
    (document.head || document.documentElement).appendChild(style);
  }

  function h(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function call(url, options) {
    return fetch(url, options).then(function (response) {
      return response
        .json()
        .catch(function () {
          return {};
        })
        .then(function (body) {
          if (!response.ok || body.ok === false) {
            throw new Error(body.message || 'HTTP ' + response.status);
          }
          return body;
        });
    });
  }

  function open() {
    if (current) return current.promise;

    injectStyle();

    var settled = false;
    var resolveOuter;
    var promise = new Promise(function (resolve) {
      resolveOuter = resolve;
    });

    var state = { path: null, root: null, parent: null, entries: [], truncated: false };

    var overlay = h('div', NS + '-overlay');
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', '选择工作区目录');

    var panel = h('div', NS);
    overlay.appendChild(panel);

    var head = h('div', NS + '-head');
    head.appendChild(h('div', NS + '-title', '选择工作区目录'));
    var closeBtn = h('button', NS + '-x', '×');
    closeBtn.type = 'button';
    closeBtn.setAttribute('aria-label', '取消');
    closeBtn.addEventListener('click', function () {
      finish(null);
    });
    head.appendChild(closeBtn);
    panel.appendChild(head);

    var crumbs = h('div', NS + '-crumbs');
    panel.appendChild(crumbs);

    var list = h('div', NS + '-list');
    panel.appendChild(list);

    var newRow = h('div', NS + '-new');
    var input = h('input', NS + '-input');
    input.type = 'text';
    input.placeholder = '新文件夹名称';
    input.setAttribute('aria-label', '新文件夹名称');
    var createBtn = h('button', NS + '-btn', '创建');
    createBtn.type = 'button';
    createBtn.setAttribute('data-primary', '');
    newRow.appendChild(input);
    newRow.appendChild(createBtn);
    panel.appendChild(newRow);

    var foot = h('div', NS + '-foot');
    var newBtn = h('button', NS + '-btn', '新建文件夹');
    newBtn.type = 'button';
    var pathLabel = h('div', NS + '-path');
    var cancelBtn = h('button', NS + '-btn', '取消');
    cancelBtn.type = 'button';
    var pickBtn = h('button', NS + '-btn', '选择当前目录');
    pickBtn.type = 'button';
    pickBtn.setAttribute('data-primary', '');
    foot.appendChild(newBtn);
    foot.appendChild(pathLabel);
    foot.appendChild(cancelBtn);
    foot.appendChild(pickBtn);
    panel.appendChild(foot);

    function finish(value) {
      if (settled) return;
      settled = true;
      document.removeEventListener('keydown', onKey, true);
      if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
      current = null;
      resolveOuter(value);
    }

    function onKey(event) {
      if (event.key !== 'Escape') return;
      // 新文件夹输入框开着时，Esc 只收起输入框，交给它自己的 keydown 处理。
      if (event.target === input && newRow.hasAttribute('data-open')) return;
      event.stopPropagation();
      finish(null);
    }

    function showError(message) {
      list.textContent = '';
      var box = h('div', NS + '-empty ' + NS + '-error', message);
      list.appendChild(box);
    }

    function renderCrumbs() {
      crumbs.textContent = '';
      if (!state.path || !state.root) return;
      var root = state.root;
      var rest = state.path === root ? '' : state.path.slice(root.length).replace(/^[\\/]+/, '');
      var parts = rest ? rest.split(/[\\/]+/) : [];
      var acc = root;

      var rootBtn = h('button', NS + '-crumb', root === '/' ? '/' : root.split(/[\\/]/).pop() || root);
      rootBtn.type = 'button';
      rootBtn.title = root;
      rootBtn.addEventListener('click', function () {
        load(root);
      });
      crumbs.appendChild(rootBtn);

      for (var i = 0; i < parts.length; i++) {
        if (!parts[i]) continue;
        acc = acc.replace(/[\\/]+$/, '') + '/' + parts[i];
        crumbs.appendChild(h('span', NS + '-sep', '/'));
        (function (target) {
          var btn = h('button', NS + '-crumb', parts[i]);
          btn.type = 'button';
          btn.title = target;
          btn.addEventListener('click', function () {
            load(target);
          });
          crumbs.appendChild(btn);
        })(acc);
      }
    }

    function renderList() {
      list.textContent = '';
      // 「上一级」放最前面：退到浏览根之后就没有了，不会越出根。
      if (state.parent) {
        var up = h('button', NS + '-row ' + NS + '-up');
        up.type = 'button';
        up.title = state.parent;
        up.appendChild(h('span', NS + '-icon', '↑'));
        up.appendChild(h('span', NS + '-name', '上一级'));
        up.addEventListener('click', function () {
          load(state.parent);
        });
        list.appendChild(up);
      }
      if (!state.entries.length) {
        if (state.parent) return;
        list.appendChild(h('div', NS + '-empty', '这个目录下没有子目录'));
        return;
      }
      state.entries.forEach(function (entry) {
        var row = h('button', NS + '-row');
        row.type = 'button';
        row.title = entry.path;
        row.appendChild(h('span', NS + '-icon', '📁'));
        row.appendChild(h('span', NS + '-name', entry.name));
        row.addEventListener('click', function () {
          load(entry.path);
        });
        list.appendChild(row);
      });
      if (state.truncated) {
        list.appendChild(h('div', NS + '-empty', '目录过多，只显示了前一部分'));
      }
    }

    function render() {
      renderCrumbs();
      renderList();
      pathLabel.textContent = state.path || '';
      pathLabel.title = state.path || '';
      pickBtn.disabled = !state.path;
      newBtn.disabled = !state.path;
    }

    function load(path) {
      list.textContent = '';
      list.appendChild(h('div', NS + '-empty', '正在读取…'));
      var url = API + '/list' + (path ? '?path=' + encodeURIComponent(path) : '');
      call(url).then(
        function (body) {
          if (settled) return;
          state.path = body.path;
          state.root = body.root;
          state.parent = body.parent;
          state.entries = Array.isArray(body.entries) ? body.entries : [];
          state.truncated = Boolean(body.truncated);
          render();
        },
        function (error) {
          if (settled) return;
          showError(error && error.message ? error.message : '读取目录失败');
        }
      );
    }

    function submitNewFolder() {
      var name = input.value.trim();
      if (!name) {
        input.focus();
        return;
      }
      createBtn.disabled = true;
      call(API + '/mkdir', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ path: state.path, name: name })
      }).then(
        function (body) {
          createBtn.disabled = false;
          input.value = '';
          newRow.removeAttribute('data-open');
          load(body.path);
        },
        function (error) {
          createBtn.disabled = false;
          showError(error && error.message ? error.message : '创建失败');
        }
      );
    }

    newBtn.addEventListener('click', function () {
      if (newRow.hasAttribute('data-open')) {
        newRow.removeAttribute('data-open');
      } else {
        newRow.setAttribute('data-open', '');
        input.focus();
      }
    });
    createBtn.addEventListener('click', submitNewFolder);
    input.addEventListener('keydown', function (event) {
      if (event.key === 'Enter') {
        event.preventDefault();
        submitNewFolder();
      } else if (event.key === 'Escape') {
        event.preventDefault();
        newRow.removeAttribute('data-open');
      }
    });
    cancelBtn.addEventListener('click', function () {
      finish(null);
    });
    pickBtn.addEventListener('click', function () {
      if (state.path) finish(state.path);
    });
    overlay.addEventListener('click', function (event) {
      if (event.target === overlay) finish(null);
    });

    document.addEventListener('keydown', onKey, true);
    (document.body || document.documentElement).appendChild(overlay);
    load(null);

    current = { promise: promise };
    return promise;
  }

  var api = {
    pick: function () {
      return open();
    }
  };

  try {
    Object.defineProperty(globalThis, '__DSH_DIRECTORY_PICKER__', {
      value: api,
      configurable: true,
      writable: false
    });
  } catch (error) {
    globalThis.__DSH_DIRECTORY_PICKER__ = api;
  }
})();
