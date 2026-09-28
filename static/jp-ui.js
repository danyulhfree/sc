/* jp-ui — shared behaviour for the jp panels (bilire, dy, sc, cr, fc2, fic).
   Source of truth: u/deploy/jp-ui/. Copies in each project are synced by sync.sh;
   edit here, never in a copy. No dependencies; exposes window.JPUI. */
(function () {
  'use strict';

  var root = document.documentElement;

  /* ---------- theme ---------- */
  // Pages also inline the first line of this in <head> so the theme is set before paint.
  var THEME_KEY = 'jp-theme';
  function storedTheme() { try { return localStorage.getItem(THEME_KEY) || ''; } catch (e) { return ''; } }
  function applyTheme(theme) {
    if (theme === 'light' || theme === 'dark') root.setAttribute('data-theme', theme);
    else root.removeAttribute('data-theme');
  }
  applyTheme(storedTheme());
  var THEME_LABEL = { '': '跟随系统', light: '浅色', dark: '深色' };
  function bindThemeToggle(button) {
    if (!button) return;
    var order = ['', 'light', 'dark'];
    function paint() {
      var t = storedTheme();
      button.textContent = t === 'dark' ? '☾' : t === 'light' ? '☀' : '◐';
      button.title = '主题：' + THEME_LABEL[t] + '（点击切换）';
      button.setAttribute('aria-label', button.title);
    }
    button.addEventListener('click', function () {
      var next = order[(order.indexOf(storedTheme()) + 1) % order.length];
      try { if (next) localStorage.setItem(THEME_KEY, next); else localStorage.removeItem(THEME_KEY); } catch (e) {}
      applyTheme(next);
      paint();
    });
    paint();
  }

  /* ---------- text helpers ---------- */
  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function bytes(n) {
    n = Number(n);
    if (!isFinite(n) || n < 0) return '—';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2)) + ' ' + units[i];
  }
  function duration(seconds) {
    seconds = Math.max(0, Math.floor(Number(seconds) || 0));
    var h = Math.floor(seconds / 3600), m = Math.floor(seconds % 3600 / 60), s = seconds % 60;
    var pad = function (v) { return (v < 10 ? '0' : '') + v; };
    return (h ? h + ':' + pad(m) : m) + ':' + pad(s);
  }
  function ago(date) {
    var t = date instanceof Date ? date.getTime() : typeof date === 'number' ? (date < 1e12 ? date * 1000 : date) : Date.parse(date);
    if (!isFinite(t)) return '—';
    var d = Math.round((Date.now() - t) / 1000);
    if (d < 5) return '刚刚';
    if (d < 60) return d + ' 秒前';
    if (d < 3600) return Math.floor(d / 60) + ' 分钟前';
    if (d < 86400) return Math.floor(d / 3600) + ' 小时前';
    return Math.floor(d / 86400) + ' 天前';
  }

  /* ---------- status vocabulary ---------- */
  // One table for every panel. tone: live | info | warn | danger | muted.
  var STATUS = {
    recording: ['录制中', 'live'], live: ['直播中', 'live'], public: ['直播中', 'live'], online: ['在线', 'live'],
    healthy: ['正常', 'live'], ok: ['正常', 'live'], success: ['成功', 'live'], completed: ['已完成', 'live'], uploaded: ['已上传', 'live'],
    connecting: ['连接中', 'info'], pending: ['检查中', 'info'], checking: ['检查中', 'info'], queued: ['排队中', 'info'],
    waiting: ['等待中', 'info'], starting: ['启动中', 'info'], uploading: ['上传中', 'info'], sending: ['上传中', 'info'],
    reconnecting: ['重连中', 'warn'], restarting: ['重连中', 'warn'], retrying: ['重试中', 'warn'], stalled: ['已停滞', 'warn'], stale: ['状态过期', 'warn'],
    private: ['私密秀', 'warn'], group: ['团体秀', 'warn'], group_show: ['团体秀', 'warn'], p2p: ['一对一', 'warn'], f2f_private: ['一对一私密', 'warn'],
    paid: ['付费直播', 'warn'], premium: ['付费秀', 'warn'], ticket: ['门票秀', 'warn'], ticket_show: ['门票秀', 'warn'], password: ['密码房', 'warn'],
    hidden: ['隐藏', 'muted'], away: ['暂离', 'muted'],
    groupshow: ['团体秀', 'warn'], virtualprivate: ['虚拟私密', 'warn'],
    uncertain: ['结果未确认', 'warn'], flood_lock: ['频率锁定', 'warn'], timeout: ['超时', 'warn'],
    configuration_error: ['配置错误', 'danger'],
    page_unavailable: ['暂时不可用', 'warn'], network: ['网络错误', 'warn'], invalid_response: ['响应异常', 'warn'],
    rate_limited: ['限流中', 'warn'], server_error: ['对方服务异常', 'warn'], cooldown: ['冷却中', 'warn'], backoff: ['退避中', 'warn'],
    not_found: ['找不到', 'danger'], blocked: ['被封禁', 'danger'], cloudflare_forbidden: ['被拦截', 'danger'],
    http_error: ['请求失败', 'danger'], auth_error: ['登录失效', 'danger'], failed: ['失败', 'danger'], error: ['错误', 'danger'],
    quarantined: ['已隔离', 'danger'],
    off: ['离线', 'muted'], offline: ['离线', 'muted'], idle: ['空闲', 'muted'], paused: ['已暂停', 'muted'],
    stopped: ['已停止', 'muted'], disabled: ['已停用', 'muted'], unknown: ['未知', 'muted']
  };
  var TONE_GROUP = { live: 'active', info: 'active', warn: 'problem', danger: 'problem', muted: 'idle' };
  function status(code) {
    var key = String(code == null ? '' : code).toLowerCase();
    var hit = STATUS[key];
    var tone = hit ? hit[1] : 'muted';
    return { code: key, label: hit ? hit[0] : (code || '未知'), tone: tone, group: TONE_GROUP[tone] };
  }
  function badge(code, extra) {
    var s = status(code);
    var el = document.createElement('span');
    el.className = 'jp-badge';
    el.dataset.tone = s.tone;
    el.textContent = s.label;
    el.title = extra ? s.label + ' · ' + extra : (s.code && s.code !== s.label ? s.code : s.label);
    return el;
  }

  /* ---------- toast ---------- */
  var toastHost = null;
  function toast(message, tone, ms) {
    if (!toastHost) {
      toastHost = document.createElement('div');
      toastHost.className = 'jp-toasts';
      toastHost.setAttribute('role', 'status');
      toastHost.setAttribute('aria-live', 'polite');
      document.body.appendChild(toastHost);
    }
    var el = document.createElement('div');
    el.className = 'jp-toast';
    if (tone) el.dataset.tone = tone;
    el.textContent = message;
    toastHost.appendChild(el);
    // Each toast owns its own timer, so a newer toast is never hidden by an older one.
    setTimeout(function () { el.remove(); }, ms || (tone === 'error' ? 6000 : 3200));
    while (toastHost.children.length > 3) toastHost.firstChild.remove();
    return el;
  }

  /* ---------- confirm dialog ---------- */
  function confirmDialog(opts) {
    opts = typeof opts === 'string' ? { message: opts } : (opts || {});
    return new Promise(function (resolve) {
      var dialog = document.createElement('dialog');
      dialog.className = 'jp-dialog jp';
      dialog.innerHTML =
        '<form method="dialog"><h3></h3><p></p><div class="jp-dialog-actions">' +
        '<button class="jp-btn" value="cancel" type="submit"></button>' +
        '<button class="jp-btn" value="ok" type="submit"></button></div></form>';
      dialog.querySelector('h3').textContent = opts.title || '请确认';
      dialog.querySelector('p').textContent = opts.message || '';
      var buttons = dialog.querySelectorAll('button');
      buttons[0].textContent = opts.cancelText || '取消';
      buttons[1].textContent = opts.confirmText || '确定';
      buttons[1].className = 'jp-btn ' + (opts.danger ? 'danger solid' : 'primary');
      document.body.appendChild(dialog);
      // Enter submits whichever button has focus (native <dialog> form behaviour), and
      // focus starts on Cancel for destructive actions so Enter never confirms by accident.
      dialog.addEventListener('close', function () {
        resolve(dialog.returnValue === 'ok');
        dialog.remove();
      });
      dialog.showModal();
      (opts.danger ? buttons[0] : buttons[1]).focus();
    });
  }

  /* ---------- requests ---------- */
  var config = { loginPath: null, csrfHeader: null, csrfToken: null };
  function configure(options) { for (var k in options) config[k] = options[k]; }

  function isLoginResponse(response) {
    if (response.status === 401) return true;
    if (response.redirected && /(^|\/)login(\?|$)/.test(new URL(response.url).pathname)) return true;
    var type = response.headers.get('content-type') || '';
    return config.loginPath && response.ok && type.indexOf('text/html') === 0;
  }

  function request(url, options) {
    options = options || {};
    var headers = Object.assign({ 'Accept': 'application/json', 'X-Requested-With': 'jp-ui' }, options.headers || {});
    if (options.json !== undefined) { headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(options.json); }
    if (config.csrfHeader && config.csrfToken && (options.method || 'GET') !== 'GET') headers[config.csrfHeader] = config.csrfToken;
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, options.timeout || 15000);
    if (options.signal) options.signal.addEventListener('abort', function () { controller.abort(); });
    return fetch(url, {
      method: options.method || 'GET', headers: headers, body: options.body,
      credentials: 'same-origin', cache: 'no-store', signal: controller.signal
    }).then(function (response) {
      if (config.loginPath && isLoginResponse(response)) {
        location.assign(config.loginPath);  // relative, so it stays under the mount prefix
        throw new Error('登录已失效，正在跳转');
      }
      return response.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
        if (!response.ok || (data && data.success === false)) {
          var message = (data && (data.error || data.message)) || ('请求失败（HTTP ' + response.status + '）');
          var error = new Error(message);
          error.status = response.status;
          error.data = data;
          throw error;
        }
        return data;
      });
    }, function (error) {
      throw new Error(error && error.name === 'AbortError' ? '请求超时' : '网络错误');
    }).finally(function () { clearTimeout(timer); });
  }

  /* ---------- poller ---------- */
  // Its own AbortController, so polling never cancels a user action and vice versa.
  function poller(opts) {
    var timer = null, controller = null, failures = 0, stopped = false;
    var interval = opts.interval || 5000;
    var hidden = opts.hiddenInterval || interval * 4;
    function schedule(ms) { clearTimeout(timer); if (!stopped) timer = setTimeout(tick, ms); }
    function tick() {
      if (controller) controller.abort();
      controller = new AbortController();
      if (opts.conn && !failures) opts.conn.dataset.state = opts.conn.dataset.state || 'loading';
      return request(opts.url, { signal: controller.signal, timeout: opts.timeout || 10000 }).then(function (data) {
        failures = 0;
        if (opts.conn) {
          var time = new Date().toLocaleTimeString();
          opts.conn.dataset.state = 'ok';
          opts.conn.textContent = '已连接';
          opts.conn.title = '最后更新 ' + time;
          var stamp = document.createElement('span');
          stamp.className = 'jp-conn-time';
          stamp.textContent = ' · ' + time;
          opts.conn.appendChild(stamp);
        }
        if (opts.banner) opts.banner.hidden = true;
        opts.onData(data);
      }, function (error) {
        failures++;
        if (opts.conn) { opts.conn.dataset.state = 'lost'; opts.conn.textContent = '连接中断'; }
        if (opts.banner && failures >= (opts.failuresBeforeBanner || 2)) {
          opts.banner.hidden = false;
          opts.banner.textContent = '与服务的连接中断：' + error.message + '，正在重试…';
        }
        if (opts.onError) opts.onError(error, failures);
      }).then(function () {
        schedule(document.hidden ? hidden : interval);
      });
    }
    document.addEventListener('visibilitychange', function () { if (!document.hidden) schedule(150); });
    schedule(0);
    return { refresh: function () { schedule(0); }, stop: function () { stopped = true; clearTimeout(timer); } };
  }

  /* ---------- keyed list rendering ---------- */
  // Reuses existing nodes by key so focus, hover and scroll survive each poll;
  // update(node, item) should only change what differs.
  function keyed(container, items, keyOf, create, update) {
    var wanted = new Set(items.map(function (item) { return String(keyOf(item)); }));
    var existing = new Map();
    // Drop stale nodes first: a moved node loses focus, so nodes that stay should not
    // have to move just because a removed neighbour sat between them.
    Array.prototype.slice.call(container.children).forEach(function (node) {
      var key = node.dataset ? node.dataset.key : undefined;
      if (key === undefined || !wanted.has(key)) node.remove();
      else existing.set(key, node);
    });
    var previous = null;
    items.forEach(function (item) {
      var key = String(keyOf(item));
      var node = existing.get(key);
      if (!node) { node = create(item); node.dataset.key = key; }
      update(node, item);
      var expected = previous ? previous.nextSibling : container.firstChild;
      if (node !== expected) container.insertBefore(node, expected);
      previous = node;
    });
  }
  function setText(node, text) { text = String(text == null ? '' : text); if (node.textContent !== text) node.textContent = text; }

  /* ---------- busy buttons ---------- */
  function busy(button, promise) {
    if (!button) return promise;
    button.setAttribute('aria-busy', 'true');
    button.disabled = true;
    return Promise.resolve(promise).finally(function () {
      button.removeAttribute('aria-busy');
      button.disabled = false;
    });
  }

  /* ---------- form fields that polling must not clobber ---------- */
  // Fill a field from server data only when the user is not editing it.
  function syncField(input, value) {
    if (document.activeElement === input || input.dataset.dirty === '1') return;
    if (input.type === 'checkbox') input.checked = !!value;
    else if (input.value !== String(value)) input.value = value;
  }
  function trackDirty(input) {
    input.addEventListener('input', function () { input.dataset.dirty = '1'; });
    input.addEventListener('change', function () { input.dataset.dirty = '1'; });
  }
  function clearDirty(input) { delete input.dataset.dirty; }

  window.JPUI = {
    version: 1, configure: configure,
    esc: esc, bytes: bytes, duration: duration, ago: ago,
    status: status, badge: badge, toast: toast, confirm: confirmDialog,
    request: request, poller: poller, keyed: keyed, setText: setText, busy: busy,
    syncField: syncField, trackDirty: trackDirty, clearDirty: clearDirty,
    theme: { bind: bindThemeToggle, apply: applyTheme }
  };
})();
