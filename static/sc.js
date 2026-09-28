/* Stripchat recorder dashboard, on the shared jp-ui kit. */
(function () {
  'use strict';
  const J = window.JPUI;
  const $ = (id) => document.getElementById(id);
  const base = document.body.dataset.basePath || '';
  J.configure({ csrfHeader: 'X-CSRF-Token', csrfToken: document.body.dataset.csrfToken });
  J.theme.bind($('theme'));

  const state = { models: [], filter: 'all' };
  const when = (value) => value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—';
  function uptime(seconds) {
    let n = Math.max(0, Math.floor(Number(seconds) || 0));
    const d = Math.floor(n / 86400); n %= 86400;
    const h = Math.floor(n / 3600), m = Math.floor(n % 3600 / 60);
    return d ? d + ' 天 ' + h + ' 小时' : h ? h + ' 小时 ' + m + ' 分' : m + ' 分钟';
  }
  function roomUrl(name) { return 'https://stripchat.com/' + encodeURIComponent(name); }
  function modelGroup(item) {
    if (item.paused) return 'paused';
    if (item.recording) return 'active';
    const group = J.status(item.status).group;
    return group === 'problem' ? 'problem' : group === 'active' ? 'active' : 'idle';
  }

  /* ---------- recordings ---------- */
  function renderRecordings(items) {
    J.setText($('recording-count'), items.length ? items.length + ' 个' : '');
    $('recording-table').hidden = items.length === 0;
    $('recording-empty').hidden = items.length > 0;
    const now = Date.now() / 1000;
    J.keyed($('recording-body'), items, (item) => item.name, () => {
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td class="primary"><a class="name" target="_blank" rel="noopener noreferrer"></a></td>' +
        '<td data-label="文件"><span class="jp-mono file"></span><span class="sub"></span></td>' +
        '<td data-label="大小" class="jp-num"></td>' +
        '<td data-label="时长" class="jp-num"></td>' +
        '<td class="actions"><button class="jp-btn sm" type="button" data-action="pause">暂停</button></td>';
      return tr;
    }, (tr, item) => {
      const link = tr.querySelector('.name');
      J.setText(link, item.name);
      link.href = roomUrl(item.name);
      J.setText(tr.querySelector('.file'), item.file);
      const notes = [];
      if (item.restarts > 0) notes.push('已重连 ' + item.restarts + ' 次');
      if (item.last_error) notes.push(item.last_error);
      const sub = tr.querySelector('.sub');
      J.setText(sub, notes.join(' · '));
      sub.dataset.tone = item.last_error ? 'warn' : '';
      J.setText(tr.children[2], J.bytes(item.bytes));
      tr.dataset.start = String(now - (item.elapsed_seconds || 0));
      J.setText(tr.children[3], J.duration(item.elapsed_seconds));
      tr.querySelector('button').dataset.model = item.name;
    });
  }

  /* ---------- model grid ---------- */
  function renderModels() {
    const query = $('model-search').value.trim().toLowerCase();
    const counts = { all: 0, active: 0, problem: 0, paused: 0, idle: 0 };
    const visible = [];
    for (const item of state.models) {
      const group = modelGroup(item);
      counts.all++; counts[group]++;
      if ((state.filter === 'all' || state.filter === group) && (!query || item.name.indexOf(query) !== -1)) visible.push(item);
    }
    document.querySelectorAll('#model-filter button').forEach((button) => {
      const key = button.dataset.filter;
      const label = { all: '全部', active: '在线', problem: '异常', paused: '已暂停', idle: '离线' }[key];
      J.setText(button, label + ' ' + counts[key]);
      button.setAttribute('aria-pressed', String(key === state.filter));
    });
    J.setText($('model-count'), counts.all + ' 个');
    const empty = $('models-empty');
    empty.hidden = visible.length > 0;
    empty.textContent = state.models.length ? '没有符合条件的主播' : '暂无主播状态';
    // Recording and problem rows first, then alphabetical: what needs attention stays on top.
    const order = { active: 0, problem: 1, paused: 2, idle: 3 };
    visible.sort((a, b) => (order[modelGroup(a)] - order[modelGroup(b)]) || a.name.localeCompare(b.name));
    J.keyed($('models'), visible, (item) => item.name, () => {
      const box = document.createElement('div');
      box.className = 'sc-model';
      box.innerHTML =
        '<a class="name" target="_blank" rel="noopener noreferrer"></a>' +
        '<span class="jp-badge"></span>' +
        '<button class="jp-btn sm icon" type="button" data-action="toggle"></button>' +
        '<span class="detail"></span>';
      return box;
    }, (box, item) => {
      const link = box.querySelector('.name');
      J.setText(link, item.name);
      link.href = roomUrl(item.name);
      const shown = item.paused ? J.status('paused') : item.recording ? J.status('recording') : J.status(item.status);
      const badge = box.querySelector('.jp-badge');
      badge.dataset.tone = shown.tone;
      J.setText(badge, shown.label);
      badge.title = item.status || '';
      const parts = [];
      if (item.error) parts.push(item.error + (item.http_status ? '（HTTP ' + item.http_status + '）' : ''));
      if (item.checked_at && !item.paused) parts.push('检查于 ' + J.ago(item.checked_at));
      const detail = box.querySelector('.detail');
      J.setText(detail, parts.join(' · '));
      detail.title = item.error || '';
      detail.dataset.tone = shown.tone === 'danger' ? 'danger' : shown.tone === 'warn' && item.error ? 'warn' : '';
      box.dataset.group = modelGroup(item);
      const button = box.querySelector('button');
      button.dataset.model = item.name;
      button.dataset.paused = item.paused ? '1' : '';
      J.setText(button, item.paused ? '▶' : 'Ⅱ');
      button.title = (item.paused ? '恢复 ' : '暂停 ') + item.name;
      button.setAttribute('aria-label', button.title);
    });
  }

  /* ---------- the rest of the status ---------- */
  function render(data) {
    const manager = data.manager;
    state.models = manager.models || [];
    const recordings = manager.recordings || [];
    const paused = state.models.filter((m) => m.paused).length;
    const problems = state.models.filter((m) => modelGroup(m) === 'problem').length;

    J.setText($('stat-recording'), recordings.length);
    J.setText($('stat-checking'), '检查中 ' + manager.checking_count);
    J.setText($('stat-wanted'), manager.wanted_count);
    J.setText($('stat-wanted-hint'), '暂停 ' + paused + ' · 异常 ' + problems);
    $('stat-wanted-card').dataset.tone = problems ? 'warn' : '';

    const upload = data.upload || {};
    const uploadStatus = J.status(upload.state);
    J.setText($('stat-queue'), upload.queue_files);
    J.setText($('stat-queue-hint'), J.bytes(upload.queue_bytes) + ' · ' + uploadStatus.label);
    $('stat-queue-card').dataset.tone = uploadStatus.tone === 'danger' || uploadStatus.tone === 'warn' ? uploadStatus.tone : '';

    const disk = data.disk || {};
    const diskTone = disk.used_percent > 90 ? 'danger' : disk.used_percent > 75 ? 'warn' : '';
    J.setText($('stat-disk'), J.bytes(disk.free_bytes));
    J.setText($('stat-disk-hint'), '已用 ' + disk.used_percent + '%');
    $('stat-disk-card').dataset.tone = diskTone;
    J.setText($('stat-uptime'), uptime(data.app.uptime_seconds));
    J.setText($('stat-version'), data.app.version);

    renderRecordings(recordings);
    renderModels();

    const stateBadge = $('upload-state');
    stateBadge.dataset.tone = uploadStatus.tone;
    J.setText(stateBadge, uploadStatus.label);
    stateBadge.title = upload.state || '';
    J.setText($('upload-queue'), upload.queue_files + ' 个文件 · ' + J.bytes(upload.queue_bytes));
    J.setText($('upload-success'), upload.last_success ? upload.last_success.path + ' · ' + when(upload.last_success.at) : '—');
    const uploadError = $('upload-error');
    J.setText(uploadError, upload.last_error ? upload.last_error.message + ' · ' + when(upload.last_error.at) : '—');
    uploadError.dataset.tone = upload.last_error ? 'danger' : '';
    J.setText($('upload-updated'), upload.updated_at ? J.ago(upload.updated_at) : '—');

    J.setText($('disk-total'), J.bytes(disk.total_bytes));
    J.setText($('disk-used'), J.bytes(disk.used_bytes));
    J.setText($('disk-free'), J.bytes(disk.free_bytes));
    J.setText($('disk-percent'), disk.used_percent + '% 已使用');
    const meter = $('disk-meter');
    meter.dataset.tone = diskTone;
    meter.firstElementChild.style.width = Math.min(100, disk.used_percent || 0) + '%';

    J.syncField($('segment-minutes'), data.segment_minutes);
  }

  /* ---------- actions ---------- */
  function setPaused(name, pause, button) {
    const run = () => J.busy(button, J.request(base + '/api/models/' + encodeURIComponent(name) + '/' + (pause ? 'pause' : 'resume'), { method: 'POST' }))
      .then(() => { J.toast((pause ? '已暂停 ' : '已恢复 ') + name, 'ok'); poll.refresh(); },
            (error) => J.toast((pause ? '暂停' : '恢复') + '失败：' + error.message, 'error'));
    const model = state.models.find((m) => m.name === name);
    if (!pause || !(model && model.recording)) return run();
    return J.confirm({
      title: '暂停 ' + name + '？',
      message: '正在进行的录制会停止并保存当前文件，之后不再检查该主播，直到手动恢复。\n服务重启后暂停状态会清除。',
      confirmText: '暂停录制', danger: true
    }).then((ok) => ok && run());
  }

  document.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    if (button.dataset.action === 'pause') setPaused(button.dataset.model, true, button);
    else if (button.dataset.action === 'toggle') setPaused(button.dataset.model, !button.dataset.paused, button);
  });

  $('model-filter').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-filter]');
    if (!button) return;
    state.filter = button.dataset.filter;
    renderModels();
  });
  $('model-search').addEventListener('input', renderModels);

  const minutes = $('segment-minutes');
  J.trackDirty(minutes);
  $('settings-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const value = Number(minutes.value);
    const button = event.submitter || event.currentTarget.querySelector('button');
    J.busy(button, J.request(base + '/api/settings/segment-duration', { method: 'PUT', json: { minutes: value } }))
      .then(() => { J.clearDirty(minutes); minutes.blur(); J.toast('分段时长已改为 ' + value + ' 分钟', 'ok'); },
            (error) => J.toast('保存失败：' + error.message, 'error'));
  });

  const poll = J.poller({
    url: base + '/api/status', interval: 4000, hiddenInterval: 20000,
    conn: $('conn'), banner: $('banner'), onData: render
  });

  setInterval(() => {
    const now = Date.now() / 1000;
    document.querySelectorAll('#recording-body tr[data-start]').forEach((tr) => {
      J.setText(tr.children[3], J.duration(now - Number(tr.dataset.start)));
    });
  }, 1000);
})();
