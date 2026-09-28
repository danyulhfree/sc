/* Stripchat wanted list editor, on the shared jp-ui kit. */
(function () {
  'use strict';
  const J = window.JPUI;
  const $ = (id) => document.getElementById(id);
  const base = document.body.dataset.basePath || '';
  J.configure({ csrfHeader: 'X-CSRF-Token', csrfToken: document.body.dataset.csrfToken });
  J.theme.bind($('theme'));

  let models = [];

  function parseInput(text) {
    return text.split(/[\n,，\s]+/).map((value) => {
      const fromUrl = value.match(/stripchat\.com\/([^/?#\s]+)/i);
      return (fromUrl ? fromUrl[1] : value).replace(/^@/, '').trim().toLowerCase();
    }).filter(Boolean);
  }

  function render() {
    const query = $('search').value.trim().toLowerCase();
    const visible = models.filter((name) => !query || name.indexOf(query) !== -1);
    J.setText($('count'), query ? visible.length + ' / ' + models.length + ' 个' : models.length + ' 个');
    const empty = $('empty');
    empty.hidden = visible.length > 0;
    empty.textContent = models.length ? '没有匹配的主播' : '列表为空';
    J.keyed($('models'), visible, (name) => name, () => {
      const chip = document.createElement('span');
      chip.className = 'jp-chip';
      chip.innerHTML = '<span></span><button type="button" data-action="remove">×</button>';
      return chip;
    }, (chip, name) => {
      J.setText(chip.firstChild, name);
      chip.lastChild.dataset.model = name;
      chip.lastChild.setAttribute('aria-label', '删除 ' + name);
      chip.lastChild.title = '删除 ' + name;
    });
  }

  function load() {
    return J.request(base + '/api/wanted').then((data) => {
      $('banner').hidden = true;
      models = (data.models || []).slice().sort();
      const repeated = data.repeated_models || [];
      $('duplicate').hidden = repeated.length === 0;
      $('duplicate').textContent = '文件中有重复项：' + repeated.join('、');
      render();
    }, (error) => {
      $('banner').hidden = false;
      $('banner').textContent = '读取列表失败：' + error.message;
    });
  }

  $('models-input').addEventListener('input', () => {
    const names = parseInput($('models-input').value);
    const fresh = names.filter((name) => models.indexOf(name) === -1);
    J.setText($('add-preview'), names.length ? '共 ' + names.length + ' 个，其中新增 ' + fresh.length + ' 个' : '');
  });

  $('add-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const names = parseInput($('models-input').value);
    if (!names.length) return;
    const button = event.submitter || event.currentTarget.querySelector('button[type="submit"]');
    J.busy(button, J.request(base + '/api/wanted', { method: 'POST', json: { models: names } }))
      .then((data) => {
        const added = (data && data.added) || [];
        J.toast(added.length ? '已添加 ' + added.length + ' 个：' + added.join('、') : '都已在列表中，没有新增', added.length ? 'ok' : undefined);
        $('models-input').value = '';
        J.setText($('add-preview'), '');
        return load();
      }, (error) => J.toast('添加失败：' + error.message, 'error'));  // keep the input so nothing is lost
  });

  $('search').addEventListener('input', render);

  document.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-action="remove"]');
    if (!button) return;
    const name = button.dataset.model;
    J.confirm({
      title: '删除 ' + name + '？',
      message: '删除后不再检查该主播；如果正在录制，录制会停止并保存当前文件。',
      confirmText: '删除', danger: true
    }).then((ok) => {
      if (!ok) return;
      J.busy(button, J.request(base + '/api/wanted/' + encodeURIComponent(name), { method: 'DELETE' }))
        .then(() => { J.toast('已删除 ' + name, 'ok'); return load(); }, (error) => J.toast('删除失败：' + error.message, 'error'));
    });
  });

  load();
})();
