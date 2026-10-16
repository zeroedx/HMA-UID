(() => {
  'use strict';
  const { lang, t } = window.CQUidI18n;
  const SCRIPT = '/data/adb/modules/cq_uid_seccomp/control.sh';
  const builtins = new Set([
    'com.chunqiunativecheck',
    'com.chunqiu.appvisibilitydemo'
  ]);
  const $ = id => document.getElementById(id);
  let saved = null, packages = [], busy = false, serial = 0;
  const validPackage = value => value.length <= 255 && /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$/.test(value);
  const signature = (enabled, list) => JSON.stringify([enabled, [...list].sort()]);
  const dirty = () => saved && signature($('enabled').checked, packages) !== signature(saved.enabled, saved.packages);
  function feedback(message, error = false) { $('feedback').textContent = message; $('feedback').classList.toggle('error', error); }
  function command(args) {
    return new Promise((resolve, reject) => {
      if (!window.ksu || typeof window.ksu.exec !== 'function') return reject(new Error(t('missingBridge')));
      const name = 'cqUidCallback' + (++serial);
      const timer = setTimeout(() => { delete window[name]; reject(new Error(t('timeout'))); }, 15000);
      window[name] = (code, stdout, stderr) => {
        clearTimeout(timer); delete window[name];
        if (code !== 0) return reject(new Error((stderr || stdout || t('operationFailed')).trim()));
        try { resolve(JSON.parse(stdout)); } catch { reject(new Error(t('invalidResponse'))); }
      };
      try { window.ksu.exec('CQ_LANG=' + lang + ' sh ' + SCRIPT + ' ' + args, '{}', name); }
      catch (error) { clearTimeout(timer); delete window[name]; reject(error); }
    });
  }
  function render() {
    $('count').textContent = packages.length;
    $('packages').replaceChildren();
    packages.forEach(name => {
      const item = document.createElement('li'); item.className = 'package-row';
      const body = document.createElement('div'); body.className = 'package-body';
      const packageName = document.createElement('div'); packageName.className = 'package-name'; packageName.textContent = name;
      body.append(packageName);
      if (builtins.has(name)) { const badge = document.createElement('span'); badge.className = 'badge'; badge.textContent = t('builtin'); body.append(badge); }
      const remove = document.createElement('button'); remove.className = 'remove'; remove.type = 'button'; remove.disabled = busy;
      remove.setAttribute('aria-label', t('remove', { package: name }));
      remove.dataset.package = name;
      remove.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M6 18L18 6"/></svg>';
      remove.addEventListener('click', () => { packages = packages.filter(p => p !== name); render(); feedback(t('removed')); });
      item.append(body, remove); $('packages').append(item);
    });
    $('empty').hidden = packages.length !== 0;
    const ready = saved !== null && !busy;
    for (const id of ['enabled', 'package-name', 'add', 'defaults']) $(id).disabled = !ready;
    $('refresh').disabled = busy;
    $('save').disabled = !ready || (!dirty() && !saved.moduleDisabled);
    $('save').textContent = t(busy ? 'processing' : 'save');
    $('save-hint').textContent = t(busy ? 'wait' : !saved ? 'disconnected' : dirty() ? 'unsaved' : 'saved');
    $('status-text').textContent = !saved ? t('disconnected') : $('enabled').checked
      ? t(packages.length === 1 ? 'selectedOne' : 'selected', { count: packages.length }) + (dirty() ? t('pendingSave') : '')
      : t(dirty() ? 'disablePending' : 'disabled');
    if (saved) {
      $('notice').hidden = !saved.pendingUpdate && !saved.moduleDisabled;
      $('notice').textContent = saved.pendingUpdate ? t('updateNotice') : saved.moduleDisabled ? t('disabledNotice') : '';
    }
  }
  function accept(state) {
    if (!Array.isArray(state.packages) || !state.packages.every(validPackage) || typeof state.enabled !== 'boolean') throw new Error(t('invalidConfig'));
    saved = state; packages = [...new Set(state.packages)]; $('enabled').checked = state.enabled;
    $('version').textContent = state.version ?? ''; render();
  }
  async function load() {
    if (busy) return;
    if (dirty()) { feedback(t('saveBeforeRefresh'), true); return; }
    busy = true; render();
    try { accept(await command('status')); feedback(''); }
    catch (error) { feedback(error.message, true); }
    finally { busy = false; render(); }
  }
  $('add-form').addEventListener('submit', event => {
    event.preventDefault();
    const name = $('package-name').value.trim();
    let error = !validPackage(name) ? t('invalidPackage') : packages.includes(name) ? t('duplicate') : packages.length >= 128 ? t('limit') : '';
    $('input-error').textContent = error; $('package-name').setAttribute('aria-invalid', error ? 'true' : 'false');
    if (error) return;
    packages.push(name); $('package-name').value = ''; render(); feedback(t('added')); $('package-name').focus();
  });
  $('enabled').addEventListener('change', () => { render(); feedback(t('toggleChanged')); });
  $('defaults').addEventListener('click', () => { packages = [...new Set([...packages, ...builtins])]; render(); feedback(t('defaultsAdded')); });
  $('refresh').addEventListener('click', load);
  $('save').addEventListener('click', async () => {
    if (busy || !saved) return;
    if ($('enabled').checked && packages.length === 0) { feedback(t('emptyScope'), true); return; }
    const payload = `enabled=${$('enabled').checked ? 1 : 0}\n${packages.join('\n')}${packages.length ? '\n' : ''}`;
    // Payload is validated ASCII; only Base64 crosses the shell argument boundary.
    const encoded = btoa(payload);
    busy = true; render(); feedback(t('saving'));
    try { accept(await command('save ' + encoded + ' apply')); feedback(t(saved.pendingUpdate ? 'savedReboot' : 'applied')); }
    catch (error) { feedback(error.message, true); }
    finally { busy = false; render(); }
  });
  load();
})();
