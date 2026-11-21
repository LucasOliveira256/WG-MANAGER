'use strict';
(function () {
  const $ = (sel) => document.querySelector(sel);
  const VIEWS = ['loading', 'login', 'wizard', 'main'];
  const STEPS = ['password', 'ros', 'wg', 'done'];

  let csrf = '';
  let rosTested = false;
  let lastConf = null;

  // ---------- utilidades ----------

  async function api(path, body) {
    const init = { credentials: 'same-origin', headers: {} };
    if (body !== undefined) {
      init.method = 'POST';
      init.headers['Content-Type'] = 'application/json';
      init.headers['X-CSRF-Token'] = csrf;
      init.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(path, init);
    } catch (e) {
      throw new Error('Sem conexão com o servidor.');
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* corpo vazio */ }
    if (!res.ok) {
      if (res.status === 401 && data && data.code === 'session') {
        location.reload();
      }
      throw new Error((data && data.error) || ('Erro ' + res.status));
    }
    return data;
  }

  function setMsg(el, text, kind) {
    el.textContent = text || '';
    el.className = 'msg' + (kind ? ' ' + kind : '');
  }

  function showView(name) {
    VIEWS.forEach((v) => { $('#view-' + v).hidden = v !== name; });
    $('#topbar').hidden = name !== 'main';
  }

  async function copyText(text, btn) {
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        ok = true;
      }
    } catch (e) { /* tenta o método antigo */ }
    if (!ok) {
      // Em HTTP simples (LAN) a API moderna de clipboard não está disponível.
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.className = 'offscreen';
      document.body.appendChild(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      ta.remove();
    }
    const old = btn.textContent;
    btn.textContent = ok ? 'Copiado' : 'Não foi possível copiar';
    setTimeout(() => { btn.textContent = old; }, 1800);
  }

  function formatBytes(v) {
    const n = Number(v);
    if (!isFinite(n) || v === '' || v === undefined) return '-';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0, x = n;
    while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
    return (i === 0 ? String(x) : x.toFixed(1)) + ' ' + units[i];
  }

  // "1w2d3h4m5s" (formato de tempo do RouterOS) -> segundos; null se vazio.
  function parseRosDuration(s) {
    if (!s) return null;
    const mult = { w: 604800, d: 86400, h: 3600, m: 60, s: 1 };
    const re = /(\d+)([wdhms])/g;
    let m, total = 0, found = false;
    while ((m = re.exec(s)) !== null) { total += Number(m[1]) * mult[m[2]]; found = true; }
    return found ? total : null;
  }

  function ipKey(addr) {
    const first = String(addr || '').split(',')[0].split('/')[0].trim().split('.');
    if (first.length !== 4) return Number.MAX_SAFE_INTEGER;
    return first.reduce((acc, p) => acc * 256 + (Number(p) || 0), 0);
  }

  // ---------- inicialização ----------

  async function boot() {
    showView('loading');
    try {
      const st = await api('/api/state');
      csrf = st.csrf;
      if (st.state === 'no-config') return showStep('password');
      if (!st.authenticated) { showView('login'); $('#login-pw').focus(); return; }
      if (st.state === 'setup') return showStep(st.hasRos ? 'wg' : 'ros');
      showMain();
    } catch (e) {
      $('#view-loading').textContent = e.message;
    }
  }

  // ---------- login / logout ----------

  $('#form-login').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#login-err');
    setMsg(err, '', 'error');
    try {
      const r = await api('/api/login', { password: $('#login-pw').value });
      csrf = r.csrf;
      $('#login-pw').value = '';
      boot();
    } catch (ex) {
      setMsg(err, ex.message, 'error');
    }
  });

  $('#btn-logout').addEventListener('click', async () => {
    try { await api('/api/logout', {}); } catch (e) { /* segue para recarregar */ }
    location.reload();
  });

  // ---------- wizard ----------

  function showStep(step) {
    showView('wizard');
    document.querySelectorAll('.step').forEach((s) => { s.hidden = s.dataset.step !== step; });
    $('#wiz-progress').textContent = step === 'done'
      ? 'Configuração concluída.'
      : 'Passo ' + (STEPS.indexOf(step) + 1) + ' de 3';
    if (step === 'wg') loadExistingInterfaces();
  }

  // Passo 1: senha
  $('#form-password').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#pw-err');
    setMsg(err, '', 'error');
    const pw = $('#pw1').value;
    if (pw.length < 8) return setMsg(err, 'A senha deve ter pelo menos 8 caracteres.', 'error');
    if (pw !== $('#pw2').value) return setMsg(err, 'As senhas não conferem.', 'error');
    try {
      const r = await api('/api/setup/password', { password: pw });
      csrf = r.csrf;
      $('#pw1').value = '';
      $('#pw2').value = '';
      showStep('ros');
    } catch (ex) {
      setMsg(err, ex.message, 'error');
    }
  });

  // Passo 2: RouterBoard
  function rosPayload() {
    return {
      https: $('#ros-https').checked,
      host: $('#ros-host').value.trim(),
      port: Number($('#ros-port').value),
      user: $('#ros-user').value.trim(),
      password: $('#ros-pass').value,
      verifyTLS: $('#ros-verify').checked,
    };
  }

  function invalidateTest() {
    rosTested = false;
    $('#ros-next').disabled = true;
  }

  $('#form-ros').addEventListener('input', invalidateTest);
  $('#ros-https').addEventListener('change', () => {
    const port = $('#ros-port');
    if ($('#ros-https').checked && port.value === '80') port.value = '443';
    if (!$('#ros-https').checked && port.value === '443') port.value = '80';
  });

  $('#ros-test').addEventListener('click', async () => {
    const msg = $('#ros-msg');
    const btn = $('#ros-test');
    setMsg(msg, 'Testando…');
    btn.disabled = true;
    try {
      const r = await api('/api/setup/ros/test', rosPayload());
      rosTested = true;
      $('#ros-next').disabled = false;
      setMsg(msg, 'Conexão OK. Interfaces WireGuard encontradas: ' + r.interfaces.length + '.', 'ok');
    } catch (ex) {
      invalidateTest();
      setMsg(msg, ex.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  $('#form-ros').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!rosTested) return;
    const msg = $('#ros-msg');
    try {
      await api('/api/setup/ros', rosPayload());
      $('#ros-pass').value = '';
      showStep('wg');
    } catch (ex) {
      invalidateTest();
      setMsg(msg, ex.message, 'error');
    }
  });

  // Passo 3: servidor WireGuard
  function wgAdopt() {
    return document.querySelector('input[name="wg-mode"]:checked').value === 'adopt';
  }

  function syncWgMode() {
    const adopt = wgAdopt();
    $('#wg-iface-field').hidden = adopt;
    $('#wg-port-field').hidden = adopt;
    $('#wg-iface-select-field').hidden = !adopt;
  }
  document.querySelectorAll('input[name="wg-mode"]').forEach((r) => r.addEventListener('change', syncWgMode));

  async function loadExistingInterfaces() {
    const sel = $('#wg-iface-select');
    try {
      const r = await api('/api/setup/interfaces');
      sel.textContent = '';
      r.interfaces.forEach((i) => {
        const o = document.createElement('option');
        o.value = i.name;
        o.textContent = i.name + (i.listenPort ? ' (porta ' + i.listenPort + ')' : '');
        sel.appendChild(o);
      });
      if (!r.interfaces.length) {
        const o = document.createElement('option');
        o.value = '';
        o.textContent = 'Nenhuma interface WireGuard encontrada';
        sel.appendChild(o);
      }
    } catch (ex) {
      setMsg($('#wg-msg'), ex.message, 'error');
    }
  }

  $('#form-wg').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('#wg-msg');
    setMsg(msg, '', 'error');
    const adopt = wgAdopt();
    const body = {
      adopt: adopt,
      iface: adopt ? $('#wg-iface-select').value : $('#wg-iface').value.trim(),
      listenPort: Number($('#wg-port').value) || 0,
      subnet: $('#wg-subnet').value.trim(),
      serverIP: $('#wg-serverip').value.trim(),
      endpoint: $('#wg-endpoint').value.trim(),
      dns: $('#wg-dns').value.trim(),
      allowedIPs: $('#wg-allowed').value.trim(),
    };
    const btn = e.submitter;
    if (btn) btn.disabled = true;
    try {
      const r = await api('/api/setup/wg', body);
      $('#fw-rule').textContent = r.firewall;
      showStep('done');
    } catch (ex) {
      setMsg(msg, ex.message, 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  // Passo 4: firewall
  $('#fw-copy').addEventListener('click', (e) => copyText($('#fw-rule').textContent, e.currentTarget));
  $('#go-main').addEventListener('click', showMain);

  // ---------- painel ----------

  function showMain() {
    showView('main');
    loadPeers();
  }

  function statusOf(p) {
    if (p.disabled) return { key: 'off', label: 'Desativado' };
    const secs = parseRosDuration(p.lastHandshake);
    if (secs === null) return { key: 'never', label: 'Sem handshake' };
    if (secs <= 180) return { key: 'on', label: 'Conectado' };
    return { key: 'idle', label: 'Inativo' };
  }

  function cell(text, cls) {
    const td = document.createElement('td');
    td.textContent = text;
    if (cls) td.className = cls;
    return td;
  }

  function actionButton(label, cls, handler) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn small ' + cls;
    b.textContent = label;
    b.addEventListener('click', handler);
    return b;
  }

  async function loadPeers() {
    const msg = $('#list-msg');
    setMsg(msg, '', 'error');
    try {
      const d = await api('/api/peers');
      $('#server-info').textContent = 'Interface ' + d.iface + ', endpoint ' + d.endpoint + ':' + d.port;
      renderPeers(d.peers);
    } catch (ex) {
      setMsg(msg, ex.message, 'error');
    }
  }

  function renderPeers(peers) {
    const body = $('#peers-body');
    body.textContent = '';
    peers.sort((a, b) => ipKey(a.address) - ipKey(b.address));
    $('#peers-empty').hidden = peers.length > 0;

    peers.forEach((p) => {
      const st = statusOf(p);
      const tr = document.createElement('tr');
      tr.className = 'st-' + st.key;
      tr.appendChild(cell(p.name || '(sem nome)'));
      tr.appendChild(cell(p.address, 'mono'));
      const stTd = document.createElement('td');
      const tag = document.createElement('span');
      tag.className = 'tag t-' + st.key;
      tag.textContent = st.label;
      stTd.appendChild(tag);
      tr.appendChild(stTd);
      tr.appendChild(cell(p.lastHandshake ? 'há ' + p.lastHandshake : 'nunca'));
      tr.appendChild(cell(formatBytes(p.rx), 'num'));
      tr.appendChild(cell(formatBytes(p.tx), 'num'));

      const act = document.createElement('td');
      act.className = 'act';
      act.appendChild(actionButton(p.disabled ? 'Ativar' : 'Desativar', '', async () => {
        try {
          await api('/api/peers/' + encodeURIComponent(p.id) + '/toggle', { disabled: !p.disabled });
          loadPeers();
        } catch (ex) { setMsg($('#list-msg'), ex.message, 'error'); }
      }));
      act.appendChild(actionButton('Remover', 'danger', async () => {
        if (!window.confirm('Remover o peer "' + (p.name || p.address) + '"? Esta ação não pode ser desfeita.')) return;
        try {
          await api('/api/peers/' + encodeURIComponent(p.id) + '/delete', {});
          loadPeers();
        } catch (ex) { setMsg($('#list-msg'), ex.message, 'error'); }
      }));
      tr.appendChild(act);
      body.appendChild(tr);
    });
  }

  $('#btn-refresh').addEventListener('click', loadPeers);

  $('#form-peer').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('#peer-msg');
    setMsg(msg, '', 'error');
    const btn = e.submitter;
    if (btn) btn.disabled = true;
    try {
      const r = await api('/api/peers', {
        name: $('#peer-name').value.trim(),
        ip: $('#peer-ip').value.trim(),
        keepalive: Number($('#peer-keepalive').value) || 0,
        psk: $('#peer-psk').checked,
      });
      lastConf = r;
      $('#conf-text').value = r.conf;
      $('#result').hidden = false;
      $('#result').scrollIntoView({ block: 'nearest' });
      $('#peer-name').value = '';
      $('#peer-ip').value = '';
      loadPeers();
    } catch (ex) {
      setMsg(msg, ex.message, 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  $('#conf-copy').addEventListener('click', (e) => {
    if (lastConf) copyText(lastConf.conf, e.currentTarget);
  });

  $('#conf-download').addEventListener('click', () => {
    if (!lastConf) return;
    const blob = new Blob([lastConf.conf], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = lastConf.filename || 'peer.conf';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  $('#conf-close').addEventListener('click', () => {
    lastConf = null;
    $('#conf-text').value = '';
    $('#result').hidden = true;
  });

  boot();
})();
