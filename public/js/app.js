/* ==========================================================================
   ISS-DS client core  —  loaded by every page (except login.html's own script)
   Provides: ISS.api · ISS.esc · ISS.toast · ISS.confirm · ISS.prompt · ISS.alert
             ISS.busy · ISS.fmtDate · ISS.fileMeta · ISS.toneFor · ISS.ready (shell + user)
   Pages mark up <body data-page data-title data-sub> + <main id="content">; the shell wraps it.
   ========================================================================== */
(function () {
  'use strict';

  /* ---------- tiny utilities ---------- */
  const $ = (sel, root = document) => root.querySelector(sel);
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  /** Escape any value before putting it into an HTML string (prevents XSS from titles, usernames, etc.). */
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ESC[c]);
  const html = (str) => { const t = document.createElement('template'); t.innerHTML = str.trim(); return t.content.firstElementChild; };
  const debounce = (fn, ms = 160) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  };
  const ADMIN_ROLES = ['Administrator', 'President'];

  /* ---------- API helper: JSON in/out, friendly errors, auto-redirect on 401 ---------- */
  async function api(url, { method = 'GET', body, form } = {}) {
    const opts = { method, headers: { Accept: 'application/json' }, credentials: 'same-origin' };
    if (form) opts.body = form;
    else if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    let res;
    try { res = await fetch(url, opts); } catch { throw new Error('Network error. Check your connection and try again.'); }
    if (res.status === 401) { location.href = '/login'; throw new Error('Please sign in again.'); }
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new Error((data && data.error) || `Something went wrong (${res.status}).`);
    return data;
  }

  /* ---------- dates & files ---------- */
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  /** 'YYYY-MM-DD' -> 'Mar 1, 2026' without any timezone shifting. */
  function fmtDate(ymd) {
    const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(ymd || '');
    return m ? `${MONTHS[+m[2] - 1]} ${+m[3]}, ${m[1]}` : '—';
  }
  const todayYMD = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };

  function fileMeta(name) {
    const ext = String(name || '').split('.').pop().toLowerCase();
    if (ext === 'pdf') return { ext, icon: 'fa-file-pdf', cls: 'ft-pdf' };
    if (['xls', 'xlsx', 'csv'].includes(ext)) return { ext, icon: 'fa-file-excel', cls: 'ft-xls' };
    if (['doc', 'docx'].includes(ext)) return { ext, icon: 'fa-file-word', cls: 'ft-doc' };
    if (['ppt', 'pptx'].includes(ext)) return { ext, icon: 'fa-file-powerpoint', cls: 'ft-ppt' };
    if (['png', 'jpg', 'jpeg'].includes(ext)) return { ext, icon: 'fa-file-image', cls: 'ft-img' };
    return { ext, icon: 'fa-file-lines', cls: 'ft-txt' };
  }
  const TONES = ['violet', 'aqua', 'amber', 'mint', 'rose', 'indigo'];
  const FIXED_TONE = { reports: 'violet', memos: 'aqua', records: 'amber', finance: 'mint' };
  /** Stable colour per document type (known types keep their brand colour, new ones get a hashed one). */
  function toneFor(name) {
    const k = String(name).toLowerCase();
    if (FIXED_TONE[k]) return 't-' + FIXED_TONE[k];
    let h = 0; for (const c of k) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    return 't-' + TONES[h % TONES.length];
  }
  function catIcon(name) {
    const k = String(name).toLowerCase();
    if (k.includes('financ')) return 'fa-money-check-dollar';
    if (k.includes('report')) return 'fa-chart-pie';
    if (k.includes('memo')) return 'fa-bullhorn';
    if (k.includes('record')) return 'fa-box-archive';
    return 'fa-layer-group';
  }

  /* ---------- toast ---------- */
  function toast(message, type = 'ok', ms = 3800) {
    let box = $('.toasts');
    if (!box) { box = html('<div class="toasts" role="status" aria-live="polite"></div>'); document.body.append(box); }
    const icons = { ok: 'fa-check', err: 'fa-xmark', warn: 'fa-triangle-exclamation', info: 'fa-info' };
    const t = html(`<div class="toast ${type}"><i class="fa-solid ${icons[type] || icons.info}"></i><span>${esc(message)}</span></div>`);
    box.append(t);
    const close = () => { t.classList.add('out'); setTimeout(() => t.remove(), 300); };
    setTimeout(close, ms);
    t.addEventListener('click', close);
  }

  /* ---------- dialogs (native <dialog>: focus trap + Esc come for free) ---------- */
  function dialog({ icon = 'fa-circle-question', tone = '', title, text = '', confirm = 'OK', cancel = 'Cancel', hideCancel = false, input = null }) {
    return new Promise((resolve) => {
      const d = html(`<dialog class="dlg" aria-label="${esc(title)}"><form class="dlg-card" novalidate>
        <div class="dlg-ico ${tone}"><i class="fa-solid ${icon}"></i></div>
        <h3>${esc(title)}</h3>
        ${text ? `<p>${esc(text)}</p>` : ''}
        ${input ? `<div class="field"><input class="input" type="${input.type || 'text'}" autocomplete="off" placeholder="${esc(input.placeholder || '')}" value="${esc(input.value || '')}" /><small class="err" style="color:var(--rose);font-weight:700" hidden></small></div>` : ''}
        <div class="dlg-actions">
          ${hideCancel ? '' : `<button type="button" class="btn btn-ghost" data-cancel>${esc(cancel)}</button>`}
          <button type="submit" class="btn ${tone === 'danger' ? 'btn-danger' : 'btn-primary'}">${esc(confirm)}</button>
        </div></form></dialog>`);
      let result = input ? null : false;
      const form = $('form', d), field = $('input', d), err = $('.err', d);
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        if (field) {
          const v = field.value.trim();
          const problem = input.validate ? input.validate(v) : (!v ? 'This field is required.' : '');
          if (problem) { err.textContent = problem; err.hidden = false; field.focus(); return; }
          result = v;
        } else result = true;
        d.close();
      });
      const cancelBtn = $('[data-cancel]', d);
      if (cancelBtn) cancelBtn.addEventListener('click', () => d.close());
      d.addEventListener('click', (e) => { if (e.target === d) d.close(); });
      d.addEventListener('close', () => { d.remove(); resolve(result); });
      document.body.append(d);
      d.showModal();
      (field || $('button[type=submit]', d)).focus();
      if (field) field.select();
    });
  }
  const confirmDialog = (o) => dialog({ ...o });
  const promptDialog = (o) => dialog({ ...o, input: o.input || {} });
  const alertDialog = (o) => dialog({ hideCancel: true, ...o });

  // Declarative closing for page-defined <dialog class="dlg">: [data-close] buttons + backdrop click.
  document.addEventListener('click', (e) => {
    const closer = e.target.closest('[data-close]');
    if (closer) { const d = closer.closest('dialog'); if (d) d.close(); }
    else if (e.target.matches && e.target.matches('dialog.dlg')) e.target.close();
  });

  /** Disable a button + show a spinner while an async task runs. */
  async function busy(btn, task, label) {
    const original = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-circle-notch spin"></i> ${esc(label || 'Working…')}`;
    try { return await task(); } finally { btn.disabled = false; btn.innerHTML = original; }
  }


  /* ---------- icon dropdown (replaces <select> where each option has an icon) ---------- */
  function picker(root, { name = '', placeholder = 'Choose…', icon = 'fa-layer-group', onChange } = {}) {
    root.classList.add('picker');
    root.innerHTML = `<button type="button" class="picker-btn" aria-haspopup="listbox" aria-expanded="false">
        <span class="picker-ico none"><i class="fa-solid ${icon}"></i></span><span class="picker-label ph">${esc(placeholder)}</span><i class="fa-solid fa-chevron-down caret"></i></button>
      <ul class="picker-list" role="listbox" hidden></ul>${name ? `<input type="hidden" name="${esc(name)}" />` : ''}`;
    const btn = $('.picker-btn', root), list = $('.picker-list', root), hidden = $('input', root);
    let items = [], value = '', active = -1;

    const open = (on) => { list.hidden = !on; root.classList.toggle('open', on); btn.setAttribute('aria-expanded', on); if (on) { active = Math.max(0, items.findIndex((i) => i.value === value)); mark(); } };
    const mark = () => list.querySelectorAll('li[data-i]').forEach((li, i) => li.classList.toggle('active', i === active));
    function paint() {
      const it = items.find((x) => x.value === value);
      $('.picker-label', root).textContent = it ? it.label : placeholder;
      $('.picker-label', root).classList.toggle('ph', !it);
      const ic = $('.picker-ico', root);
      ic.className = 'picker-ico ' + (it ? it.tone || '' : 'none');
      ic.innerHTML = `<i class="fa-solid ${it ? it.icon || icon : icon}"></i>`;
      if (hidden) hidden.value = value;
    }
    function render() {
      list.innerHTML = items.length
        ? items.map((it, i) => `<li role="option" data-i="${i}" aria-selected="${it.value === value}"><span class="picker-ico ${it.tone || ''}"><i class="fa-solid ${it.icon || icon}"></i></span><span>${esc(it.label)}</span><i class="fa-solid fa-check tick"></i></li>`).join('')
        : '<li class="picker-empty">Nothing to choose yet</li>';
    }
    function choose(i) { value = items[i].value; paint(); render(); open(false); btn.focus(); if (onChange) onChange(value); }

    btn.addEventListener('click', () => open(list.hidden));
    list.addEventListener('click', (e) => { const li = e.target.closest('li[data-i]'); if (li) choose(+li.dataset.i); });
    document.addEventListener('click', (e) => { if (!root.contains(e.target)) open(false); });
    btn.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') return open(false);
      if (!['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(e.key)) return;
      e.preventDefault();
      if (list.hidden) return open(true);
      if (e.key === 'ArrowDown') active = Math.min(items.length - 1, active + 1);
      else if (e.key === 'ArrowUp') active = Math.max(0, active - 1);
      else if (active >= 0) return choose(active);
      mark(); const li = list.children[active]; if (li && li.scrollIntoView) li.scrollIntoView({ block: 'nearest' });
    });

    const api = {
      get value() { return value; },
      set value(v) { value = items.some((i) => i.value === v) ? v : ''; paint(); render(); },   // programmatic: does not fire onChange
      setItems(next) { items = next; if (!items.some((i) => i.value === value)) value = ''; paint(); render(); },
      has: (v) => items.some((i) => i.value === v),
      focus: () => btn.focus(),
    };
    render();
    return api;
  }

  /* ---------- shell: sidebar + topbar + hero ---------- */
  const NAV = [
    { key: 'dashboard', href: '/dashboard', icon: 'fa-house', label: 'Dashboard' },
    { key: 'documents', href: '/documents', icon: 'fa-folder-tree', label: 'My Documents' },
    { key: 'upload', href: '/upload', icon: 'fa-cloud-arrow-up', label: 'Upload Document' },
    { key: 'activity', href: '/activity-log', icon: 'fa-chart-line', label: 'Activity Log', allow: (r) => ADMIN_ROLES.includes(r) },
    { key: 'recycle', href: '/recycle-bin', icon: 'fa-trash-can-arrow-up', label: 'Recycle Bin', allow: (r) => r !== 'Officer' },
    { key: 'admin', href: '/admin', icon: 'fa-gear', label: 'Admin Panel', allow: (r) => ADMIN_ROLES.includes(r) },
  ];

  const isMobile = () => matchMedia('(max-width: 900px)').matches;
  function toggleRail(force) {
    const b = document.body;
    if (isMobile()) b.classList.toggle('rail-open', force);
    else { const off = b.classList.toggle('rail-off', force === undefined ? undefined : !force); store.set('iss.rail', off ? 'off' : 'on'); }
  }

  function buildShell() {
    const b = document.body, d = b.dataset;
    const content = $('#content');
    if (!content) return null;
    const heroActions = $('#heroActions');
    if (store.get('iss.rail') === 'off') b.classList.add('rail-off');

    const app = html(`<div class="app">
      <div class="scrim" data-scrim></div>
      <aside class="rail" id="rail" aria-label="Main navigation">
        <div class="rail-brand"><img src="/nobglogo.png" alt="CSU ISS logo" width="128" height="128" /></div>
        <nav class="rail-nav">
          ${NAV.map((n) => `<a class="nav-link${n.key === d.page ? ' active' : ''}" href="${n.href}" data-nav="${n.key}" ${n.allow ? 'hidden' : ''} ${n.key === d.page ? 'aria-current="page"' : ''}><i class="fa-solid ${n.icon}"></i><span>${n.label}</span></a>`).join('')}
        </nav>
        <div class="rail-profile">
          <div class="rail-user"><div class="avatar" id="userAvatar">·</div><div style="min-width:0"><strong id="userName">Loading…</strong><span id="userRole">ISS-DS Portal</span></div></div>
          <a class="logout" href="/logout"><i class="fa-solid fa-right-from-bracket"></i> Sign out</a>
        </div>
      </aside>
      <div class="stage">
        <header class="topbar">
          <button class="icon-btn" id="railToggle" aria-label="Toggle menu" aria-controls="rail"><i class="fa-solid fa-bars"></i></button>
          <div class="crumb">ISS-DS · <b>${esc(d.title || '')}</b></div>
          <div class="date-chip"><i class="fa-regular fa-calendar"></i>${new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' })}</div>
        </header>
        <section class="hero" id="hero">
          <div class="hero-sheets" aria-hidden="true"><span></span><span></span><span></span></div>
          <h1 id="heroTitle">${esc(d.title || '')}</h1>
          <p id="heroSub">${esc(d.sub || '')}</p>
        </section>
      </div></div>`);

    b.prepend(app);
    const stage = $('.stage', app);
    if (heroActions) { heroActions.className = 'hero-actions'; heroActions.hidden = false; $('#hero').append(heroActions); }
    stage.append(content);

    $('#railToggle').addEventListener('click', () => toggleRail());
    $('[data-scrim]').addEventListener('click', () => toggleRail(false));
    $('.rail-nav').addEventListener('click', (e) => { if (e.target.closest('a') && isMobile()) toggleRail(false); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && b.classList.contains('rail-open')) toggleRail(false); });
    return app;
  }

  function applyUser(me) {
    const name = me.fullName || me.username || 'User';
    $('#userName').textContent = name;
    $('#userRole').textContent = `${me.role} · @${me.username}`;
    $('#userAvatar').textContent = name.trim().charAt(0).toUpperCase();
    document.querySelectorAll('[data-nav]').forEach((a) => {
      const item = NAV.find((n) => n.key === a.dataset.nav);
      a.hidden = !!(item.allow && !item.allow(me.role));
    });
  }

  function setHero({ title, sub } = {}) {
    if (title !== undefined) $('#heroTitle').textContent = title;
    if (sub !== undefined) $('#heroSub').textContent = sub;
  }

  /* ---------- boot ---------- */
  const meRequest = api('/api/me');             // start immediately, in parallel with page scripts
  meRequest.catch(() => {});                    // handled via ISS.ready consumers (401 already redirects)
  buildShell();
  const ready = meRequest.then((me) => { applyUser(me); return me; });

  // Friendly messages for ?error=… redirects from the server
  const ERR = {
    admin_denied: 'Only Administrators and Presidents can open the Admin Panel.',
    activity_denied: 'Only Administrators and Presidents can view the Activity Log.',
    bin_denied: 'Officers cannot open the Recycle Bin.',
  };
  const q = new URLSearchParams(location.search).get('error');
  if (q && ERR[q]) { ready.then(() => alertDialog({ icon: 'fa-lock', tone: 'danger', title: 'Access denied', text: ERR[q], confirm: 'Got it' })); history.replaceState({}, '', location.pathname); }

  window.ISS = {
    $, esc, html, debounce, store, api, toast, busy, ready, setHero,
    confirm: confirmDialog, prompt: promptDialog, alert: alertDialog,
    fmtDate, todayYMD, fileMeta, toneFor, catIcon, picker, ADMIN_ROLES,
  };
})();