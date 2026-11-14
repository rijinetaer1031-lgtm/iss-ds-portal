/* ==========================================================================
   ISS-DS document helpers (needs app.js)
   ISS.docs.row / card   -> HTML for a document (all user text is escaped)
   ISS.docs.bind(el, getDoc, handlers) -> one delegated click listener for [data-act]
   ISS.docs.preview(doc) -> viewer dialog      ISS.docs.approve(doc, onDone)
   ========================================================================== */
(function () {
  'use strict';
  const { esc, api, toast, html, $ } = ISS;
  const APPROVER_ROLES = ['President'];
  const BROWSER_PREVIEW = ['pdf', 'txt', 'png', 'jpg', 'jpeg'];
  const OFFICE = ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'];

  function approvalBadge(doc, role) {
    if (doc.approval_status === 'Approved') {
      const by = doc.approver ? ` title="Approved by @${esc(doc.approver)}"` : '';
      return `<span class="badge badge-ok"${by}><i class="fa-solid fa-circle-check"></i> Approved</span>`;
    }
    if (APPROVER_ROLES.includes(role)) {
      return `<button class="badge badge-wait" data-act="approve" data-id="${doc.id}" title="Approve this document"><i class="fa-solid fa-check"></i> Approve</button>`;
    }
    return '<span class="badge badge-wait"><i class="fa-solid fa-clock"></i> Pending</span>';
  }

  /** List row used on the Documents page. opts: { edit, remove } */
  function row(doc, role, opts = {}) {
    const m = ISS.fileMeta(doc.standardized_file_name);
    const event = doc.subfolder && doc.subfolder !== 'General' ? `<span><i class="fa-solid fa-ticket"></i>${esc(doc.subfolder)}</span>` : '';
    return `<article class="doc ${m.cls}">
      <div class="doc-ico"><i class="fa-solid ${m.icon}"></i></div>
      <div class="doc-main">
        <h4 title="${esc(doc.standardized_file_name)}">${esc(doc.title)}</h4>
        <div class="doc-meta">
          <span title="Standardized file name"><i class="fa-regular fa-file"></i>${esc(doc.standardized_file_name)}</span>
          <span><i class="fa-regular fa-calendar"></i>${ISS.fmtDate(doc.document_date)}</span>
          <span><i class="fa-solid fa-code-branch"></i>v${doc.version_number}</span>${event}
        </div>
      </div>
      <div class="doc-actions">
        ${approvalBadge(doc, role)}
        ${opts.edit ? `<button class="btn btn-ghost btn-sm" data-act="edit" data-id="${doc.id}" title="Edit details" aria-label="Edit ${esc(doc.title)}"><i class="fa-solid fa-pen"></i></button>` : ''}
        <button class="btn btn-ghost btn-sm" data-act="preview" data-id="${doc.id}"><i class="fa-regular fa-eye"></i><span>Preview</span></button>
        <a class="btn btn-ghost btn-sm" href="${esc(doc.file_url)}" download title="Download" aria-label="Download ${esc(doc.title)}"><i class="fa-solid fa-cloud-arrow-down"></i></a>
        ${opts.remove && role !== 'Officer' ? `<button class="btn btn-ghost btn-sm" data-act="remove" data-id="${doc.id}" title="Move to Recycle Bin" aria-label="Delete ${esc(doc.title)}" style="color:var(--rose)"><i class="fa-solid fa-trash-can"></i></button>` : ''}
      </div>
    </article>`;
  }

  /** Card used on the dashboard grid. */
  function card(doc, index, role) {
    const m = ISS.fileMeta(doc.standardized_file_name);
    return `<article class="doc-card ${m.cls}" style="--i:${Math.min(index, 12)}">
      <div class="top"><div class="doc-ico"><i class="fa-solid ${m.icon}"></i></div>${approvalBadge(doc, role)}</div>
      <div><span class="badge badge-violet" style="margin-bottom:8px"><i class="fa-solid ${ISS.catIcon(doc.category)}"></i> ${esc(doc.category)}</span>
        <h4 title="${esc(doc.standardized_file_name)}">${esc(doc.title)}</h4>
        <div class="doc-meta"><span><i class="fa-regular fa-calendar"></i>${ISS.fmtDate(doc.document_date)}</span><span><i class="fa-solid fa-code-branch"></i>v${doc.version_number}</span></div></div>
      <div class="bottom">
        <button class="btn btn-ghost btn-sm" data-act="preview" data-id="${doc.id}"><i class="fa-regular fa-eye"></i> Preview</button>
        <a class="btn btn-ghost btn-sm" href="${esc(doc.file_url)}" download aria-label="Download ${esc(doc.title)}"><i class="fa-solid fa-cloud-arrow-down"></i></a>
      </div></article>`;
  }

  /** One delegated listener instead of an inline onclick per button. */
  function bind(container, getDoc, handlers = {}) {
    container.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-act]');
      if (!btn || !container.contains(btn)) return;
      const doc = getDoc(Number(btn.dataset.id));
      if (!doc) return;
      const fn = { preview, approve: (d) => approve(d, handlers.changed), ...handlers }[btn.dataset.act];
      if (fn) fn(doc, btn);
    });
  }

  /* ---------- viewer ---------- */
  let viewer;
  function ensureViewer() {
    if (viewer) return viewer;
    viewer = html(`<dialog class="dlg viewer" aria-label="Document preview"><div class="dlg-body">
      <div class="dlg-head" style="margin:0"><h3><i class="fa-solid fa-file-lines"></i><span id="vTitle"></span></h3>
        <button class="icon-btn" data-close aria-label="Close preview"><i class="fa-solid fa-xmark"></i></button></div>
      <div id="vStage" style="flex:1;display:flex;flex-direction:column;min-height:0"></div>
      <div style="display:flex;justify-content:flex-end"><a class="btn btn-primary" id="vDl" download><i class="fa-solid fa-cloud-arrow-down"></i> Download original</a></div>
    </div></dialog>`);
    viewer.addEventListener('close', () => { $('#vStage', viewer).innerHTML = ''; }); // stop loading + free memory
    document.body.append(viewer);
    return viewer;
  }

  const fallback = (msg) => `<div class="viewer-fallback"><div><i class="fa-regular fa-eye-slash"></i><strong>Preview unavailable</strong><p style="margin-top:6px;max-width:44ch">${msg}</p></div></div>`;

  async function preview(doc) {
    const v = ensureViewer(), stage = $('#vStage', v);
    $('#vTitle', v).textContent = doc.title;
    $('#vDl', v).href = doc.file_url;
    stage.innerHTML = '';
    v.showModal();
    const ext = ISS.fileMeta(doc.standardized_file_name).ext;
    api(`/api/activity/log-view/${doc.id}`, { method: 'POST' }).catch(() => {}); // fire-and-forget view counter

    if (BROWSER_PREVIEW.includes(ext)) {
      stage.innerHTML = `<iframe title="Preview of ${esc(doc.title)}" src="${esc(doc.file_url)}"></iframe>`;
    } else if (OFFICE.includes(ext)) {
      if (['localhost', '127.0.0.1'].includes(location.hostname)) {
        stage.innerHTML = fallback('Office files can only be previewed once the site is online. Use <b>Download original</b> for now.');
        return;
      }
      stage.innerHTML = '<div class="skeleton" style="flex:1"></div>';
      try {
        const { url } = await api(`/api/documents/${doc.id}/preview-link`);
        const full = encodeURIComponent(location.origin + url);
        stage.innerHTML = `<iframe title="Preview of ${esc(doc.title)}" src="https://docs.google.com/gview?url=${full}&embedded=true"></iframe>`;
      } catch (err) { stage.innerHTML = fallback(esc(err.message)); }
    } else {
      stage.innerHTML = fallback('This file type opens best after you download it.');
    }
  }

  /* ---------- approval ---------- */
  async function approve(doc, onDone) {
    const ok = await ISS.confirm({ icon: 'fa-stamp', tone: 'ok', title: 'Approve this document?', text: `“${doc.title}” will be marked as officially approved. This is recorded in the activity log.`, confirm: 'Approve' });
    if (!ok) return;
    try {
      await api(`/api/documents/approve/${doc.id}`, { method: 'POST' });
      toast('Document approved.');
      if (onDone) onDone(doc);
    } catch (err) { toast(err.message, 'err'); }
  }

  ISS.docs = { row, card, bind, preview, approve, approvalBadge };
})();