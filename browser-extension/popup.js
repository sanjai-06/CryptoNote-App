// browser-extension/popup.js
// Enhanced popup with save prompt, search, favicons, fill button, and add-new modal

document.addEventListener('DOMContentLoaded', async () => {
  // ── DOM refs ────────────────────────────────────────────────────────────────
  const statusDot    = document.getElementById('status-indicator');
  const statusBadge  = document.getElementById('status-badge');
  const statusText   = document.getElementById('status-text');
  const lockedView   = document.getElementById('locked-view');
  const unlockedView = document.getElementById('unlocked-view');
  const btnRefresh   = document.getElementById('btn-refresh');
  const searchInput  = document.getElementById('search-input');
  const clearBtn     = document.getElementById('btn-clear-search');
  const loginList    = document.getElementById('login-list');
  const listTitle    = document.getElementById('list-title');
  const listCount    = document.getElementById('list-count');
  const siteUrl      = document.getElementById('current-site-url');
  const savePrompt   = document.getElementById('save-prompt');
  const savePromptUrl= document.getElementById('save-prompt-url');
  const btnSaveConf  = document.getElementById('btn-save-confirm');
  const btnSaveDism  = document.getElementById('btn-save-dismiss');
  const addModal     = document.getElementById('add-modal');
  const btnAddNew    = document.getElementById('btn-add-new');
  const btnCloseModal= document.getElementById('btn-close-modal');
  const newTitle     = document.getElementById('new-title');
  const newUsername  = document.getElementById('new-username');
  const newPassword  = document.getElementById('new-password');
  const btnTogglePass= document.getElementById('btn-toggle-pass');
  const btnSaveNew   = document.getElementById('btn-save-new');

  let currentUrl  = '';
  let currentHost = '';
  let currentTab  = null;
  let allLogins   = [];
  let pendingSave = null;

  // ── Get current tab info ────────────────────────────────────────────────────
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tabs.length > 0) {
    currentTab = tabs[0];
    try {
      const url = new URL(tabs[0].url);
      if (url.protocol === 'http:' || url.protocol === 'https:') {
        currentUrl  = url.origin;
        currentHost = url.hostname;
      }
    } catch(e) {}
  }

  siteUrl.textContent = currentHost || '—';

  // ── Helpers ─────────────────────────────────────────────────────────────────

  function showToast(msg, duration = 1800) {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), duration);
  }

  function getFaviconUrl(url) {
    try {
      const origin = new URL(url).origin;
      return `${origin}/favicon.ico`;
    } catch { return null; }
  }

  function getFallbackEmoji(title) {
    const first = (title || '?').trim()[0].toUpperCase();
    return first;
  }

  async function sendMsg(action, data = {}) {
    return new Promise(resolve => {
      chrome.runtime.sendMessage({ action, ...data }, response => {
        if (chrome.runtime.lastError) resolve({ error: chrome.runtime.lastError.message });
        else resolve(response || {});
      });
    });
  }

  // ── Status check ────────────────────────────────────────────────────────────
  async function checkStatus() {
    const res = await sendMsg('get_status');
    return res && res.isConnected && res.isUnlocked;
  }

  // ── Fetch logins ────────────────────────────────────────────────────────────
  async function fetchLogins(query = '', filterUrl = '') {
    const res = await sendMsg('get_logins', { url: filterUrl, query });
    return (res && res.logins) ? res.logins : [];
  }

  // ── Render logins ────────────────────────────────────────────────────────────
  function renderLogins(logins) {
    loginList.innerHTML = '';
    listCount.textContent = logins.length > 0 ? `${logins.length}` : '';

    if (logins.length === 0) {
      loginList.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">🔍</div>
          <div class="empty-state-title">No logins found</div>
          <div class="empty-state-desc">Try a different search or add a new login using the + button below.</div>
        </div>`;
      return;
    }

    logins.forEach(login => {
      const item = document.createElement('div');
      item.className = 'login-item';

      const titleStr = login.title || login.url || 'Unnamed Entry';
      const userStr  = login.username || 'No username';
      const faviconUrl = login.url ? getFaviconUrl(login.url) : null;
      const fallback   = getFallbackEmoji(titleStr);

      item.innerHTML = `
        <div class="login-favicon" data-fallback="${fallback}">
          ${faviconUrl
            ? `<img src="${faviconUrl}" alt="" onerror="this.parentElement.innerHTML='<span>${fallback}</span>'">`
            : `<span>${fallback}</span>`
          }
        </div>
        <div class="login-info">
          <div class="login-title">${escapeHtml(titleStr)}</div>
          <div class="login-username">${escapeHtml(userStr)}</div>
        </div>
        <div class="login-actions">
          <button class="btn-fill fill-btn" title="Autofill this login">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>
            Fill
          </button>
          <button class="action-btn copy-user" data-val="${escapeAttr(login.username || '')}" title="Copy username">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
          <button class="action-btn copy-pass" data-val="${escapeAttr(login.password || '')}" title="Copy password">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </button>
        </div>`;

      // Fill button
      item.querySelector('.fill-btn').addEventListener('click', (e) => {
        e.stopPropagation();
        doFill(login);
      });

      // Copy username
      item.querySelector('.copy-user').addEventListener('click', (e) => {
        e.stopPropagation();
        copyToClipboard(login.username || '', 'Username copied!');
      });

      // Copy password
      item.querySelector('.copy-pass').addEventListener('click', (e) => {
        e.stopPropagation();
        copyToClipboard(login.password || '', 'Password copied!');
      });

      // Click item row → fill
      item.addEventListener('click', () => doFill(login));

      loginList.appendChild(item);
    });
  }

  function doFill(login) {
    if (!currentTab) return;
    chrome.tabs.sendMessage(currentTab.id, {
      action: 'force_autofill',
      username: login.username,
      password: login.password
    }, () => {
      showToast('✓ Filled!');
      setTimeout(() => window.close(), 800);
    });
  }

  function copyToClipboard(text, msg) {
    navigator.clipboard.writeText(text)
      .then(() => showToast('✓ ' + msg))
      .catch(() => showToast('Copy failed'));
  }

  function escapeHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function escapeAttr(str) {
    return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // ── Init (load vault state) ─────────────────────────────────────────────────
  async function init() {
    loginList.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Loading vault…</span></div>';

    const isUnlocked = await checkStatus();

    if (!isUnlocked) {
      statusDot.classList.remove('active');
      statusBadge.classList.remove('unlocked');
      statusText.textContent = 'Locked';
      lockedView.classList.remove('hidden');
      unlockedView.classList.add('hidden');
      return;
    }

    statusDot.classList.add('active');
    statusBadge.classList.add('unlocked');
    statusText.textContent = 'Unlocked';
    lockedView.classList.add('hidden');
    unlockedView.classList.remove('hidden');

    // Pre-fill new-login title with current site
    if (currentHost) {
      newTitle.value = currentHost;
    }

    // Fetch suggested logins for this site first
    if (currentUrl) {
      listTitle.textContent = 'Suggested Logins';
      allLogins = await fetchLogins('', currentUrl);
    }

    // Fallback: show all logins
    if (!allLogins.length) {
      listTitle.textContent = 'All Vault Logins';
      allLogins = await fetchLogins();
    }

    renderLogins(allLogins);

    // Check for pending save prompt from content script
    chrome.storage.session.get(['pendingSave'], ({ pendingSave: ps }) => {
      if (ps && ps.url) {
        pendingSave = ps;
        savePromptUrl.textContent = ps.url;
        savePrompt.classList.remove('hidden');
      }
    });
  }

  // ── Search ──────────────────────────────────────────────────────────────────
  let searchTimeout = null;

  searchInput.addEventListener('input', (e) => {
    const q = e.target.value.trim();
    clearBtn.classList.toggle('hidden', !q);
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(async () => {
      if (q) {
        listTitle.textContent = 'Search Results';
        const results = await fetchLogins(q, '');
        renderLogins(results);
      } else {
        listTitle.textContent = currentUrl ? 'Suggested Logins' : 'All Vault Logins';
        renderLogins(allLogins);
      }
    }, 250);
  });

  clearBtn.addEventListener('click', () => {
    searchInput.value = '';
    clearBtn.classList.add('hidden');
    listTitle.textContent = currentUrl ? 'Suggested Logins' : 'All Vault Logins';
    renderLogins(allLogins);
    searchInput.focus();
  });

  // ── Save prompt ─────────────────────────────────────────────────────────────
  btnSaveConf.addEventListener('click', async () => {
    if (!pendingSave) return;
    await sendMsg('save_login', {
      url: pendingSave.url,
      username: pendingSave.username,
      password: pendingSave.password,
    });
    chrome.storage.session.remove('pendingSave');
    savePrompt.classList.add('hidden');
    showToast('✓ Login saved to vault!');
    allLogins = await fetchLogins();
    renderLogins(allLogins);
  });

  btnSaveDism.addEventListener('click', () => {
    chrome.storage.session.remove('pendingSave');
    savePrompt.classList.add('hidden');
    pendingSave = null;
  });

  // ── Refresh ─────────────────────────────────────────────────────────────────
  btnRefresh.addEventListener('click', init);

  // ── Add new modal ────────────────────────────────────────────────────────────
  btnAddNew.addEventListener('click', () => {
    addModal.classList.remove('hidden');
    newUsername.focus();
  });

  btnCloseModal.addEventListener('click', () => {
    addModal.classList.add('hidden');
  });

  btnTogglePass.addEventListener('click', () => {
    const isPass = newPassword.type === 'password';
    newPassword.type = isPass ? 'text' : 'password';
    btnTogglePass.innerHTML = isPass
      ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`
      : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
  });

  btnSaveNew.addEventListener('click', async () => {
    const title    = newTitle.value.trim();
    const username = newUsername.value.trim();
    const password = newPassword.value;

    if (!username || !password) {
      showToast('⚠ Username and password required');
      return;
    }

    btnSaveNew.disabled = true;
    btnSaveNew.textContent = 'Saving…';

    const res = await sendMsg('save_login', {
      url:      currentUrl || title || 'unknown',
      username,
      password,
      title:    title || currentHost || username,
    });

    btnSaveNew.disabled = false;
    btnSaveNew.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Save to Vault`;

    if (res && !res.error) {
      showToast('✓ Saved to vault!');
      addModal.classList.add('hidden');
      // Refresh list
      allLogins = await fetchLogins();
      listTitle.textContent = 'All Vault Logins';
      renderLogins(allLogins);
    } else {
      showToast('⚠ Save failed — is the app running?');
    }
  });

  // ── Keyboard shortcuts ───────────────────────────────────────────────────────
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (!addModal.classList.contains('hidden')) {
        addModal.classList.add('hidden');
      } else {
        window.close();
      }
    }
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
  });

  // ── Start ────────────────────────────────────────────────────────────────────
  init();
});
