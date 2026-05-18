// browser-extension/content.js
// Injected into every page. Detects login forms and provides inline autofill
// dropdown from the CryptoNote desktop app via the background service worker.

(function () {
  'use strict';

  // Don't run in iframes unless they contain login forms
  const isIframe = window.self !== window.top;

  // ── Constants ──────────────────────────────────────────────────────────────
  const PROCESSED_ATTR = 'data-cn-processed';
  const DROPDOWN_ID    = 'cn-autofill-dropdown';
  const ICON_ID_PREFIX = 'cn-icon-';
  let iconIdCounter    = 0;

  // ── Styles injected into the page ──────────────────────────────────────────
  const style = document.createElement('style');
  style.textContent = `
    .cn-icon-wrapper {
      position: absolute !important;
      right: 8px !important;
      top: 50% !important;
      transform: translateY(-50%) !important;
      width: 22px !important;
      height: 22px !important;
      cursor: pointer !important;
      z-index: 2147483646 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      opacity: 0.5 !important;
      transition: opacity 0.2s, transform 0.2s !important;
      border-radius: 4px !important;
      padding: 2px !important;
    }
    .cn-icon-wrapper:hover {
      opacity: 1 !important;
      transform: translateY(-50%) scale(1.1) !important;
    }
    .cn-icon-wrapper svg { display: block; }

    /* Subtle glow on fields that have a CryptoNote suggestion */
    .cn-has-suggestion:focus {
      box-shadow: 0 0 0 2px rgba(0, 229, 160, 0.3) !important;
    }

    /* Autofill dropdown */
    #${DROPDOWN_ID} {
      position: fixed !important;
      z-index: 2147483647 !important;
      background: #0d1117 !important;
      border: 1px solid rgba(0, 229, 160, 0.25) !important;
      border-radius: 10px !important;
      box-shadow: 0 12px 40px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.04) !important;
      padding: 6px !important;
      min-width: 280px !important;
      max-width: 360px !important;
      max-height: 280px !important;
      overflow-y: auto !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', sans-serif !important;
      animation: cnDropdownIn 0.18s ease-out !important;
    }

    @keyframes cnDropdownIn {
      from { opacity: 0; transform: translateY(-4px); }
      to   { opacity: 1; transform: translateY(0); }
    }

    #${DROPDOWN_ID}::-webkit-scrollbar { width: 4px; }
    #${DROPDOWN_ID}::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 4px; }

    .cn-dropdown-header {
      display: flex !important;
      align-items: center !important;
      gap: 7px !important;
      padding: 7px 10px 6px !important;
      font-size: 10.5px !important;
      font-weight: 700 !important;
      text-transform: uppercase !important;
      letter-spacing: 0.8px !important;
      color: #4a5568 !important;
    }
    .cn-dropdown-header svg { flex-shrink: 0; }

    .cn-dropdown-item {
      display: flex !important;
      align-items: center !important;
      gap: 10px !important;
      padding: 9px 10px !important;
      border-radius: 7px !important;
      cursor: pointer !important;
      transition: background 0.15s !important;
      border: none !important;
      background: none !important;
      width: 100% !important;
      text-align: left !important;
      font-family: inherit !important;
    }
    .cn-dropdown-item:hover, .cn-dropdown-item:focus {
      background: rgba(255,255,255,0.05) !important;
      outline: none !important;
    }
    .cn-dropdown-item:active {
      background: rgba(0,229,160,0.1) !important;
    }

    .cn-dropdown-favicon {
      width: 28px !important;
      height: 28px !important;
      border-radius: 7px !important;
      background: #111820 !important;
      border: 1px solid rgba(255,255,255,0.07) !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      font-size: 13px !important;
      flex-shrink: 0 !important;
      overflow: hidden !important;
      color: #eaf0f6 !important;
    }
    .cn-dropdown-favicon img {
      width: 16px !important;
      height: 16px !important;
      object-fit: contain !important;
    }

    .cn-dropdown-info {
      flex: 1 !important;
      overflow: hidden !important;
    }
    .cn-dropdown-title {
      font-weight: 600 !important;
      font-size: 13px !important;
      color: #eaf0f6 !important;
      white-space: nowrap !important;
      overflow: hidden !important;
      text-overflow: ellipsis !important;
    }
    .cn-dropdown-user {
      font-size: 11.5px !important;
      color: #8b9ab0 !important;
      margin-top: 1px !important;
      white-space: nowrap !important;
      overflow: hidden !important;
      text-overflow: ellipsis !important;
    }

    .cn-dropdown-fill-tag {
      font-size: 10px !important;
      font-weight: 600 !important;
      color: #00e5a0 !important;
      background: rgba(0,229,160,0.1) !important;
      border: 1px solid rgba(0,229,160,0.2) !important;
      padding: 2px 7px !important;
      border-radius: 4px !important;
      flex-shrink: 0 !important;
      letter-spacing: 0.3px !important;
    }

    .cn-dropdown-empty {
      padding: 16px !important;
      text-align: center !important;
      color: #4a5568 !important;
      font-size: 12px !important;
    }

    .cn-dropdown-footer {
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      padding: 6px 10px !important;
      margin-top: 2px !important;
      border-top: 1px solid rgba(255,255,255,0.05) !important;
      gap: 4px !important;
    }
    .cn-dropdown-footer span {
      font-size: 10px !important;
      color: #4a5568 !important;
      letter-spacing: 0.3px !important;
    }
  `;
  document.head.appendChild(style);

  // ── SVG icons ──────────────────────────────────────────────────────────────
  const LOCK_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00e5a0" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;

  const SHIELD_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#00e5a0" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;

  // ── State ──────────────────────────────────────────────────────────────────
  let cachedLogins = null;
  let activeDropdown = null;
  let activeField = null;
  let selectedIndex = -1;

  // ── Helpers ────────────────────────────────────────────────────────────────
  function sendMessage(msg) {
    return new Promise(resolve => {
      try {
        chrome.runtime.sendMessage(msg, response => {
          if (chrome.runtime.lastError) resolve(null);
          else resolve(response);
        });
      } catch { resolve(null); }
    });
  }

  function getFaviconUrl(url) {
    try { return `${new URL(url).origin}/favicon.ico`; }
    catch { return null; }
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function domainMatch(entryUrl, pageOrigin) {
    try {
      const entryHost = new URL(entryUrl).hostname.toLowerCase();
      const pageHost  = new URL(pageOrigin).hostname.toLowerCase();
      // Exact match or subdomain match
      return pageHost === entryHost || pageHost.endsWith('.' + entryHost);
    } catch { return false; }
  }

  // ── Form detection (robust multi-strategy) ────────────────────────────────
  function findLoginFields() {
    const results = [];
    const passwordFields = document.querySelectorAll(
      `input[type="password"]:not([${PROCESSED_ATTR}]):not([aria-hidden="true"])`
    );

    passwordFields.forEach(pwField => {
      if (pwField.offsetParent === null && !pwField.closest('[style*="visibility"]')) return; // hidden

      const container = pwField.closest('form') || pwField.parentElement?.parentElement?.parentElement || document;

      // Strategy 1: Look for labeled username/email fields
      const candidates = Array.from(container.querySelectorAll(
        'input[type="email"], input[type="text"], input[type="tel"], input[autocomplete~="username"], input[autocomplete~="email"]'
      )).filter(el => {
        if (el.type === 'hidden' || el.offsetParent === null) return false;
        const meta = (el.name + ' ' + el.id + ' ' + el.placeholder + ' ' + (el.getAttribute('aria-label') || '')).toLowerCase();
        return meta.match(/user|email|login|mail|phone|account|id|name|handle/);
      });

      // Strategy 2: Any text/email input before the password field in DOM order
      let usernameField = candidates[0];
      if (!usernameField) {
        const allInputs = Array.from(container.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"])'));
        const pwIdx = allInputs.indexOf(pwField);
        for (let i = pwIdx - 1; i >= 0; i--) {
          const inp = allInputs[i];
          if (inp.type === 'email' || inp.type === 'text' || inp.type === 'tel') {
            usernameField = inp;
            break;
          }
        }
      }

      // Strategy 3: Fallback to first text/email in container
      if (!usernameField) {
        usernameField = container.querySelector('input[type="email"], input[type="text"]');
      }

      if (usernameField && pwField) {
        results.push({ usernameField, pwField, form: pwField.closest('form') });
      }
    });

    return results;
  }

  // ── Fill form with framework-compatible events ─────────────────────────────
  function fillField(field, value) {
    // Use native setter to bypass React/Vue/Angular controlled components
    const nativeSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    )?.set;

    if (nativeSetter) {
      nativeSetter.call(field, value);
    } else {
      field.value = value;
    }

    // Dispatch comprehensive events for all frameworks
    field.dispatchEvent(new Event('input',    { bubbles: true, composed: true }));
    field.dispatchEvent(new Event('change',   { bubbles: true, composed: true }));
    field.dispatchEvent(new Event('blur',     { bubbles: true }));
    field.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'a' }));
    field.dispatchEvent(new KeyboardEvent('keyup',   { bubbles: true, key: 'a' }));
  }

  function fillForm(usernameField, pwField, username, password) {
    if (usernameField) fillField(usernameField, username);
    if (pwField)       fillField(pwField, password);

    // Brief visual feedback
    [usernameField, pwField].filter(Boolean).forEach(el => {
      el.style.transition = 'box-shadow 0.3s ease';
      el.style.boxShadow = '0 0 0 2px rgba(0,229,160,0.5)';
      setTimeout(() => { el.style.boxShadow = ''; }, 1200);
    });
  }

  // ── Inline Autofill Dropdown ──────────────────────────────────────────────
  function closeDropdown() {
    const existing = document.getElementById(DROPDOWN_ID);
    if (existing) existing.remove();
    activeDropdown = null;
    activeField = null;
    selectedIndex = -1;
  }

  function positionDropdown(dropdown, anchorField) {
    const rect = anchorField.getBoundingClientRect();
    let top  = rect.bottom + 4;
    let left = rect.left;

    // Ensure dropdown doesn't overflow viewport
    const maxW = Math.min(360, window.innerWidth - 16);
    if (left + maxW > window.innerWidth) left = window.innerWidth - maxW - 8;
    if (left < 8) left = 8;

    // If not enough space below, show above
    if (top + 280 > window.innerHeight && rect.top > 280) {
      top = rect.top - dropdown.offsetHeight - 4;
    }

    dropdown.style.top  = top + 'px';
    dropdown.style.left = left + 'px';
    dropdown.style.width = Math.max(rect.width, 280) + 'px';
  }

  function showDropdown(anchorField, loginPairs, logins) {
    closeDropdown();
    if (!logins || logins.length === 0) return;

    const dropdown = document.createElement('div');
    dropdown.id = DROPDOWN_ID;

    // Header
    dropdown.innerHTML = `
      <div class="cn-dropdown-header">
        ${SHIELD_SVG}
        <span>CryptoNote</span>
      </div>
    `;

    // Sort: matching-site logins first
    const pageOrigin = window.location.origin;
    const sorted = [...logins].sort((a, b) => {
      const aMatch = a.url && domainMatch(a.url, pageOrigin) ? 0 : 1;
      const bMatch = b.url && domainMatch(b.url, pageOrigin) ? 0 : 1;
      return aMatch - bMatch;
    });

    // Render items
    sorted.forEach((login, idx) => {
      const item = document.createElement('button');
      item.className = 'cn-dropdown-item';
      item.setAttribute('data-idx', idx);
      item.tabIndex = -1;

      const title    = login.title || login.url || 'Unnamed';
      const username = login.username || 'No username';
      const favicon  = login.url ? getFaviconUrl(login.url) : null;
      const initial  = (title[0] || '?').toUpperCase();
      const isMatch  = login.url && domainMatch(login.url, pageOrigin);

      item.innerHTML = `
        <div class="cn-dropdown-favicon">
          ${favicon
            ? `<img src="${escapeHtml(favicon)}" alt="" onerror="this.parentElement.innerHTML='<span>${initial}</span>'">`
            : `<span>${initial}</span>`
          }
        </div>
        <div class="cn-dropdown-info">
          <div class="cn-dropdown-title">${escapeHtml(title)}</div>
          <div class="cn-dropdown-user">${escapeHtml(username)}</div>
        </div>
        ${isMatch ? '<span class="cn-dropdown-fill-tag">FILL</span>' : ''}
      `;

      item.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        // Find the correct pair for this anchor
        const pair = loginPairs.find(p => p.usernameField === anchorField || p.pwField === anchorField);
        if (pair) {
          fillForm(pair.usernameField, pair.pwField, login.username, login.password);
        } else {
          // Fallback: try to fill any pair
          loginPairs.forEach(p => fillForm(p.usernameField, p.pwField, login.username, login.password));
        }
        closeDropdown();
      });

      dropdown.appendChild(item);
    });

    // Footer
    const footer = document.createElement('div');
    footer.className = 'cn-dropdown-footer';
    footer.innerHTML = `${SHIELD_SVG} <span>Secured by CryptoNote</span>`;
    dropdown.appendChild(footer);

    document.body.appendChild(dropdown);
    positionDropdown(dropdown, anchorField);
    activeDropdown = dropdown;
    activeField = anchorField;
  }

  // ── Inject CryptoNote icon into a field ────────────────────────────────────
  function injectIcon(input, onClick) {
    if (input.getAttribute(PROCESSED_ATTR)) return;
    input.setAttribute(PROCESSED_ATTR, '1');

    const parent = input.parentElement;
    if (!parent) return;
    const pos = window.getComputedStyle(parent).position;
    if (pos === 'static') parent.style.position = 'relative';

    const wrapper = document.createElement('div');
    wrapper.className = 'cn-icon-wrapper';
    wrapper.id = ICON_ID_PREFIX + (iconIdCounter++);
    wrapper.innerHTML = LOCK_SVG;
    wrapper.title = 'Autofill with CryptoNote';

    wrapper.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      onClick();
    });

    parent.appendChild(wrapper);
    input.classList.add('cn-has-suggestion');

    return wrapper;
  }

  // ── Fetch logins from the desktop app ──────────────────────────────────────
  async function fetchLogins() {
    if (cachedLogins) return cachedLogins;

    const response = await sendMessage({
      action: 'get_logins',
      url: window.location.origin,
    });

    if (response && response.logins && response.logins.length > 0) {
      cachedLogins = response.logins;
      return cachedLogins;
    }

    // Fallback: fetch all logins
    const allResponse = await sendMessage({
      action: 'get_logins',
      url: '',
      query: '',
    });

    cachedLogins = (allResponse && allResponse.logins) ? allResponse.logins : [];
    return cachedLogins;
  }

  // ── Main: process login forms ──────────────────────────────────────────────
  async function processPage() {
    const loginPairs = findLoginFields();
    if (loginPairs.length === 0) return;

    const logins = await fetchLogins();
    if (!logins.length) return;

    // Find site-matching logins
    const pageOrigin = window.location.origin;
    const siteLogins = logins.filter(l => l.url && domainMatch(l.url, pageOrigin));
    const bestLogin  = siteLogins[0] || logins[0];

    loginPairs.forEach(({ usernameField, pwField }) => {
      // Inject icons
      const showDd = () => showDropdown(usernameField, loginPairs, logins);

      injectIcon(usernameField, showDd);
      injectIcon(pwField, showDd);

      // Show dropdown on focus if field is empty
      const handleFocus = (field) => {
        field.addEventListener('focus', () => {
          if (!field.value && logins.length > 0) {
            showDropdown(field, loginPairs, logins);
          }
        });
      };

      handleFocus(usernameField);
      handleFocus(pwField);

      // Auto-fill the best match if both fields are empty
      if (!usernameField.value && !pwField.value && siteLogins.length === 1) {
        fillForm(usernameField, pwField, bestLogin.username, bestLogin.password);
      }
    });
  }

  // ── Auto-save: detect form submissions ─────────────────────────────────────
  function setupAutoSave() {
    // Capture phase listener to catch before navigation
    document.addEventListener('submit', (e) => {
      const form = e.target;
      if (!(form instanceof HTMLFormElement)) return;

      const pwField = form.querySelector('input[type="password"]');
      if (!pwField || !pwField.value) return;

      // Try multiple strategies to find the username field
      const unField =
        form.querySelector('input[autocomplete~="username"]') ||
        form.querySelector('input[autocomplete~="email"]') ||
        form.querySelector('input[type="email"]') ||
        form.querySelector('input[type="text"][name*="user"]') ||
        form.querySelector('input[type="text"][name*="email"]') ||
        form.querySelector('input[type="text"][name*="login"]') ||
        form.querySelector('input[type="text"]');

      if (unField && unField.value) {
        chrome.runtime.sendMessage({
          action:   'new_credentials_detected',
          url:      window.location.origin,
          title:    document.title || window.location.hostname,
          username: unField.value,
          password: pwField.value,
        });
      }
    }, true);

    // Also detect credential submissions via XMLHttpRequest/fetch (SPAs)
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('button[type="submit"], input[type="submit"], button:not([type])');
      if (!btn) return;

      const form = btn.closest('form');
      if (!form) return;

      const pwField = form.querySelector('input[type="password"]');
      const unField = form.querySelector('input[type="email"], input[type="text"]');

      if (pwField?.value && unField?.value) {
        chrome.runtime.sendMessage({
          action:   'new_credentials_detected',
          url:      window.location.origin,
          title:    document.title || window.location.hostname,
          username: unField.value,
          password: pwField.value,
        });
      }
    }, true);
  }

  // ── Listen for force-fill from popup ──────────────────────────────────────
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'force_autofill') {
      const loginPairs = findLoginFields();

      if (loginPairs.length > 0) {
        loginPairs.forEach(({ usernameField, pwField }) => {
          fillForm(usernameField, pwField, request.username, request.password);
        });
        sendResponse({ success: true });
      } else {
        // Aggressive fallback: find any inputs that look like login fields
        const pw = document.querySelector('input[type="password"]');
        const un = document.querySelector(
          'input[type="email"], input[autocomplete~="username"], input[type="text"]'
        );
        if (un && pw) {
          fillForm(un, pw, request.username, request.password);
          sendResponse({ success: true });
        } else {
          sendResponse({ success: false, error: 'No login form found' });
        }
      }
      return true;
    }
  });

  // ── Global: close dropdown on outside click / Escape ──────────────────────
  document.addEventListener('click', (e) => {
    if (activeDropdown && !activeDropdown.contains(e.target) &&
        !e.target.closest('.cn-icon-wrapper')) {
      closeDropdown();
    }
  }, true);

  document.addEventListener('keydown', (e) => {
    if (!activeDropdown) return;

    const items = activeDropdown.querySelectorAll('.cn-dropdown-item');
    if (!items.length) return;

    if (e.key === 'Escape') {
      closeDropdown();
      activeField?.focus();
      e.preventDefault();
    } else if (e.key === 'ArrowDown') {
      selectedIndex = Math.min(selectedIndex + 1, items.length - 1);
      items.forEach((it, i) => it.style.background = i === selectedIndex ? 'rgba(255,255,255,0.05)' : '');
      items[selectedIndex]?.scrollIntoView({ block: 'nearest' });
      e.preventDefault();
    } else if (e.key === 'ArrowUp') {
      selectedIndex = Math.max(selectedIndex - 1, 0);
      items.forEach((it, i) => it.style.background = i === selectedIndex ? 'rgba(255,255,255,0.05)' : '');
      items[selectedIndex]?.scrollIntoView({ block: 'nearest' });
      e.preventDefault();
    } else if (e.key === 'Enter' && selectedIndex >= 0) {
      items[selectedIndex]?.click();
      e.preventDefault();
    }
  }, true);

  // Close dropdown on scroll/resize
  window.addEventListener('scroll', closeDropdown, true);
  window.addEventListener('resize', closeDropdown);

  // ── Initialize ────────────────────────────────────────────────────────────
  function init() {
    setupAutoSave();
    setTimeout(processPage, 500);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Re-run on dynamic navigation (SPAs) and DOM mutations
  let lastUrl = location.href;
  let debounceTimer = null;

  new MutationObserver(() => {
    // URL change detection for SPAs
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      cachedLogins = null; // Clear cache on navigation
      closeDropdown();
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(processPage, 600);
      return;
    }

    // New password fields may have been added dynamically
    const newPwFields = document.querySelectorAll(
      `input[type="password"]:not([${PROCESSED_ATTR}])`
    );
    if (newPwFields.length > 0) {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(processPage, 400);
    }
  }).observe(document.documentElement, { subtree: true, childList: true });

})();
