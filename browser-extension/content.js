// browser-extension/content.js
// Injected into every page. Detects login forms and autofills credentials
// from the CryptoNote desktop app via the background service worker.

(function () {
  'use strict';

  // Don't run in iframes
  if (window.self !== window.top) return;

  // ── Styles injected into the page ────────────────────────────────────────
  const style = document.createElement('style');
  style.textContent = `
    .cn-icon-wrapper {
      position: absolute !important;
      right: 8px !important;
      top: 50% !important;
      transform: translateY(-50%) !important;
      width: 20px !important;
      height: 20px !important;
      cursor: pointer !important;
      z-index: 2147483647 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      opacity: 0.6 !important;
      transition: opacity 0.15s !important;
    }
    .cn-icon-wrapper:hover { opacity: 1 !important; }
    .cn-icon-wrapper svg { display: block; }

    /* Subtle glow on fields that have a CryptoNote suggestion */
    .cn-has-suggestion {
      outline: none !important;
    }
    .cn-has-suggestion:focus {
      box-shadow: 0 0 0 2px rgba(0, 229, 160, 0.35) !important;
    }
  `;
  document.head.appendChild(style);

  // ── Lock SVG icon ─────────────────────────────────────────────────────────
  const LOCK_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00e5a0" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;

  // ── Form detection ─────────────────────────────────────────────────────────
  function getLoginForms() {
    const forms = [];
    const passwordFields = document.querySelectorAll(
      'input[type="password"]:not([data-cn-processed])'
    );

    passwordFields.forEach(pwField => {
      const container = pwField.closest('form') || document;

      // Try to find the best username/email field
      const candidates = [
        ...Array.from(container.querySelectorAll(
          'input[type="email"], input[type="text"], input[type="tel"]'
        ))
      ].filter(el => {
        const name = (el.name + el.id + el.placeholder).toLowerCase();
        return name.match(/user|email|login|mail|phone|account/);
      });

      const usernameField = candidates[0] || container.querySelector(
        'input[type="email"], input[type="text"]'
      );

      if (usernameField && pwField) {
        forms.push({ usernameField, pwField });
      }
    });

    return forms;
  }

  // ── Inject CryptoNote icon into a field ────────────────────────────────────
  function injectIcon(input, onClickFill) {
    // Ensure the parent is positioned
    const parent = input.parentElement;
    const pos = window.getComputedStyle(parent).position;
    if (pos === 'static') parent.style.position = 'relative';

    const wrapper = document.createElement('div');
    wrapper.className = 'cn-icon-wrapper';
    wrapper.innerHTML = LOCK_SVG;
    wrapper.title = 'Autofill with CryptoNote';
    wrapper.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      onClickFill();
    });

    parent.appendChild(wrapper);
    return wrapper;
  }

  // ── Fill a form with credentials ───────────────────────────────────────────
  function fillForm(usernameField, pwField, username, password) {
    usernameField.value = username;
    pwField.value       = password;

    // Trigger framework change detection (React, Vue, Angular)
    [usernameField, pwField].forEach(el => {
      el.dispatchEvent(new Event('input',  { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    });
  }

  // ── Auto-suggest on page load ──────────────────────────────────────────────
  async function autoSuggest() {
    const forms = getLoginForms();
    if (forms.length === 0) return;

    const response = await new Promise(resolve => {
      chrome.runtime.sendMessage(
        { action: 'get_logins', url: window.location.origin },
        resolve
      );
    }).catch(() => null);

    if (!response || response.error || !response.logins?.length) return;

    const login = response.logins[0];

    forms.forEach(({ usernameField, pwField }) => {
      // Mark as processed so we don't double-process
      pwField.setAttribute('data-cn-processed', '1');
      usernameField.classList.add('cn-has-suggestion');
      pwField.classList.add('cn-has-suggestion');

      // Inject icon next to the username field
      injectIcon(usernameField, () => {
        fillForm(usernameField, pwField, login.username, login.password);
      });

      // Auto-fill when user focuses the username field (first time only)
      usernameField.addEventListener('focus', () => {
        if (!usernameField.value) {
          fillForm(usernameField, pwField, login.username, login.password);
        }
      }, { once: true });
    });
  }

  // ── Auto-save on form submit ───────────────────────────────────────────────
  document.addEventListener('submit', (e) => {
    const form = e.target;
    const pwField = form.querySelector('input[type="password"]');
    const unField = form.querySelector(
      'input[type="email"], input[type="text"][name*="user"], input[name*="email"], input[type="text"]'
    );

    if (pwField?.value && unField?.value) {
      // Notify background to show save prompt in popup
      chrome.runtime.sendMessage({
        action:   'new_credentials_detected',
        url:      window.location.origin,
        username: unField.value,
        password: pwField.value,
      });
    }
  }, true); // capture phase so we catch before the form navigates

  // ── Listen for force-fill from popup ──────────────────────────────────────
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'force_autofill') {
      const forms = getLoginForms();
      if (forms.length === 0) {
        // Try any password field as fallback
        const pw = document.querySelector('input[type="password"]');
        const un = document.querySelector('input[type="email"], input[type="text"]');
        if (un && pw) {
          fillForm(un, pw, request.username, request.password);
          sendResponse({ success: true });
        } else {
          sendResponse({ success: false, error: 'No login form found' });
        }
        return;
      }

      forms.forEach(({ usernameField, pwField }) => {
        fillForm(usernameField, pwField, request.username, request.password);
      });
      sendResponse({ success: true });
    }
  });

  // ── Wait for DOM before running ────────────────────────────────────────────
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(autoSuggest, 600));
  } else {
    setTimeout(autoSuggest, 600);
  }

  // Re-run on dynamic navigation (SPAs)
  let lastUrl = location.href;
  new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      setTimeout(autoSuggest, 800);
    }
  }).observe(document, { subtree: true, childList: true });

})();
