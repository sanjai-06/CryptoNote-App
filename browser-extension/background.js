// browser-extension/background.js
// Service worker – bridges the popup / content scripts with the
// CryptoNote desktop app via Native Messaging.
// Compatible with both Chrome (Manifest V3) and Firefox (Manifest V3/V2).

const HOST_NAME = 'com.cryptonote.app';

// ── Browser API compatibility layer ──────────────────────────────────────────
const browserAPI = typeof browser !== 'undefined' ? browser : chrome;

// ── Native messaging helper ──────────────────────────────────────────────────
async function sendToNativeHost(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(HOST_NAME, message, (response) => {
        if (chrome.runtime.lastError) {
          console.warn('[CryptoNote] Native messaging error:', chrome.runtime.lastError.message);
          resolve({ error: chrome.runtime.lastError.message });
        } else {
          resolve(response || {});
        }
      });
    } catch (e) {
      console.warn('[CryptoNote] Native messaging not available:', e);
      resolve({ error: 'Native messaging not available' });
    }
  });
}

// ── Badge management ─────────────────────────────────────────────────────────
function updateBadge(isConnected) {
  const text  = isConnected ? '' : '!';
  const color = isConnected ? '#00e5a0' : '#ef4444';
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

// ── Auto-check connection on startup ─────────────────────────────────────────
async function checkConnection() {
  const res = await sendToNativeHost({ action: 'ping' });
  updateBadge(res && res.status === 'ok');
}

chrome.runtime.onStartup?.addListener(checkConnection);
chrome.runtime.onInstalled?.addListener(checkConnection);

// ── Message router ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

  // Ping / status check
  if (request.action === 'get_status') {
    sendToNativeHost({ action: 'ping' }).then(res => {
      const isConnected = res && res.status === 'ok';
      const isUnlocked  = isConnected && !!res.unlocked;
      updateBadge(isConnected);
      sendResponse({ isConnected, isUnlocked });
    });
    return true;
  }

  // Fetch logins (filtered by URL and/or search query)
  if (request.action === 'get_logins') {
    sendToNativeHost({
      action: 'get_logins',
      url:   request.url   || '',
      query: request.query || '',
    }).then(res => {
      sendResponse(res && res.logins ? res : { logins: [] });
    });
    return true;
  }

  // Save / update a login entry
  if (request.action === 'save_login') {
    sendToNativeHost({
      action:   'save_login',
      url:      request.url      || '',
      username: request.username || '',
      password: request.password || '',
      title:    request.title    || '',
    }).then(sendResponse);
    return true;
  }

  // Handle save-prompt from content script
  if (request.action === 'new_credentials_detected') {
    // Use session storage (Chrome MV3) or local storage (Firefox fallback)
    const storage = chrome.storage.session || chrome.storage.local;
    storage.set({
      pendingSave: {
        url:      request.url,
        title:    request.title || '',
        username: request.username,
        password: request.password,
        tabId:    sender.tab?.id,
        timestamp: Date.now(),
      }
    });

    // Show notification badge
    chrome.action.setBadgeText({ text: '1' });
    chrome.action.setBadgeBackgroundColor({ color: '#eab308' });

    return false; // synchronous
  }
});

// ── Context menu for quick fill ──────────────────────────────────────────────
try {
  chrome.contextMenus?.create({
    id: 'cn-autofill',
    title: 'Autofill with CryptoNote',
    contexts: ['editable'],
  });

  chrome.contextMenus?.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === 'cn-autofill' && tab?.id) {
      const res = await sendToNativeHost({
        action: 'get_logins',
        url: tab.url || '',
      });

      if (res && res.logins && res.logins.length > 0) {
        const login = res.logins[0];
        chrome.tabs.sendMessage(tab.id, {
          action: 'force_autofill',
          username: login.username,
          password: login.password,
        });
      }
    }
  });
} catch {
  // Context menus may not be available in all contexts
}
