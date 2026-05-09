// browser-extension/background.js
// Service worker – bridges the popup / content scripts with the
// CryptoNote desktop app via Native Messaging.

const HOST_NAME = 'com.cryptonote.app';

// ── Native messaging helper ──────────────────────────────────────────────────
async function sendToNativeHost(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(HOST_NAME, message, (response) => {
      if (chrome.runtime.lastError) {
        console.warn('[CryptoNote] Native messaging error:', chrome.runtime.lastError.message);
        resolve({ error: chrome.runtime.lastError.message });
      } else {
        resolve(response || {});
      }
    });
  });
}

// ── Message router ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

  // Ping / status check
  if (request.action === 'get_status') {
    sendToNativeHost({ action: 'ping' }).then(res => {
      if (res && res.status === 'ok') {
        sendResponse({ isConnected: true, isUnlocked: !!res.unlocked });
      } else {
        sendResponse({ isConnected: false, isUnlocked: false });
      }
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
});

// ── Handle save-prompt from content script ───────────────────────────────────
// When the content script detects a form submission with new credentials,
// it sends a 'new_credentials_detected' message. We store it in session
// storage so the popup can display a "Save?" banner the next time it opens.
chrome.runtime.onMessage.addListener((request, sender) => {
  if (request.action === 'new_credentials_detected') {
    chrome.storage.session.set({
      pendingSave: {
        url:      request.url,
        username: request.username,
        password: request.password,
        tabId:    sender.tab?.id,
      }
    });
  }
});
