const HOST_NAME = 'com.cryptonote.app';

// In Manifest V3, we use native messaging directly. 
// A persistent connection can be kept open, but for simplicity and reliability, 
// we will connect and send one-off messages.

async function sendToNativeHost(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(HOST_NAME, message, (response) => {
      if (chrome.runtime.lastError) {
        console.error("Native Messaging Error:", chrome.runtime.lastError.message);
        resolve({ error: chrome.runtime.lastError.message });
      } else {
        resolve(response);
      }
    });
  });
}

// Listen for messages from content scripts or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'get_logins') {
    sendToNativeHost({ action: 'get_logins', url: request.url })
      .then(sendResponse);
    return true; // Keep message channel open for async response
  }
  
  if (request.action === 'save_login') {
    sendToNativeHost({ 
      action: 'save_login', 
      url: request.url, 
      username: request.username, 
      password: request.password 
    }).then(sendResponse);
    return true;
  }
  
  if (request.action === 'get_status') {
    sendToNativeHost({ action: 'ping' })
      .then(res => {
        if (res && res.status === 'ok') {
            sendResponse({ isConnected: true, isUnlocked: res.unlocked });
        } else {
            sendResponse({ isConnected: false });
        }
      });
    return true;
  }
});
