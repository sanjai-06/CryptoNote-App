// browser-extension/popup.js

document.addEventListener('DOMContentLoaded', async () => {
  const statusDot = document.getElementById('status-indicator');
  const lockedView = document.getElementById('locked-view');
  const unlockedView = document.getElementById('unlocked-view');
  const btnRefresh = document.getElementById('btn-refresh');
  const searchInput = document.getElementById('search-input');
  const loginList = document.getElementById('login-list');
  const listTitle = document.getElementById('list-title');

  let currentUrl = '';
  let allLogins = [];

  // Get current tab URL
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tabs.length > 0 && tabs[0].url) {
    try {
      const url = new URL(tabs[0].url);
      if (url.protocol === 'http:' || url.protocol === 'https:') {
        currentUrl = url.origin;
      }
    } catch(e) {}
  }

  async function checkStatus() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: 'get_status' }, (response) => {
        if (chrome.runtime.lastError || !response || !response.isConnected || !response.isUnlocked) {
          resolve(false);
        } else {
          resolve(true);
        }
      });
    });
  }

  async function fetchLogins(query = '', filterUrl = '') {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: 'get_logins', url: filterUrl, query }, (response) => {
        if (chrome.runtime.lastError || !response || response.error) {
          resolve([]);
        } else {
          resolve(response.logins || []);
        }
      });
    });
  }

  function renderLogins(logins) {
    loginList.innerHTML = '';
    
    if (logins.length === 0) {
      loginList.innerHTML = '<div class="empty-state">No logins found</div>';
      return;
    }

    logins.forEach(login => {
      const item = document.createElement('div');
      item.className = 'login-item';
      
      const titleStr = login.title || login.url || 'Unnamed Entry';
      const userStr = login.username || 'No username';
      
      item.innerHTML = `
        <div class="login-info">
          <div class="login-title">${titleStr}</div>
          <div class="login-username">${userStr}</div>
        </div>
        <div class="login-actions">
          <button class="action-btn copy-user" data-val="${login.username || ''}">User</button>
          <button class="action-btn copy-pass" data-val="${login.password || ''}">Pass</button>
        </div>
      `;
      
      // Copy functionality
      item.querySelectorAll('.action-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const val = e.target.getAttribute('data-val');
          navigator.clipboard.writeText(val);
          const original = e.target.innerText;
          e.target.innerText = 'Copied!';
          setTimeout(() => e.target.innerText = original, 1000);
        });
      });
      
      // Auto-fill functionality (if clicked on the item itself)
      item.addEventListener('click', () => {
        chrome.tabs.sendMessage(tabs[0].id, {
          action: 'force_autofill',
          username: login.username,
          password: login.password
        }).catch(() => {
          // Content script might not be injected or listening
        });
      });

      loginList.appendChild(item);
    });
  }

  async function init() {
    const isUnlocked = await checkStatus();
    
    if (!isUnlocked) {
      statusDot.classList.remove('active');
      lockedView.classList.remove('hidden');
      unlockedView.classList.add('hidden');
      return;
    }

    statusDot.classList.add('active');
    lockedView.classList.add('hidden');
    unlockedView.classList.remove('hidden');

    // Initially fetch logins for the current URL
    if (currentUrl) {
      listTitle.innerText = 'Suggested Logins';
      allLogins = await fetchLogins('', currentUrl);
      if (allLogins.length === 0) {
        // If no suggested logins, fetch all
        listTitle.innerText = 'All Vault Logins';
        allLogins = await fetchLogins();
      }
    } else {
      listTitle.innerText = 'All Vault Logins';
      allLogins = await fetchLogins();
    }
    
    renderLogins(allLogins);
  }

  // Event Listeners
  btnRefresh.addEventListener('click', init);
  
  // Debounced search
  let timeout = null;
  searchInput.addEventListener('input', (e) => {
    clearTimeout(timeout);
    timeout = setTimeout(async () => {
      const q = e.target.value.trim();
      listTitle.innerText = q ? 'Search Results' : (currentUrl ? 'Suggested Logins' : 'All Vault Logins');
      
      if (q) {
        const results = await fetchLogins(q, '');
        renderLogins(results);
      } else {
        init(); // Reset to suggested/all
      }
    }, 300);
  });

  init();
});
