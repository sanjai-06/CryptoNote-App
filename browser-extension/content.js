// CryptoNote Content Script

// Minimal CSS to indicate CryptoNote icon in inputs
const style = document.createElement('style');
style.textContent = `
  .cn-autofill-icon {
    background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>');
    background-repeat: no-repeat;
    background-position: right 8px center;
    background-size: 16px;
    cursor: pointer;
  }
`;
document.head.appendChild(style);

function getLoginForms() {
  const forms = [];
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  
  passwordInputs.forEach(pw => {
    // Try to find the closest form, or just use the document
    const form = pw.closest('form');
    // Try to find an associated username/email field
    const un = (form || document).querySelector('input[type="text"], input[type="email"], input[name*="user"], input[name*="email"], input[name*="login"]');
    
    if (un && pw) {
      forms.push({ form, username: un, password: pw });
    }
  });
  
  return forms;
}

async function requestAutofill() {
  const forms = getLoginForms();
  if (forms.length === 0) return;

  const response = await new Promise(resolve => {
    chrome.runtime.sendMessage({ action: 'get_logins', url: window.location.origin }, resolve);
  });

  if (!response || response.error || !response.logins || response.logins.length === 0) {
    return;
  }

  // For now, just autofill the first match automatically, or add icon to let user click
  const login = response.logins[0]; // If there are multiple, a real extension would show a dropdown
  
  forms.forEach(({ username, password }) => {
    // Add icon class to show CryptoNote is active
    username.classList.add('cn-autofill-icon');
    
    // When user clicks the field, autofill it
    username.addEventListener('focus', () => {
        if (!username.value) {
            username.value = login.username;
            password.value = login.password;
            // Dispatch events so React/Vue/Angular frameworks pick up the change
            username.dispatchEvent(new Event('input', { bubbles: true }));
            password.dispatchEvent(new Event('input', { bubbles: true }));
        }
    }, { once: true });
  });
}

// Also intercept form submissions for Auto-save
document.addEventListener('submit', (e) => {
  const target = e.target;
  const pw = target.querySelector('input[type="password"]');
  const un = target.querySelector('input[type="text"], input[type="email"], input[name*="user"], input[name*="email"], input[name*="login"]');
  
  if (un && pw && un.value && pw.value) {
    // Send to background to trigger native save prompt
    chrome.runtime.sendMessage({
      action: 'save_login',
      url: window.location.origin,
      username: un.value,
      password: pw.value
    });
  }
});

// Run on page load
setTimeout(requestAutofill, 500);
