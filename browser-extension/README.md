# CryptoNote Browser Extension

A **Manifest V3** browser extension that connects to the **CryptoNote** desktop app, giving you:

- 🔑 **One-click autofill** on any login form
- 💾 **Auto-save prompt** when you sign into a new site
- 🔍 **Instant vault search** from the popup
- ➕ **Add new logins** directly from the browser
- 🛡️ **Zero-knowledge** – your plaintext passwords never leave the desktop app

---

## How It Works

```
Browser Extension  ──(Native Messaging)──►  CryptoNote Desktop App
     Popup                                        Encrypted Vault
  Content Script                              (Rust + AES-256-GCM)
```

The extension communicates with the CryptoNote desktop app using **Chrome Native Messaging**. It never talks directly to any server — all cryptographic operations happen inside the Rust desktop app.

---

## Installation (Developer Mode)

### 1. Install the CryptoNote desktop app
Make sure the CryptoNote desktop app is installed and the native messaging host is registered.

```bash
# From the repo root
bash install_nmh.sh
```

### 2. Load the extension in Chrome / Brave / Edge

1. Open your browser and navigate to `chrome://extensions`
2. Enable **Developer Mode** (toggle in top-right)
3. Click **"Load unpacked"**
4. Select the `browser-extension/` folder from this repository

### 3. Unlock your vault
Open the CryptoNote desktop app and unlock your vault. The extension status dot will turn **green** (🟢) once connected.

---

## Features

| Feature | Description |
|---|---|
| **Suggested Logins** | When you open the popup on a site you have saved, matching logins appear automatically |
| **Search** | Full-text search across all vault entries (Ctrl+K) |
| **Autofill** | Click any entry row or the ✏️ Fill button to fill the login form on the current page |
| **Copy username / password** | Hover over an entry to reveal copy buttons |
| **Add New** | Click the **+** button in the footer to manually add a login |
| **Save Prompt** | When you submit a new login form, a "Save to vault?" banner appears in the popup |
| **Auto-suggest** | A 🔐 icon appears inside username fields when CryptoNote has a matching login |
| **SPA Support** | Works on single-page apps (React, Vue, Angular) via MutationObserver |

---

## File Structure

```
browser-extension/
├── manifest.json       # Extension manifest (MV3)
├── background.js       # Service worker – native messaging bridge
├── content.js          # Injected into every page – form detection & autofill
├── popup.html          # Extension popup UI
├── popup.css           # Dark glassmorphism styles
├── popup.js            # Popup logic (search, save, fill)
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl + K` | Focus search box |
| `Escape` | Close modal / close popup |

---

## Security Notes

- All passwords are decrypted **inside the Rust desktop app only**
- The extension receives plaintext credentials only at the moment of filling — they are never stored in the extension
- Native Messaging requires the desktop app to be running — if it's closed, the extension shows "Locked"
- The extension does not make any network requests directly

---

## Permissions Explained

| Permission | Reason |
|---|---|
| `nativeMessaging` | Communicate with the CryptoNote desktop app |
| `storage` | Store temporary "save prompt" state between popup opens |
| `activeTab` | Read the current tab's URL to suggest relevant logins |
| `scripting` | Inject autofill into login forms |
| `clipboardWrite` | Copy usernames / passwords to clipboard |
