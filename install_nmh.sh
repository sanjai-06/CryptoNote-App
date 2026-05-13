#!/bin/bash
# install_nmh.sh
# Installs the Native Messaging Host manifest for Chrome/Chromium

# Use the debug binary for now
BINARY_PATH="$(pwd)/src-tauri/target/debug/cryptonote"

if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Could not find cryptonote binary at $BINARY_PATH"
    echo "Make sure you run 'npm run tauri:dev' or 'cargo build' first."
    exit 1
fi

# The Extension ID is permanently locked via the RSA "key" property in manifest.json.
# This means the ID is identical across Chrome, Brave, and Edge automatically.
EXTENSION_ID="eikhhgnmionoanbacfcpjfmehbcccmmc"

cat <<EOF > com.cryptonote.app.json
{
  "name": "com.cryptonote.app",
  "description": "CryptoNote Native Messaging Host",
  "path": "$BINARY_PATH",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://eikhhgnmionoanbacfcpjfmehbcccmmc/"
  ]
}
EOF

# Install for Google Chrome
mkdir -p ~/.config/google-chrome/NativeMessagingHosts/
cp com.cryptonote.app.json ~/.config/google-chrome/NativeMessagingHosts/

# Install for Chromium/Brave
mkdir -p ~/.config/chromium/NativeMessagingHosts/
cp com.cryptonote.app.json ~/.config/chromium/NativeMessagingHosts/

mkdir -p ~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/
cp com.cryptonote.app.json ~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/

echo "Native Messaging Host installed!"
echo "Note: You MUST update 'allowed_origins' in the installed JSON files with your actual Extension ID once you load the unpacked extension in Chrome."
