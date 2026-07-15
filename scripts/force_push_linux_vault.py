#!/usr/bin/env python3
"""
Force-push the Linux vault to the server.
This reads the local SQLite vault, re-encrypts the export with the correct keys,
and pushes it to the Render server, overwriting whatever mobile pushed.

Usage: python3 scripts/force_push_linux_vault.py <master_password>
"""
import sys, json, sqlite3, base64, hashlib, hmac as hmaclib, os, time
import requests

# ── Config ────────────────────────────────────────────────────────────────────
SERVER = "https://sanjai-06-cryptonote-app.onrender.com"
USER_ID = "sanjaivk13@gmail.com"
VAULT_DB = os.path.expanduser("~/.local/share/CryptoNote/vault.db")

if len(sys.argv) < 2:
    print("Usage: python3 force_push_linux_vault.py <master_password>")
    sys.exit(1)

PASSWORD = sys.argv[1]

# ── Read salt from vault DB ──────────────────────────────────────────────────
conn = sqlite3.connect(VAULT_DB)
salt_b64 = conn.execute("SELECT value FROM vault_meta WHERE key='salt'").fetchone()[0]
print(f"[1] Linux salt: {salt_b64}")

# ── Derive keys using Argon2id (same params as Rust) ─────────────────────────
try:
    from argon2.low_level import hash_secret_raw, Type
except ImportError:
    print("Installing argon2-cffi...")
    os.system(f"{sys.executable} -m pip install argon2-cffi")
    from argon2.low_level import hash_secret_raw, Type

salt_bytes = base64.b64decode(salt_b64)
master_key = hash_secret_raw(
    secret=PASSWORD.encode('utf-8'),
    salt=salt_bytes,
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=Type.ID,  # Argon2id
)
print(f"[2] Master key derived (first 4 bytes: {master_key[:4].hex()})")

# ── HKDF-SHA256 subkey derivation (matching Rust) ────────────────────────────
import hashlib
def hkdf_expand(prk, info, length=32):
    """HKDF-Expand (RFC 5869) with SHA-256"""
    hash_len = 32
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmaclib.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

# HKDF-Extract (salt=None → zeroed)
prk = hmaclib.new(b'\x00' * 32, master_key, hashlib.sha256).digest()

vault_key = hkdf_expand(prk, b"cryptonote-vault-key-v1")
hmac_key = hkdf_expand(prk, b"cryptonote-hmac-key-v1")
sync_key = hkdf_expand(prk, b"cryptonote-sync-key-v1")
device_key = hkdf_expand(prk, b"cryptonote-device-key-v1")
print(f"[3] Subkeys derived")

# ── Verify keys by trying to decrypt meta_enc ────────────────────────────────
meta_enc_json = conn.execute("SELECT value FROM vault_meta WHERE key='meta_enc'").fetchone()[0]
meta_enc = json.loads(meta_enc_json)

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# XChaCha20-Poly1305 using cryptography lib doesn't support X variant directly
# Let's use nacl (PyNaCl) instead
try:
    import nacl.secret
    import nacl.utils
except ImportError:
    print("Installing PyNaCl...")
    os.system(f"{sys.executable} -m pip install pynacl")
    import nacl.secret
    import nacl.utils

# XChaCha20-Poly1305 decrypt
def xchacha_decrypt(key_bytes, nonce_b64, ciphertext_b64):
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ciphertext_b64)
    return crypto_aead_xchacha20poly1305_ietf_decrypt(ct, None, nonce, key_bytes)

def xchacha_encrypt(key_bytes, plaintext_bytes):
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
    nonce = nacl.utils.random(24)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext_bytes, None, nonce, key_bytes)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "algorithm": "XChaCha20-Poly1305"
    }

try:
    meta_json_bytes = xchacha_decrypt(vault_key, meta_enc["nonce"], meta_enc["ciphertext"])
    meta = json.loads(meta_json_bytes)
    print(f"[4] Meta decrypted OK — vault_id={meta['vault_id']}, version={meta.get('version',1)}")
except Exception as e:
    print(f"[4] FATAL: Cannot decrypt vault meta — WRONG PASSWORD!")
    print(f"    Error: {e}")
    sys.exit(1)

# ── Export all entries (decrypt with vault_key, same as Rust export_json) ─────
entries = []
rows = conn.execute(
    "SELECT id, title_enc, username_enc, password_enc, url_enc, notes_enc, totp_enc, tags_enc, created_at, updated_at, version FROM vault_entries"
).fetchall()

for row in rows:
    eid, title_e, user_e, pass_e, url_e, notes_e, totp_e, tags_e, ca, ua, ver = row
    def dec(enc_json_str):
        if not enc_json_str:
            return None
        d = json.loads(enc_json_str)
        return xchacha_decrypt(vault_key, d["nonce"], d["ciphertext"]).decode()
    
    entries.append({
        "id": eid,
        "title": dec(title_e),
        "username": dec(user_e),
        "password": dec(pass_e),
        "url": dec(url_e) if url_e else None,
        "notes": dec(notes_e) if notes_e else None,
        "totp_secret": dec(totp_e) if totp_e else None,
        "tags": json.loads(dec(tags_e)) if tags_e else [],
        "created_at": ca,
        "updated_at": ua,
        "version": ver,
    })

conn.close()
print(f"[5] Exported {len(entries)} entries from local vault")

# ── Build the export JSON (same format as Rust export_json) ──────────────────
vault_export = {"entries": entries, "meta": meta}
vault_json = json.dumps(vault_export)

# ── Encrypt with sync_key ────────────────────────────────────────────────────
encrypted_vault = xchacha_encrypt(sync_key, vault_json.encode())
print(f"[6] Vault encrypted with sync_key (ciphertext len={len(encrypted_vault['ciphertext'])})")

# ── Compute HMAC ─────────────────────────────────────────────────────────────
version = meta.get("sync_version", meta.get("version", 1))
timestamp = int(time.time())
sequence = 1
device_id = f"device-{USER_ID.replace('@','').replace('.','')}"

hmac_input = f"{USER_ID}:{device_id}:{version}:{timestamp}:{sequence}:{salt_b64}:{encrypted_vault['ciphertext']}"
hmac_val = hmaclib.new(hmac_key, hmac_input.encode(), hashlib.sha256).digest()
hmac_b64 = base64.b64encode(hmac_val).decode()
print(f"[7] HMAC computed")

# ── Push to server with force=true ───────────────────────────────────────────
payload = {
    "user_id": USER_ID,
    "device_id": device_id,
    "version": version,
    "timestamp": timestamp,
    "encrypted_vault": encrypted_vault,
    "hmac": hmac_b64,
    "sequence": sequence,
    "kdf_salt": salt_b64,
    "force": True,
}

print(f"[8] Pushing to {SERVER}/api/vault/push ...")
resp = requests.post(f"{SERVER}/api/vault/push", json=payload, timeout=30)
print(f"[9] Server response: {resp.status_code} {resp.text}")

# ── Verify ───────────────────────────────────────────────────────────────────
print("\n[10] Verifying server state...")
pull = requests.get(f"{SERVER}/api/vault/pull/{USER_ID}", timeout=30).json()
srv_salt = pull.get("payload", {}).get("kdf_salt", "")
srv_ver = pull.get("payload", {}).get("version", "?")
print(f"  Server kdf_salt: {srv_salt}")
print(f"  Linux  kdf_salt: {salt_b64}")
print(f"  Match: {'✓ YES' if srv_salt == salt_b64 else '✗ NO'}")
print(f"  Server version: {srv_ver}")

if srv_salt == salt_b64:
    print("\n✅ SUCCESS — Server now has the Linux vault with correct salt.")
    print("   Go to Mobile → Settings → Sync → enter your master password → Sync Now")
else:
    print("\n❌ FAILED — Salt still doesn't match. Check server logs.")
