# Security Design

## Encryption: AES-256-GCM
- Every password is encrypted individually with AES-256-GCM
- A unique nonce (IV) is generated per entry using `os.urandom(12)`
- The GCM authentication tag detects any tampering with stored data

## Key Derivation: PBKDF2-HMAC-SHA256
- Master password is never stored
- A random 32-byte salt is generated once at vault creation
- 600,000 iterations (NIST 2023 recommendation)
- Output: 32-byte key used directly for AES-256

## Session Management
- The derived key lives in memory only while the vault is unlocked
- Auto-lock clears the key after 5 minutes of inactivity
- On exit, the key is explicitly cleared from memory

## Threat Model
| Threat | Mitigation |
|---|---|
| Stolen vault file | AES-256-GCM — useless without master password |
| Brute-force master password | PBKDF2 600k iterations — ~2min per guess |
| Tampered vault data | GCM authentication tag rejects modified ciphertext |
| Unlocked session hijack | Auto-lock after 5min inactivity |
| Rainbow tables | Unique salt per vault |