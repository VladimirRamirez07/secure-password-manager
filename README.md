# 🔐 Secure Password Manager

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-33%20passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)
![Coverage](https://img.shields.io/badge/Coverage-96%25-brightgreen?style=for-the-badge&logo=codecov&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-red?style=for-the-badge&logo=letsencrypt&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Rich](https://img.shields.io/badge/Rich-CLI-blueviolet?style=for-the-badge&logo=gnometerminal&logoColor=white)
![Cryptography](https://img.shields.io/badge/cryptography-42.0.5-orange?style=for-the-badge&logo=pypi&logoColor=white)

> A local, **AES-256-GCM encrypted** password manager built with Python.
> Designed with security-first principles — your data never leaves your machine.

---

## 📸 Preview

```
🔐 Secure Password Manager

✓ Vault unlocked.

  Auto-lock in 299s
  1. List passwords
  2. Add password
  3. Delete password
  4. Generate password
  5. Lock vault
  6. Exit

  Option [1/2/3/4/5/6]:
```

---

## 🛡️ Security Architecture

| Layer | Technology | Why |
|---|---|---|
| Encryption | AES-256-GCM | Authenticated encryption — protects confidentiality AND integrity |
| Key Derivation | PBKDF2-HMAC-SHA256 | Slow hash function to resist brute-force on master password |
| Iterations | 600,000 | NIST recommendation for PBKDF2-SHA256 (2023) |
| Storage | SQLite (local) | No cloud sync — zero remote attack surface |
| Salt | `os.urandom(32)` | Unique per vault, prevents rainbow table attacks |
| Nonce | `os.urandom(12)` | Unique per entry, prevents ciphertext reuse |

---

## 🎯 Threat Model

### ✅ Protected Against
- Unauthorized access to the vault file (AES-256-GCM)
- Master password brute-force (PBKDF2 with 600,000 iterations)
- Tampering with stored data (GCM authentication tag)
- Session hijacking (auto-lock after inactivity)
- Rainbow table attacks (unique salt per vault)
- Ciphertext reuse (unique nonce per entry)

### ❌ Out of Scope
- Keyloggers on the host machine
- Memory dumps while the vault is unlocked
- Physical access with root privileges

---

## ✨ Features

- 🔑 **Master password** with strength validation
- 🔒 **AES-256-GCM** encryption per entry
- 🧂 **PBKDF2** key derivation with 600k iterations
- 🎲 **Cryptographic password generator** using `secrets` module
- 📊 **Password strength evaluator** (score 0–100)
- ⏱️ **Auto-lock** after 5 minutes of inactivity
- 🗄️ **Local SQLite** storage — no internet required
- 🎨 **Rich CLI** with colored tables and prompts

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/VladimirRamirez07/secure-password-manager.git
cd secure-password-manager

# Create virtual environment
python -m venv venv

# Activate it
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# Run the app
python main.py
```

### First Run
On first launch you'll be prompted to create a master password:
```
Requirements: 12+ chars, uppercase, lowercase, number, special character
Example: MyVault@2026
```

---

## 📁 Project Structure

```
secure-password-manager/
├── main.py                          # Entry point
├── requirements.txt                 # Dependencies
├── pytest.ini                       # Test configuration
│
├── src/
│   ├── crypto/
│   │   ├── encryption.py            # AES-256-GCM encrypt/decrypt
│   │   ├── key_derivation.py        # PBKDF2-HMAC-SHA256
│   │   └── master_password.py       # Vault init and authentication
│   │
│   ├── database/
│   │   ├── db.py                    # SQLite operations
│   │   └── models.py                # Schema definitions
│   │
│   ├── ui/
│   │   └── cli.py                   # Rich CLI interface
│   │
│   └── utils/
│       ├── password_generator.py    # Cryptographic generator
│       └── auto_lock.py             # Inactivity timer
│
├── tests/
│   ├── test_encryption.py           # 8 tests
│   ├── test_key_derivation.py       # 7 tests
│   ├── test_password_generator.py   # 11 tests
│   └── test_auto_lock.py            # 8 tests
│
└── docs/
    └── SECURITY.md                  # Full security documentation
```

---

## 🧪 Running Tests

```bash
# Run all tests with coverage
pytest

# Run a specific module
pytest tests/test_encryption.py -v
```

### Test Results
```
33 passed in 22.80s

Name                                Stmts   Cover
src/crypto/encryption.py               18    94%
src/crypto/key_derivation.py           15   100%
src/utils/password_generator.py        43    98%
src/utils/auto_lock.py                 48    94%
```

---

## 🔧 Tech Stack

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Core language |
| `cryptography` | 42.0.5 | AES-GCM, PBKDF2 |
| `sqlite3` | built-in | Local encrypted storage |
| `secrets` | built-in | Cryptographic randomness |
| `rich` | 13.7.1 | Terminal UI |
| `pytest` | 8.1.1 | Testing framework |
| `pytest-cov` | 5.0.0 | Coverage reports |
| `black` | 24.3.0 | Code formatter |
| `flake8` | 7.0.0 | Linter |

---

## 📖 Documentation

- [Security Design](docs/SECURITY.md)

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">Built with 🔐 by <a href="https://github.com/VladimirRamirez07">VladimirRamirez07</a></p>