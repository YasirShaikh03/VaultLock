# 🔐 Password Manager

A secure, encrypted desktop password manager built with **CustomTkinter**.  
All passwords are encrypted with **AES (Fernet)** derived from your master password — nobody can read your vault without it.

## ✨ Features

- 🔑 **Master password login** — hashed with SHA-256 + salt (PBKDF2, 480k iterations)
- 🔒 **AES-128 encryption** (Fernet) for the entire vault file
- ➕ Add entries: site, username, password, notes
- 👁️ Show/hide individual passwords
- 📋 **Copy to clipboard** with one click
- 🔍 **Live search** by site or username
- 🗑️ Delete entries with confirmation
- ⚡ **Password generator** — adjustable length (8–32), symbols toggle
- 💪 **Strength meter** — colour-coded bar (Very Weak → Very Strong)
- 💾 All data saved in encrypted `vault.enc` file

## 🚀 Installation

```bash
pip install customtkinter cryptography pyperclip
```

## ▶️ Run

```bash
python password_manager.py
```

First run → **create** a master password  
Next runs → **login** with your master password

> ⚠️ **Warning:** If you forget your master password, your vault CANNOT be recovered. There is no reset.

## 📁 Project Structure

```
password_manager/
├── password_manager.py    # Main application
├── vault.enc              # Auto-created encrypted vault (do not share!)
├── vault_config.json      # Auto-created salt + password hash
├── requirements.txt
└── README.md
```
## Author

Yasir Shaikh
GitHub: https://github.com/YasirShaikh03


## 🔐 Security Design

| Layer | Method |
|---|---|
| Master password storage | SHA-256 hash + random salt (never stored in plain text) |
| Vault encryption | Fernet (AES-128-CBC + HMAC-SHA256) |
| Key derivation | PBKDF2HMAC, SHA-256, 480,000 iterations |
| Salt | 16-byte cryptographically random |

## 🧱 Tech Stack

| Library | Purpose |
|---|---|
| `customtkinter` | Modern UI |
| `cryptography` | Fernet encryption + PBKDF2 |
| `pyperclip` | Clipboard copy |
| `hashlib`, `secrets` | Hashing + secure random |

## 💡 OOP Design

- `Vault` — encryption, load, save, CRUD operations
- `AuthWindow` — login/setup window
- `PasswordManagerApp` — main app window
- `EntryCard` — reusable card widget per entry

- ## Author

Yasir Shaikh
GitHub: https://github.com/YasirShaikh03
