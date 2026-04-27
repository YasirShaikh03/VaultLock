"""
🔐 Password Manager
──────────────────
• Master password login (hashed with SHA-256 + salt)
• Passwords encrypted with Fernet (AES-128-CBC) from the `cryptography` package
• Add / view / search / delete entries
• Copy password to clipboard
• Password strength meter
• Password generator
• All data stored in encrypted JSON vault

__author__  = "Yasir Shaikh"
__github__  = "https://github.com/YasirShaikh03"
__version__ = "1.0.0"
"""

# ── Author (hidden in module metadata) ────────────────────────────────────────
# Author  : Yasir Shaikh
# GitHub  : https://github.com/YasirShaikh03
# ──────────────────────────────────────────────────────────────────────────────

import customtkinter as ctk
import json
import os
import hashlib
import secrets
import string
import base64
import pyperclip
from datetime import datetime
from tkinter import messagebox

# ── Try importing cryptography ─────────────────────────────────────────────────
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ── Theme ──────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

VAULT_FILE  = "vault.enc"
CONFIG_FILE = "vault_config.json"

# ── Hidden author signature (encoded) ─────────────────────────────────────────
_AUTHOR = base64.b64decode("WWFzaXIgU2haaWto").decode()           # Yasir Shaikh
_GITHUB = base64.b64decode("aHR0cHM6Ly9naXRodWIuY29tL1lhc2lyU2hhaWtoMDM=").decode()
# ──────────────────────────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════════════════
#  Crypto helpers
# ══════════════════════════════════════════════════════════════════════════════
def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from master password + salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=crypto_hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def hash_master(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()


def strength_score(pwd: str) -> tuple:
    """Returns (score 0-4, label, colour)."""
    score = 0
    if len(pwd) >= 8:  score += 1
    if len(pwd) >= 14: score += 1
    if any(c.isupper() for c in pwd) and any(c.islower() for c in pwd): score += 1
    if any(c.isdigit() for c in pwd): score += 1
    if any(c in string.punctuation for c in pwd): score += 1
    score = min(score, 4)
    labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    colors = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#16a34a"]
    return score, labels[score], colors[score]


def generate_password(length=16, use_symbols=True) -> str:
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    return "".join(secrets.choice(chars) for _ in range(length))


# ══════════════════════════════════════════════════════════════════════════════
#  Vault
#  © Yasir Shaikh — https://github.com/YasirShaikh03
# ══════════════════════════════════════════════════════════════════════════════
class Vault:
    # Author: Yasir Shaikh | GitHub: https://github.com/YasirShaikh03
    def __init__(self, master_password: str, salt: bytes):
        self._fernet = Fernet(derive_key(master_password, salt))
        self.entries: list = []

    def load(self):
        if not os.path.exists(VAULT_FILE):
            self.entries = []
            return
        with open(VAULT_FILE, "rb") as f:
            raw = f.read()
        decrypted = self._fernet.decrypt(raw)
        self.entries = json.loads(decrypted.decode())

    def save(self):
        data = json.dumps(self.entries, indent=2).encode()
        encrypted = self._fernet.encrypt(data)
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted)

    def add(self, site, username, password, notes=""):
        self.entries.append({
            "id": secrets.token_hex(8),
            "site": site,
            "username": username,
            "password": password,
            "notes": notes,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
        })
        self.save()

    def delete(self, entry_id):
        self.entries = [e for e in self.entries if e["id"] != entry_id]
        self.save()

    def search(self, query: str) -> list:
        q = query.lower()
        return [e for e in self.entries
                if q in e["site"].lower() or q in e["username"].lower()]


# ══════════════════════════════════════════════════════════════════════════════
#  Setup / Login Window
#  Built by Yasir Shaikh — github.com/YasirShaikh03
# ══════════════════════════════════════════════════════════════════════════════
class AuthWindow(ctk.CTk):
    """
    Authentication window for the Password Manager.

    Author : Yasir Shaikh
    GitHub : https://github.com/YasirShaikh03
    """
    def __init__(self):
        super().__init__()
        self.title("🔐  Password Manager — Login")
        self.geometry("440x480")
        self.resizable(False, False)
        self.configure(fg_color="#0d0d1a")

        self.vault: Vault | None = None
        self.is_setup = not os.path.exists(CONFIG_FILE)

        self._build_ui()

    def _build_ui(self):
        # Lock icon
        ctk.CTkLabel(self, text="🔐",
                     font=ctk.CTkFont(size=56)).pack(pady=(40, 8))

        ctk.CTkLabel(
            self,
            text="Setup Master Password" if self.is_setup else "Welcome Back",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#e4e4f0",
        ).pack()

        ctk.CTkLabel(
            self,
            text=("Create a strong master password.\nThis cannot be recovered if lost!"
                  if self.is_setup else
                  "Enter your master password to unlock the vault."),
            font=ctk.CTkFont(size=12),
            text_color="#52526a",
            justify="center",
        ).pack(pady=(4, 20))

        # Password entry
        self.pw_entry = ctk.CTkEntry(
            self, placeholder_text="Master password",
            show="•", width=300, height=42,
            font=ctk.CTkFont(size=14),
        )
        self.pw_entry.pack(pady=(0, 8))
        self.pw_entry.bind("<Return>", lambda e: self._submit())

        # Confirm entry (setup only)
        if self.is_setup:
            self.pw_confirm = ctk.CTkEntry(
                self, placeholder_text="Confirm password",
                show="•", width=300, height=42,
                font=ctk.CTkFont(size=14),
            )
            self.pw_confirm.pack(pady=(0, 8))
            self.pw_confirm.bind("<Return>", lambda e: self._submit())

        # Strength bar (setup only)
        if self.is_setup:
            self.strength_bar = ctk.CTkProgressBar(
                self, width=300, height=6, corner_radius=3,
                fg_color="#1a1a2e", progress_color="#ef4444",
            )
            self.strength_bar.set(0)
            self.strength_bar.pack(pady=(0, 4))

            self.strength_lbl = ctk.CTkLabel(
                self, text="",
                font=ctk.CTkFont(size=11), text_color="#52526a",
            )
            self.strength_lbl.pack()
            self.pw_entry.bind("<KeyRelease>", self._update_strength)

        self.error_lbl = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(size=12), text_color="#ef4444",
        )
        self.error_lbl.pack(pady=6)

        ctk.CTkButton(
            self,
            text="Create Vault" if self.is_setup else "Unlock",
            width=300, height=42,
            corner_radius=10,
            fg_color="#7c3aed", hover_color="#6d28d9",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._submit,
        ).pack()

        if not CRYPTO_OK:
            ctk.CTkLabel(
                self,
                text="⚠️  Run: pip install cryptography pyperclip",
                font=ctk.CTkFont(size=11), text_color="#f97316",
            ).pack(pady=(12, 0))

    def _update_strength(self, _=None):
        pwd = self.pw_entry.get()
        score, label, color = strength_score(pwd)
        self.strength_bar.set(score / 4)
        self.strength_bar.configure(progress_color=color)
        self.strength_lbl.configure(text=label, text_color=color)

    def _submit(self):
        if not CRYPTO_OK:
            self.error_lbl.configure(
                text="Install dependencies first.")
            return

        pwd = self.pw_entry.get()
        if not pwd:
            self.error_lbl.configure(text="Password cannot be empty.")
            return

        if self.is_setup:
            confirm = self.pw_confirm.get()
            if pwd != confirm:
                self.error_lbl.configure(text="Passwords do not match.")
                return
            if len(pwd) < 6:
                self.error_lbl.configure(text="Password too short (min 6 chars).")
                return
            # Create config
            salt_hex   = secrets.token_hex(16)
            salt_bytes = bytes.fromhex(salt_hex)
            pw_hash    = hash_master(pwd, salt_hex)
            with open(CONFIG_FILE, "w") as f:
                json.dump({"salt": salt_hex, "hash": pw_hash}, f)

            self.vault = Vault(pwd, salt_bytes)
            self.vault.entries = []
            self.vault.save()
        else:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
            if hash_master(pwd, cfg["salt"]) != cfg["hash"]:
                self.error_lbl.configure(text="Wrong password. Try again.")
                return
            salt_bytes = bytes.fromhex(cfg["salt"])
            self.vault = Vault(pwd, salt_bytes)
            try:
                self.vault.load()
            except Exception:
                self.error_lbl.configure(
                    text="Decryption failed. Wrong password?")
                return

        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
#  Entry Card
#  © Yasir Shaikh — https://github.com/YasirShaikh03
# ══════════════════════════════════════════════════════════════════════════════
class EntryCard(ctk.CTkFrame):
    """Single password entry card widget. — Yasir Shaikh"""
    def __init__(self, master, entry: dict, on_delete, on_copy, **kwargs):
        super().__init__(master, fg_color="#1a1a2e", corner_radius=10, **kwargs)
        self.entry   = entry
        self.on_delete = on_delete
        self.on_copy   = on_copy
        self._hidden   = True

        self.columnconfigure(1, weight=1)

        # Site icon letter
        icon_frame = ctk.CTkFrame(
            self, fg_color="#2563eb", corner_radius=8, width=40, height=40)
        icon_frame.grid(row=0, column=0, rowspan=2, padx=(12, 10), pady=12, sticky="ns")
        icon_frame.grid_propagate(False)
        ctk.CTkLabel(
            icon_frame,
            text=entry["site"][0].upper(),
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="white",
        ).place(relx=0.5, rely=0.5, anchor="center")

        # Site + username
        ctk.CTkLabel(
            self, text=entry["site"],
            anchor="w",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#e4e4f0",
        ).grid(row=0, column=1, sticky="w", pady=(10, 0))

        ctk.CTkLabel(
            self, text=entry["username"],
            anchor="w",
            font=ctk.CTkFont(size=12),
            text_color="#52526a",
        ).grid(row=1, column=1, sticky="w", pady=(0, 10))

        # Password label (hidden)
        self.pw_lbl = ctk.CTkLabel(
            self, text="••••••••",
            anchor="w",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color="#c4b5fd",
        )
        self.pw_lbl.grid(row=0, column=2, padx=8, rowspan=2)

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=0, column=3, rowspan=2, padx=(0, 10), pady=8)

        self.eye_btn = ctk.CTkButton(
            btn_frame, text="👁️",
            width=30, height=30, corner_radius=6,
            fg_color="transparent", hover_color="#2d2d42",
            command=self._toggle_pw,
        )
        self.eye_btn.pack(pady=2)

        ctk.CTkButton(
            btn_frame, text="📋",
            width=30, height=30, corner_radius=6,
            fg_color="transparent", hover_color="#2d2d42",
            command=lambda: on_copy(entry["password"]),
        ).pack(pady=2)

        ctk.CTkButton(
            btn_frame, text="🗑️",
            width=30, height=30, corner_radius=6,
            fg_color="transparent", hover_color="#3f1515",
            command=lambda: on_delete(entry),
        ).pack(pady=2)

    def _toggle_pw(self):
        self._hidden = not self._hidden
        self.pw_lbl.configure(
            text="••••••••" if self._hidden else self.entry["password"]
        )


# ══════════════════════════════════════════════════════════════════════════════
#  Main Password Manager Window
#  Author  : Yasir Shaikh
#  GitHub  : https://github.com/YasirShaikh03
# ══════════════════════════════════════════════════════════════════════════════
class PasswordManagerApp(ctk.CTk):
    """
    Main application window.

    Author : Yasir Shaikh
    GitHub : https://github.com/YasirShaikh03
    """
    def __init__(self, vault: Vault):
        super().__init__()
        self.vault = vault
        self.title("🔐  Password Manager")
        self.geometry("820x680")
        self.minsize(700, 560)
        self.configure(fg_color="#0d0d1a")

        self._build_ui()
        self._refresh()

    # ── UI ─────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(22, 8))

        ctk.CTkLabel(
            hdr, text="🔐 Password Manager",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#e4e4f0",
        ).pack(side="left")

        self.count_lbl = ctk.CTkLabel(
            hdr, text="",
            font=ctk.CTkFont(size=12), text_color="#52526a",
        )
        self.count_lbl.pack(side="left", padx=12, pady=(4, 0))

        ctk.CTkButton(
            hdr, text="+ Add New",
            width=110, height=34,
            corner_radius=8,
            fg_color="#7c3aed", hover_color="#6d28d9",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._open_add_dialog,
        ).pack(side="right")

        # ── Search bar ────────────────────────────────────────────────────────
        search_frame = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=10)
        search_frame.pack(fill="x", padx=24, pady=(0, 10))

        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="🔍  Search by site or username…",
            font=ctk.CTkFont(size=13),
            fg_color="transparent", border_width=0,
            height=40,
        )
        self.search_entry.pack(fill="x", padx=12)
        self.search_entry.bind("<KeyRelease>", lambda e: self._refresh())

        # ── Separator ─────────────────────────────────────────────────────────
        ctk.CTkFrame(self, fg_color="#2d2d42", height=1).pack(fill="x", padx=20)

        # ── Entry list ────────────────────────────────────────────────────────
        self.scroll = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color="#2d2d42",
        )
        self.scroll.pack(fill="both", expand=True, padx=16, pady=8)

        # ── Status bar ────────────────────────────────────────────────────────
        self.status_lbl = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(size=11), text_color="#16a34a",
        )
        self.status_lbl.pack(anchor="w", padx=24, pady=(0, 10))

    # ── Refresh list ───────────────────────────────────────────────────────────
    def _refresh(self):
        for w in self.scroll.winfo_children():
            w.destroy()

        query = self.search_entry.get().strip()
        entries = self.vault.search(query) if query else self.vault.entries

        self.count_lbl.configure(
            text=f"{len(self.vault.entries)} saved"
        )

        if not entries:
            ctk.CTkLabel(
                self.scroll,
                text="No entries found. Click '+ Add New' to get started!",
                font=ctk.CTkFont(size=13),
                text_color="#3f3f5a",
            ).pack(pady=50)
            return

        for entry in entries:
            card = EntryCard(
                self.scroll, entry,
                on_delete=self._delete_entry,
                on_copy=self._copy_password,
            )
            card.pack(fill="x", padx=4, pady=4)

    # ── Add entry dialog ───────────────────────────────────────────────────────
    def _open_add_dialog(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("Add New Entry")
        dlg.geometry("460x560")
        dlg.configure(fg_color="#13132b")
        dlg.grab_set()

        ctk.CTkLabel(
            dlg, text="New Entry",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#e4e4f0",
        ).pack(pady=(24, 16))

        fields = {}
        for label, placeholder, show in [
            ("Website / App", "e.g. github.com", ""),
            ("Username / Email", "e.g. user@email.com", ""),
            ("Password", "Enter or generate password", "•"),
            ("Notes (optional)", "Any extra info…", ""),
        ]:
            ctk.CTkLabel(dlg, text=label,
                         anchor="w", font=ctk.CTkFont(size=12),
                         text_color="#a1a1cc").pack(anchor="w", padx=24)
            entry = ctk.CTkEntry(
                dlg, placeholder_text=placeholder,
                show=show, width=400, height=38,
                font=ctk.CTkFont(size=13),
            )
            entry.pack(pady=(2, 10), padx=24)
            fields[label] = entry

        pw_entry = fields["Password"]

        # Password strength bar
        str_bar = ctk.CTkProgressBar(
            dlg, width=400, height=5, corner_radius=3,
            fg_color="#1a1a2e", progress_color="#ef4444",
        )
        str_bar.set(0)
        str_bar.pack(padx=24)

        str_lbl = ctk.CTkLabel(
            dlg, text="",
            font=ctk.CTkFont(size=11), text_color="#52526a",
        )
        str_lbl.pack(anchor="w", padx=24, pady=(2, 8))

        def update_str(_=None):
            sc, lb, cl = strength_score(pw_entry.get())
            str_bar.set(sc / 4)
            str_bar.configure(progress_color=cl)
            str_lbl.configure(text=lb, text_color=cl)

        pw_entry.bind("<KeyRelease>", update_str)

        # Generator row
        gen_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        gen_frame.pack(fill="x", padx=24, pady=(0, 10))

        sym_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            gen_frame, text="Symbols",
            variable=sym_var,
            fg_color="#7c3aed", hover_color="#6d28d9",
            font=ctk.CTkFont(size=12),
        ).pack(side="left")

        len_var = ctk.IntVar(value=16)
        slider = ctk.CTkSlider(
            gen_frame, from_=8, to=32,
            variable=len_var, width=140,
            button_color="#7c3aed",
        )
        slider.pack(side="left", padx=10)

        len_lbl = ctk.CTkLabel(
            gen_frame, text="16 chars",
            font=ctk.CTkFont(size=11), text_color="#52526a",
        )
        len_lbl.pack(side="left")

        def update_len_lbl(val):
            len_lbl.configure(text=f"{int(float(val))} chars")

        slider.configure(command=update_len_lbl)

        ctk.CTkButton(
            gen_frame, text="⚡ Generate",
            width=100, height=28, corner_radius=6,
            fg_color="#1e3a2e", hover_color="#236b3e",
            font=ctk.CTkFont(size=12),
            command=lambda: [
                pw_entry.delete(0, "end"),
                pw_entry.insert(0, generate_password(
                    int(len_var.get()), sym_var.get())),
                update_str(),
            ],
        ).pack(side="right")

        err_lbl = ctk.CTkLabel(
            dlg, text="",
            font=ctk.CTkFont(size=12), text_color="#ef4444",
        )
        err_lbl.pack()

        def save():
            site = fields["Website / App"].get().strip()
            user = fields["Username / Email"].get().strip()
            pwd  = pw_entry.get().strip()
            note = fields["Notes (optional)"].get().strip()
            if not site or not user or not pwd:
                err_lbl.configure(
                    text="Site, username and password are required.")
                return
            self.vault.add(site, user, pwd, note)
            dlg.destroy()
            self._refresh()
            self._flash_status(f"✅  '{site}' saved successfully!")

        ctk.CTkButton(
            dlg, text="💾  Save Entry",
            width=400, height=40,
            corner_radius=10,
            fg_color="#7c3aed", hover_color="#6d28d9",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=save,
        ).pack(padx=24, pady=(6, 0))

    # ── Actions ────────────────────────────────────────────────────────────────
    def _delete_entry(self, entry: dict):
        if messagebox.askyesno(
            "Delete Entry",
            f"Delete '{entry['site']}' ({entry['username']})?",
        ):
            self.vault.delete(entry["id"])
            self._refresh()
            self._flash_status(f"🗑️  '{entry['site']}' deleted.")

    def _copy_password(self, password: str):
        try:
            pyperclip.copy(password)
            self._flash_status("📋  Password copied to clipboard!")
        except Exception:
            self._flash_status("⚠️  Could not copy — install pyperclip.")

    def _flash_status(self, msg: str):
        self.status_lbl.configure(text=msg)
        self.after(3000, lambda: self.status_lbl.configure(text=""))


# ══════════════════════════════════════════════════════════════════════════════
#  Entry point
#  © Yasir Shaikh — https://github.com/YasirShaikh03
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # Step 1 — Authenticate
    auth = AuthWindow()
    auth.mainloop()

    # Step 2 — Open main app if login succeeded
    if auth.vault:
        app = PasswordManagerApp(auth.vault)
        app.mainloop()
