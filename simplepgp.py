import json
import os
import re
import sys
import threading
import warnings
from contextlib import contextmanager
from pathlib import Path
warnings.filterwarnings("ignore")

import pgpy
from pgpy.constants import (
    CompressionAlgorithm,
    EllipticCurveOID,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)
from pgpy.errors import PGPDecryptionError, PGPEncryptionError, PGPError
CRYPTO_ERRORS = (PGPError, PGPDecryptionError, PGPEncryptionError, ValueError)

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "SimplePGP"
KEYS_DIR = Path.home() / ".simplepgp" / "keys"
CONFIG_PATH = Path.home() / ".simplepgp" / "config.json"
MASTER_CANARY = "simplepgp-master-ok"

KEY_TYPES = {
    "RSA 4096 (most compatible)": ("rsa", 4096),
    "RSA 3072 (faster)": ("rsa", 3072),
    "Ed25519 (modern, small keys)": ("ed25519", None),
}

THEMES = {
    "light": dict(
        bg="#f0f0f0", panel="#f7f7f7", field="#ffffff", fg="#1f1f1f",
        muted="#666666", sel_bg="#cde5ff", sel_fg="#000000", btn="#e6e6e6",
        btn_active="#d4d4d4", ok="#0a7a2f", err="#b3261e", insert="#000000",
        border="#c0c0c0"),
    "dark": dict(
        bg="#1f1f1f", panel="#262626", field="#171717", fg="#e6e6e6",
        muted="#9a9a9a", sel_bg="#264f78", sel_fg="#ffffff", btn="#333333",
        btn_active="#414141", ok="#57c979", err="#f28b82", insert="#e6e6e6",
        border="#3c3c3c"),
}

ARMOR_MSG_RE = re.compile(
    r"-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----", re.S)
ARMOR_CLEARSIGN_RE = re.compile(
    r"-----BEGIN PGP SIGNED MESSAGE-----.*?-----END PGP SIGNATURE-----", re.S)
ARMOR_KEY_RE = re.compile(
    r"-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----.*?"
    r"-----END PGP (PUBLIC|PRIVATE) KEY BLOCK-----", re.S)


def load_config():
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


@contextmanager
def unlocked(key, passphrase):
    if key.is_protected:
        with key.unlock(passphrase):
            yield key
    else:
        yield key


def generate_key(name, keytype, passphrase=None):
    kind, size = KEY_TYPES[keytype]
    if kind == "rsa":
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, size)
        sub = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, size)
    else:
        key = pgpy.PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
        sub = pgpy.PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)

    uid = pgpy.PGPUID.new(name)
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.Certify},
        hashes=[HashAlgorithm.SHA512, HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128],
        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.ZIP,
                     CompressionAlgorithm.Uncompressed],
    )
    key.add_subkey(sub, usage={KeyFlags.EncryptCommunications,
                               KeyFlags.EncryptStorage})
    if passphrase:
        key.protect(passphrase, SymmetricKeyAlgorithm.AES256,
                    HashAlgorithm.SHA256)
    return key


def clearsign_text(key, passphrase, text):
    msg = pgpy.PGPMessage.new(text, cleartext=True)
    with unlocked(key, passphrase) as k:
        msg |= k.sign(msg)
    return str(msg)


def encrypt_text(recipients, text, signer=None, signer_pw=None):
    msg = pgpy.PGPMessage.new(text)
    if signer is not None:
        with unlocked(signer, signer_pw) as k:
            msg |= k.sign(msg)
    cipher = SymmetricKeyAlgorithm.AES256
    session_key = cipher.gen_key()
    try:
        for rk in recipients:
            pub = rk.pubkey if not rk.is_public else rk
            msg = pub.encrypt(msg, cipher=cipher, sessionkey=session_key)
    finally:
        del session_key
    return str(msg)


def keyids_of(key):
    ids = {key.fingerprint.keyid}
    ids.update(key.subkeys.keys())
    return ids


def verify_with_any(subject, keys):
    for key in keys:
        pub = key if key.is_public else key.pubkey
        try:
            if pub.verify(subject):
                return key
        except CRYPTO_ERRORS:
            continue
    return None


def sym_encrypt(text, passphrase):
    msg = pgpy.PGPMessage.new(text)
    enc = msg.encrypt(passphrase)
    return str(enc)


def sym_decrypt(blob, passphrase):
    msg = pgpy.PGPMessage.from_blob(blob)
    dec = msg.decrypt(passphrase)
    out = dec.message
    if isinstance(out, (bytes, bytearray)):
        out = bytes(out).decode("utf-8", errors="replace")
    return out


def store_is_locked(keys_dir=KEYS_DIR):
    return (Path(keys_dir) / "master.enc").exists()


def verify_master(keys_dir, passphrase):
    try:
        blob = (Path(keys_dir) / "master.enc").read_text(encoding="utf-8")
        return sym_decrypt(blob, passphrase) == MASTER_CANARY
    except CRYPTO_ERRORS + (OSError,):
        return False


class KeyStore:
    def __init__(self, keys_dir=KEYS_DIR, master_pw=None):
        self.dir = Path(keys_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.master_pw = master_pw
        self.keys = {}
        self.load()

    def load(self):
        self.keys.clear()
        blobs = []
        for path in sorted(self.dir.glob("*.asc")):
            try:
                blobs.append(path.read_text(encoding="utf-8"))
            except OSError:
                continue
        if self.master_pw:
            for path in sorted(self.dir.glob("*.enc")):
                if path.name == "master.enc":
                    continue
                try:
                    blobs.append(sym_decrypt(
                        path.read_text(encoding="utf-8"), self.master_pw))
                except CRYPTO_ERRORS + (OSError,):
                    continue
        for blob in blobs:
            try:
                key, _ = pgpy.PGPKey.from_blob(blob)
            except CRYPTO_ERRORS:
                continue
            fpr = str(key.fingerprint)
            if fpr not in self.keys or not key.is_public:
                self.keys[fpr] = key

    def identities(self):
        return [k for k in self.keys.values() if not k.is_public]

    def contacts(self):
        return [k for k in self.keys.values() if k.is_public]

    def get(self, fpr):
        return self.keys.get(fpr)

    def save(self, key):
        fpr = str(key.fingerprint)
        kind = ".pub" if key.is_public else ".sec"
        if self.master_pw:
            data, ext = sym_encrypt(str(key), self.master_pw), ".enc"
        else:
            data, ext = str(key), ".asc"
        (self.dir / (fpr + kind + ext)).write_text(data, encoding="utf-8")
        other = ".asc" if ext == ".enc" else ".enc"
        stale = [self.dir / (fpr + kind + other)]
        if kind == ".sec":
            stale += [self.dir / (fpr + ".pub" + e) for e in (".asc", ".enc")]
        for p in stale:
            if p.exists():
                p.unlink()
        self.keys[fpr] = key

    def import_blob(self, text):
        key, others = pgpy.PGPKey.from_blob(text)
        found = {}
        for k in [key] + list(others.values()):
            if isinstance(k, pgpy.PGPKey) and k.is_primary:
                found.setdefault(str(k.fingerprint), k)
        imported = []
        for fpr, k in found.items():
            existing = self.keys.get(fpr)
            if existing is not None and not existing.is_public:
                continue
            self.save(k)
            imported.append(k)
        return imported

    def delete(self, fpr):
        key = self.keys.pop(fpr, None)
        if key is None:
            return
        for kind in (".sec", ".pub"):
            for ext in (".asc", ".enc"):
                p = self.dir / (fpr + kind + ext)
                if p.exists():
                    p.unlink()

    def set_master(self, passphrase):
        self.master_pw = passphrase
        (self.dir / "master.enc").write_text(
            sym_encrypt(MASTER_CANARY, passphrase), encoding="utf-8")
        for key in list(self.keys.values()):
            self.save(key)

    def remove_master(self):
        self.master_pw = None
        for key in list(self.keys.values()):
            self.save(key)
        p = self.dir / "master.enc"
        if p.exists():
            p.unlink()


def display_name(key):
    if key.userids:
        return key.userids[0].name or "(unnamed)"
    return "(unnamed)"


def short_fpr(key):
    f = str(key.fingerprint)
    return " ".join(f[i:i + 4] for i in range(0, len(f), 4))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("960x680")
        self.minsize(760, 520)

        self.cfg = load_config()
        self.theme_name = self.cfg.get("theme", "light")
        self.palette = THEMES[self.theme_name]
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        self.store = None
        self.pw_cache = {}
        self._cancelled = False
        self._last_status = ("Ready", None)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=(6, 0))
        self.notepad_tab = ttk.Frame(nb)
        self.keys_tab = ttk.Frame(nb)
        self.settings_tab = ttk.Frame(nb)
        nb.add(self.notepad_tab, text="  Notepad  ")
        nb.add(self.keys_tab, text="  Keys  ")
        nb.add(self.settings_tab, text="  Settings  ")

        self.status = tk.Label(self, text="Ready", anchor="w", padx=8, pady=3)
        self.status.pack(fill="x", side="bottom")

        self._build_notepad()
        self._build_keys()
        self._build_settings()
        self.apply_theme(self.theme_name)
        self.update_idletasks()

        if store_is_locked(KEYS_DIR):
            while True:
                pw = self.ask_password(
                    f"Unlock {APP_NAME}",
                    "Enter master password to unlock your keys:")
                if pw is None:
                    self._cancelled = True
                    self.destroy()
                    return
                if verify_master(KEYS_DIR, pw):
                    break
                messagebox.showerror(APP_NAME, "Wrong master password.",
                                     parent=self)
            self.store = KeyStore(KEYS_DIR, pw)
        else:
            self.store = KeyStore(KEYS_DIR)
        self.refresh_keys()
        self.update_master_ui()

    def apply_theme(self, name):
        self.theme_name = name
        t = self.palette = THEMES[name]
        s = self.style
        s.configure(".", background=t["bg"], foreground=t["fg"],
                    fieldbackground=t["field"], bordercolor=t["border"],
                    lightcolor=t["bg"], darkcolor=t["bg"],
                    troughcolor=t["bg"], insertcolor=t["insert"],
                    selectbackground=t["sel_bg"], selectforeground=t["sel_fg"])
        s.configure("TFrame", background=t["bg"])
        s.configure("TLabel", background=t["bg"], foreground=t["fg"])
        s.configure("Muted.TLabel", foreground=t["muted"])
        s.configure("Bold.TLabel", font=("", 10, "bold"))
        s.configure("Error.TLabel", foreground=t["err"])
        s.configure("TButton", background=t["btn"], foreground=t["fg"])
        s.map("TButton", background=[("active", t["btn_active"]),
                                     ("pressed", t["btn_active"])])
        s.configure("TCheckbutton", background=t["bg"], foreground=t["fg"])
        s.map("TCheckbutton", background=[("active", t["bg"])])
        s.configure("TNotebook", background=t["bg"])
        s.configure("TNotebook.Tab", background=t["btn"], foreground=t["fg"],
                    padding=(12, 5))
        s.map("TNotebook.Tab", background=[("selected", t["bg"])])
        s.configure("Treeview", background=t["field"],
                    fieldbackground=t["field"], foreground=t["fg"])
        s.map("Treeview", background=[("selected", t["sel_bg"])],
              foreground=[("selected", t["sel_fg"])])
        s.configure("Treeview.Heading", background=t["btn"],
                    foreground=t["fg"])
        s.map("Treeview.Heading", background=[("active", t["btn_active"])])
        s.configure("TCombobox", fieldbackground=t["field"],
                    background=t["btn"], foreground=t["fg"],
                    arrowcolor=t["fg"])
        s.map("TCombobox",
              fieldbackground=[("readonly", t["field"])],
              foreground=[("readonly", t["fg"])],
              selectbackground=[("readonly", t["field"])],
              selectforeground=[("readonly", t["fg"])])
        s.configure("TEntry", fieldbackground=t["field"], foreground=t["fg"],
                    insertcolor=t["insert"])
        s.configure("Vertical.TScrollbar", background=t["btn"],
                    troughcolor=t["bg"], arrowcolor=t["fg"])

        self.configure(bg=t["bg"])
        self.option_add("*TCombobox*Listbox.background", t["field"])
        self.option_add("*TCombobox*Listbox.foreground", t["fg"])
        self.option_add("*TCombobox*Listbox.selectBackground", t["sel_bg"])
        self.option_add("*TCombobox*Listbox.selectForeground", t["sel_fg"])

        for w in (self.text,):
            w.config(bg=t["field"], fg=t["fg"], insertbackground=t["insert"],
                     selectbackground=t["sel_bg"],
                     selectforeground=t["sel_fg"],
                     highlightbackground=t["border"],
                     highlightcolor=t["border"])
        self.recipients_box.config(
            bg=t["field"], fg=t["fg"], selectbackground=t["sel_bg"],
            selectforeground=t["sel_fg"], highlightbackground=t["border"],
            highlightcolor=t["border"])
        self.status.config(bg=t["bg"])
        self.set_status(*self._last_status)

    def toggle_theme(self):
        name = "dark" if self.dark_var.get() else "light"
        self.apply_theme(name)
        self.cfg["theme"] = name
        save_config(self.cfg)

    def set_status(self, text, ok=None):
        t = self.palette
        color = {True: t["ok"], False: t["err"], None: t["muted"]}[ok]
        self._last_status = (text, ok)
        self.status.config(text=text, fg=color)

    def ask_password(self, title, prompt, confirm=False):
        t = self.palette
        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.resizable(False, False)
        dlg.configure(bg=t["bg"])
        dlg.transient(self)
        frm = ttk.Frame(dlg, padding=14)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text=prompt).grid(row=0, column=0, columnspan=2,
                                         sticky="w", pady=(0, 4))
        v1, v2 = tk.StringVar(), tk.StringVar()
        e1 = ttk.Entry(frm, textvariable=v1, show="•", width=34)
        e1.grid(row=1, column=0, columnspan=2, sticky="we")
        if confirm:
            ttk.Label(frm, text="Repeat:").grid(row=2, column=0, columnspan=2,
                                                sticky="w", pady=(8, 4))
            ttk.Entry(frm, textvariable=v2, show="•", width=34).grid(
                row=3, column=0, columnspan=2, sticky="we")
        err = ttk.Label(frm, text="", style="Error.TLabel")
        err.grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 0))

        result = {"pw": None}

        def ok(event=None):
            if confirm and v1.get() != v2.get():
                err.config(text="Passphrases do not match.")
                return
            result["pw"] = v1.get()
            dlg.destroy()

        ttk.Button(frm, text="OK", command=ok).grid(
            row=5, column=0, sticky="e", pady=(10, 0), padx=(0, 6))
        ttk.Button(frm, text="Cancel", command=dlg.destroy).grid(
            row=5, column=1, sticky="w", pady=(10, 0))
        dlg.bind("<Return>", ok)
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.geometry(f"+{self.winfo_rootx() + 120}+{self.winfo_rooty() + 120}")
        dlg.grab_set()
        e1.focus_set()
        self.wait_window(dlg)
        return result["pw"]

    def get_passphrase(self, key, purpose):
        if not key.is_protected:
            return None
        fpr = str(key.fingerprint)
        if fpr in self.pw_cache:
            return self.pw_cache[fpr]
        while True:
            pw = self.ask_password(
                APP_NAME,
                f"Passphrase for '{display_name(key)}' ({purpose}):")
            if pw is None:
                raise PGPError("cancelled")
            try:
                with key.unlock(pw):
                    pass
            except CRYPTO_ERRORS:
                messagebox.showerror(APP_NAME, "Wrong passphrase.",
                                     parent=self)
                continue
            self.pw_cache[fpr] = pw
            return pw

    def _build_notepad(self):
        f = self.notepad_tab

        top = ttk.Frame(f)
        top.pack(fill="x", padx=8, pady=(8, 4))

        ttk.Label(top, text="Act as (sign+decrypt):").grid(
            row=0, column=0, sticky="w")
        self.identity_var = tk.StringVar()
        self.identity_combo = ttk.Combobox(
            top, textvariable=self.identity_var, state="readonly", width=32)
        self.identity_combo.grid(row=0, column=1, sticky="w", padx=(6, 24))

        ttk.Label(top, text="Encrypt to (ctrl+click):").grid(
            row=0, column=2, sticky="nw")
        rbox_frame = ttk.Frame(top)
        rbox_frame.grid(row=0, column=3, rowspan=2, sticky="w", padx=6)
        self.recipients_box = tk.Listbox(
            rbox_frame, selectmode="extended", height=4, width=36,
            exportselection=False)
        rscroll = ttk.Scrollbar(rbox_frame, orient="vertical",
                                command=self.recipients_box.yview)
        self.recipients_box.config(yscrollcommand=rscroll.set)
        self.recipients_box.pack(side="left", fill="both")
        rscroll.pack(side="left", fill="y")

        text_frame = ttk.Frame(f)
        text_frame.pack(fill="both", expand=True, padx=8, pady=4)
        self.text = tk.Text(text_frame, wrap="word", undo=True,
                            font=("Consolas", 11))
        tscroll = ttk.Scrollbar(text_frame, orient="vertical",
                                command=self.text.yview)
        self.text.config(yscrollcommand=tscroll.set)
        self.text.pack(side="left", fill="both", expand=True)
        tscroll.pack(side="left", fill="y")

        btns = ttk.Frame(f)
        btns.pack(fill="x", padx=8, pady=(4, 8))
        for label, cmd in [
            ("Sign", self.do_sign),
            ("Encrypt", lambda: self.do_encrypt(sign=False)),
            ("Sign + Encrypt", lambda: self.do_encrypt(sign=True)),
            ("Decrypt + Verify", self.do_decrypt_verify),
        ]:
            ttk.Button(btns, text=label, command=cmd).pack(
                side="left", padx=(0, 6))
        ttk.Button(btns, text="Clear", command=self.do_clear).pack(
            side="right")
        ttk.Button(btns, text="Paste", command=self.do_paste).pack(
            side="right", padx=(0, 6))
        ttk.Button(btns, text="Copy All", command=self.do_copy_all).pack(
            side="right", padx=(0, 6))

    def notepad_text(self):
        return self.text.get("1.0", "end-1c")

    def set_notepad(self, content):
        self.text.delete("1.0", "end")
        self.text.insert("1.0", content)

    def current_identity(self):
        label = self.identity_var.get()
        fpr = self._identity_map.get(label)
        return self.store.get(fpr) if fpr else None

    def selected_recipients(self):
        keys = []
        for i in self.recipients_box.curselection():
            fpr = self._recipient_fprs[i]
            keys.append(self.store.get(fpr))
        return keys

    def do_sign(self):
        text = self.notepad_text().strip()
        if not text:
            return self.set_status("Nothing to sign.",
                                   False)
        key = self.current_identity()
        if key is None:
            return self.set_status(
                "No identity selected.", False)
        try:
            pw = self.get_passphrase(key, "signing")
            signed = clearsign_text(key, pw, text)
        except CRYPTO_ERRORS as e:
            return self.set_status(f"Signing failed: {e}", False)
        self.set_notepad(signed)
        self.set_status(f"Signed as '{display_name(key)}'. "
                        "Copy All to share it.", True)

    def do_encrypt(self, sign):
        text = self.notepad_text().strip()
        if not text:
            return self.set_status("Nothing to encrypt.", False)
        recipients = self.selected_recipients()
        if not recipients:
            return self.set_status(
                "Select at least one recipient in 'Encrypt to'.", False)
        signer = pw = None
        if sign:
            signer = self.current_identity()
            if signer is None:
                return self.set_status(
                    "No identity selected to sign with.", False)
            try:
                pw = self.get_passphrase(signer, "signing")
            except PGPError:
                return self.set_status("Cancelled.", None)
        try:
            armored = encrypt_text(recipients, text, signer, pw)
        except CRYPTO_ERRORS as e:
            return self.set_status(f"Encryption failed: {e}", False)
        self.set_notepad(armored)
        names = ", ".join(display_name(k) for k in recipients)
        extra = f", signed as '{display_name(signer)}'" if signer else ""
        self.set_status(f"Encrypted to: {names}{extra}.", True)

    def do_decrypt_verify(self):
        text = self.notepad_text()
        known = list(self.store.keys.values())

        m = ARMOR_MSG_RE.search(text)
        if m:
            return self._decrypt_block(m.group(0), known)

        m = ARMOR_CLEARSIGN_RE.search(text)
        if m:
            try:
                msg = pgpy.PGPMessage.from_blob(m.group(0))
            except CRYPTO_ERRORS as e:
                return self.set_status(f"Could not parse block: {e}", False)
            signer = verify_with_any(msg, known)
            if signer:
                self.set_status(
                    f"GOOD signature from '{display_name(signer)}' "
                    f"[{short_fpr(signer)}]", True)
            else:
                self.set_status(
                    "Signature could NOT be verified with any known key.",
                    False)
            return

        if ARMOR_KEY_RE.search(text):
            if messagebox.askyesno(
                    APP_NAME, "This looks like a PGP key. Import it?",
                    parent=self):
                self.import_text(text)
            return

        self.set_status("No PGP message, signed block, or key found in the "
                        "notepad.", False)

    def _decrypt_block(self, armored, known):
        try:
            msg = pgpy.PGPMessage.from_blob(armored)
        except CRYPTO_ERRORS as e:
            return self.set_status(f"Could not parse message: {e}", False)

        encrypter_ids = set(getattr(msg, "encrypters", set()))
        candidates = [k for k in self.store.identities()
                      if encrypter_ids & keyids_of(k)]
        if not candidates:
            candidates = self.store.identities()
        if not candidates:
            return self.set_status(
                "You have no identities that could decrypt this.", False)

        last_err = None
        for key in candidates:
            try:
                pw = self.get_passphrase(key, "decrypting")
            except PGPError:
                return self.set_status("Cancelled.", None)
            try:
                with unlocked(key, pw) as k:
                    dec = k.decrypt(msg)
            except CRYPTO_ERRORS as e:
                last_err = e
                continue
            payload = dec.message
            if isinstance(payload, (bytes, bytearray)):
                payload = bytes(payload).decode("utf-8", errors="replace")
            self.set_notepad(payload)
            note = f"Decrypted with '{display_name(key)}'."
            if dec.signatures:
                signer = verify_with_any(dec, known)
                if signer:
                    note += (f"  GOOD signature from "
                             f"'{display_name(signer)}'.")
                else:
                    note += "  Signature present but signer is UNKNOWN."
            return self.set_status(note, True)

        self.set_status(f"Decryption failed: {last_err}", False)

    def do_copy_all(self):
        content = self.notepad_text()
        self.clipboard_clear()
        self.clipboard_append(content)
        self.set_status("Notepad copied to clipboard.", True)

    def do_paste(self):
        try:
            content = self.clipboard_get()
        except tk.TclError:
            return self.set_status("Clipboard is empty.", False)
        self.set_notepad(content)
        self.set_status("Pasted from clipboard.", None)

    def do_clear(self):
        self.set_notepad("")
        self.set_status("Cleared.", None)

    def _build_keys(self):
        f = self.keys_tab
        panes = ttk.Frame(f)
        panes.pack(fill="both", expand=True, padx=8, pady=8)
        panes.columnconfigure(0, weight=1)
        panes.columnconfigure(1, weight=1)
        panes.rowconfigure(1, weight=1)

        ttk.Label(panes, text="Identities (Private Keys)",
                  style="Bold.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(panes, text="Contacts (Public Keys)",
                  style="Bold.TLabel").grid(row=0, column=1, sticky="w",
                                            padx=(12, 0))

        self.id_tree = self._make_tree(panes)
        self.id_tree.grid(row=1, column=0, sticky="nsew", pady=4)
        self.ct_tree = self._make_tree(panes)
        self.ct_tree.grid(row=1, column=1, sticky="nsew", pady=4,
                          padx=(12, 0))

        id_btns = ttk.Frame(panes)
        id_btns.grid(row=2, column=0, sticky="w")
        ttk.Button(id_btns, text="New Identity",
                   command=self.new_identity_dialog).pack(side="left",
                                                          padx=(0, 6))
        ttk.Button(id_btns, text="Copy Public Key",
                   command=self.copy_public_key).pack(side="left",
                                                      padx=(0, 6))
        ttk.Button(id_btns, text="Backup Private Key",
                   command=self.backup_private_key).pack(side="left",
                                                         padx=(0, 6))
        ttk.Button(id_btns, text="Delete",
                   command=lambda: self.delete_selected(self.id_tree)).pack(
                       side="left")

        ct_btns = ttk.Frame(panes)
        ct_btns.grid(row=2, column=1, sticky="w", padx=(12, 0))
        ttk.Button(ct_btns, text="Import Clipboard",
                   command=self.import_clipboard).pack(side="left",
                                                       padx=(0, 6))
        ttk.Button(ct_btns, text="Import File",
                   command=self.import_file).pack(side="left", padx=(0, 6))
        ttk.Button(ct_btns, text="Copy Key",
                   command=self.copy_contact_key).pack(side="left",
                                                       padx=(0, 6))
        ttk.Button(ct_btns, text="Delete",
                   command=lambda: self.delete_selected(self.ct_tree)).pack(
                       side="left")

        hint = ttk.Label(
            panes, style="Muted.TLabel",
            text=f"Keys: {KEYS_DIR}. "
                 "Back up your private keys somewhere safe.")
        hint.grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 0))

    def _make_tree(self, parent):
        tree = ttk.Treeview(parent, columns=("name", "type", "fpr"),
                            show="headings", height=12)
        tree.heading("name", text="Name")
        tree.heading("type", text="Type")
        tree.heading("fpr", text="Fingerprint")
        tree.column("name", width=140)
        tree.column("type", width=90, stretch=False)
        tree.column("fpr", width=320)
        return tree

    @staticmethod
    def _key_type_label(key):
        alg = key.key_algorithm
        if alg in (PubKeyAlgorithm.RSAEncryptOrSign,
                   PubKeyAlgorithm.RSAEncrypt, PubKeyAlgorithm.RSASign):
            return f"RSA {key.key_size}"
        return str(getattr(key.key_size, "name", key.key_size) or alg.name)

    def refresh_keys(self):
        for tree in (self.id_tree, self.ct_tree):
            tree.delete(*tree.get_children())
        self._identity_map = {}

        identities = sorted(self.store.identities(),
                            key=lambda k: display_name(k).lower())
        contacts = sorted(self.store.contacts(),
                          key=lambda k: display_name(k).lower())

        for key in identities:
            fpr = str(key.fingerprint)
            label = f"{display_name(key)}  [{fpr[-8:]}]"
            self._identity_map[label] = fpr
            self.id_tree.insert("", "end", iid=fpr, values=(
                display_name(key), self._key_type_label(key),
                short_fpr(key)))
        for key in contacts:
            self.ct_tree.insert("", "end", iid=str(key.fingerprint), values=(
                display_name(key), self._key_type_label(key),
                short_fpr(key)))

        labels = list(self._identity_map)
        self.identity_combo.config(values=labels)
        if labels and self.identity_var.get() not in labels:
            self.identity_var.set(labels[0])
        elif not labels:
            self.identity_var.set("")

        self.recipients_box.delete(0, "end")
        self._recipient_fprs = []
        for key in identities + contacts:
            tag = "me" if not key.is_public else "contact"
            self.recipients_box.insert(
                "end",
                f"{display_name(key)}  ({tag}, {str(key.fingerprint)[-8:]})")
            self._recipient_fprs.append(str(key.fingerprint))

    def new_identity_dialog(self):
        dlg = tk.Toplevel(self)
        dlg.title("New Identity")
        dlg.resizable(False, False)
        dlg.configure(bg=self.palette["bg"])
        dlg.transient(self)
        dlg.grab_set()
        frm = ttk.Frame(dlg, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Username:"
                  ).grid(row=0, column=0, sticky="w", columnspan=2)
        name_var = tk.StringVar()
        ttk.Entry(frm, textvariable=name_var, width=36).grid(
            row=1, column=0, columnspan=2, sticky="we", pady=(2, 8))

        ttk.Label(frm, text="Key type:").grid(row=2, column=0, sticky="w")
        type_var = tk.StringVar(value=list(KEY_TYPES)[0])
        ttk.Combobox(frm, textvariable=type_var, state="readonly",
                     values=list(KEY_TYPES), width=30).grid(
                         row=2, column=1, sticky="w", pady=(0, 8))

        ttk.Label(frm, text="Passphrase (optional):").grid(
            row=3, column=0, sticky="w")
        pw1 = tk.StringVar()
        ttk.Entry(frm, textvariable=pw1, show="•", width=28).grid(
            row=3, column=1, sticky="w", pady=(0, 4))
        ttk.Label(frm, text="Repeat passphrase:").grid(
            row=4, column=0, sticky="w")
        pw2 = tk.StringVar()
        ttk.Entry(frm, textvariable=pw2, show="•", width=28).grid(
            row=4, column=1, sticky="w", pady=(0, 8))

        info = ttk.Label(frm, text="", style="Muted.TLabel")
        info.grid(row=5, column=0, columnspan=2, sticky="w")

        def create():
            name = name_var.get().strip()
            if not name:
                return messagebox.showerror(APP_NAME, "Username is required.",
                                            parent=dlg)
            if pw1.get() != pw2.get():
                return messagebox.showerror(APP_NAME,
                                            "Passphrases do not match.",
                                            parent=dlg)
            btn.config(state="disabled")
            info.config(text="Generating key...")
            dlg.update_idletasks()

            def work():
                try:
                    key = generate_key(name, type_var.get(),
                                       pw1.get() or None)
                except Exception as e:
                    self.after(0, lambda: (
                        messagebox.showerror(APP_NAME,
                                             f"Key generation failed: {e}",
                                             parent=dlg),
                        btn.config(state="normal"),
                        info.config(text="")))
                    return

                def done():
                    self.store.save(key)
                    self.refresh_keys()
                    dlg.destroy()
                    self.set_status(
                        f"Created identity '{name}' "
                        f"[{short_fpr(key)}].", True)
                self.after(0, done)

            threading.Thread(target=work, daemon=True).start()

        btn = ttk.Button(frm, text="Create Key", command=create)
        btn.grid(row=6, column=0, columnspan=2, pady=(10, 0))
        dlg.bind("<Return>", lambda e: create())
        dlg.wait_visibility()
        dlg.focus_set()

    def _selected_key(self, tree):
        sel = tree.selection()
        if not sel:
            return None
        return self.store.get(sel[0])

    def copy_public_key(self):
        key = self._selected_key(self.id_tree)
        if key is None:
            return self.set_status("Select an identity first.", False)
        self.clipboard_clear()
        self.clipboard_append(str(key.pubkey))
        self.set_status(f"Public key of '{display_name(key)}' copied! "
                        "Share this with others.", True)

    def copy_contact_key(self):
        key = self._selected_key(self.ct_tree)
        if key is None:
            return self.set_status("Select a contact first.", False)
        self.clipboard_clear()
        self.clipboard_append(str(key))
        self.set_status(f"Key of '{display_name(key)}' copied.", True)

    def backup_private_key(self):
        key = self._selected_key(self.id_tree)
        if key is None:
            return self.set_status("Select an identity first.", False)
        if not key.is_protected:
            if not messagebox.askyesno(
                    APP_NAME,
                    "This private key has NO passphrase. Anyone who has the "
                    "backup file can use it.\n\nExport anyway?",
                    parent=self):
                return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".asc",
            initialfile=f"{display_name(key)}_PRIVATE.asc",
            filetypes=[("ASCII-armored key", "*.asc")])
        if not path:
            return
        Path(path).write_text(str(key), encoding="utf-8")
        self.set_status(f"Private key backed up to {path}. Keep it safe.",
                        True)

    def import_clipboard(self):
        try:
            text = self.clipboard_get()
        except tk.TclError:
            return self.set_status("Clipboard is empty.", False)
        self.import_text(text)

    def import_file(self):
        path = filedialog.askopenfilename(
            parent=self,
            filetypes=[("PGP keys", "*.asc *.gpg *.pgp *.key *.txt"),
                       ("All files", "*.*")])
        if not path:
            return
        try:
            text = Path(path).read_bytes()
        except OSError as e:
            return self.set_status(f"Could not read file: {e}", False)
        self.import_text(text)

    def import_text(self, text):
        try:
            imported = self.store.import_blob(text)
        except CRYPTO_ERRORS as e:
            return self.set_status(f"Import failed: {e}", False)
        if not imported:
            return self.set_status(
                "Nothing new to import.", False)
        self.refresh_keys()
        names = ", ".join(
            f"{display_name(k)} "
            f"({'identity' if not k.is_public else 'contact'})"
            for k in imported)
        self.set_status(f"Imported: {names}", True)

    def delete_selected(self, tree):
        sel = tree.selection()
        if not sel:
            return self.set_status("Select a key to delete.", False)
        fpr = sel[0]
        key = self.store.get(fpr)
        is_identity = key is not None and not key.is_public
        warning = (
            f"Delete '{display_name(key)}'?\n\n"
            + ("This is a PRIVATE key. Without a backup you will never be "
               "able to decrypt messages sent to it. This cannot be undone."
               if is_identity else "You can re-import it later if needed."))
        if not messagebox.askyesno(APP_NAME, warning, parent=self,
                                   icon="warning"):
            return
        self.store.delete(fpr)
        self.pw_cache.pop(fpr, None)
        self.refresh_keys()
        self.set_status("Key deleted.", None)
    def _build_settings(self):
        f = ttk.Frame(self.settings_tab, padding=16)
        f.pack(fill="both", expand=True, anchor="nw")

        ttk.Label(f, text="Appearance", style="Bold.TLabel").pack(anchor="w")
        self.dark_var = tk.BooleanVar(value=self.theme_name == "dark")
        ttk.Checkbutton(f, text="Dark Mode", variable=self.dark_var,
                        command=self.toggle_theme).pack(anchor="w",
                                                        pady=(4, 16))

        ttk.Label(f, text="Master Password", style="Bold.TLabel").pack(
            anchor="w")
        self.master_label = ttk.Label(f, text="", style="Muted.TLabel",
                                      wraplength=700, justify="left")
        self.master_label.pack(anchor="w", pady=(4, 6))
        row = ttk.Frame(f)
        row.pack(anchor="w", pady=(0, 16))
        ttk.Button(row, text="Change Master Password",
                   command=self.set_master_pw).pack(side="left", padx=(0, 6))
        self.remove_master_btn = ttk.Button(
            row, text="Remove Master Password",
            command=self.remove_master_pw)
        self.remove_master_btn.pack(side="left")

        ttk.Label(f, text="Storage", style="Bold.TLabel").pack(anchor="w")
        ttk.Label(f, text=f"Key Location: {KEYS_DIR}",
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 6))
        ttk.Button(f, text="Open Keys Folder",
                   command=lambda: os.startfile(KEYS_DIR)).pack(anchor="w")

    def update_master_ui(self):
        if self.store is not None and self.store.master_pw:
            self.master_label.config(
                text="ON. Every key file on disk is encrypted with your "
                     "master password (AES-256). You will be asked for it "
                     "each time the app starts.")
            self.remove_master_btn.state(["!disabled"])
        else:
            self.master_label.config(
                text="OFF. Key files are stored as plain text on disk. "
                     "Set a master password to encrypt all of them at rest.")
            self.remove_master_btn.state(["disabled"])

    def set_master_pw(self):
        pw = self.ask_password(
            APP_NAME, "New master password:",
            confirm=True)
        if pw is None:
            return
        if not pw:
            return self.set_status("Master password cannot be empty.", False)
        self.store.set_master(pw)
        self.update_master_ui()
        self.set_status("Master password set. All key files are now "
                        "encrypted at rest.", True)

    def remove_master_pw(self):
        if not self.store.master_pw:
            return
        if not messagebox.askyesno(
                APP_NAME,
                "Remove the master password?\n\nAll key files will be "
                "written back to disk UNENCRYPTED.", parent=self,
                icon="warning"):
            return
        self.store.remove_master()
        self.update_master_ui()
        self.set_status("Master password removed. Key files are stored "
                        "unencrypted again.", None)


def main():
    app = App()
    if not app._cancelled:
        app.mainloop()


if __name__ == "__main__":
    main()