# SimplePGP

A minimal PGP toolkit in python

- **Anonymous**: identities are just a username, no email.
- **Notepad**: Write text → Sign / Encrypt / Sign+Encrypt it, or paste a PGP
  block → Decrypt / Verify.
- **Keys**: Create identities, import contacts' public keys (clipboard or
  file), copy your public key to share, back up private keys, delete keys.
- **Master Password**: Settings tab → Set Master Password.
  Every key file on disk gets encrypted with AES-256.
  Master password asked once at startup. Remove it any time from Settings.
- Keys are stored in `~/.simplepgp/keys`
  Without a master password they are plain ASCII-armored `.asc`
  files and with one they are encrypted `.enc` files only the master password
  can open.
- Default key type is RSA 4096 for compatibility and Ed25519 is offered for other keys.

## Setup

```
pip install -r requirements.txt
```

Double-click `SimplePGP.bat`
Run `python simplepgp.py`

Build the exe: `pip install pyinstaller` then
`pyinstaller --onefile --windowed --name SimplePGP --distpath bin simplepgp.py`