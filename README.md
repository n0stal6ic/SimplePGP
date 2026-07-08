# SimplePGP

A minimal PGP toolkit in python

- **Anonymous**: identities are just a usernames.
- **Notepad**: Sign + Encrypt / Sign+Encrypt. Paste a PGP block & Decrypt / Verify.
- **Keys**: Create identities & import public keys from clipboard or file, copy your public key to share, back up private keys, delete keys.
- **Master Password**: Set Master Password in the settings tab to encrypt every key file on disk with AES-256. Master password asked once at startup and can be removed from settings.
- Keys are stored in `~/.simplepgp/keys`. Without a master password they are plain ASCII `.asc` files and with one they are encrypted `.enc` files only the master password
  can unlock.
- Default key type is RSA 4096 for compatibility and Ed25519 is offered for other keys.

## Setup

```
pip install -r requirements.txt
```

Double-click `SimplePGP.bat`
Run `python simplepgp.py`

Build the exe: `pip install pyinstaller` then
`pyinstaller --onefile --windowed --name SimplePGP --distpath bin simplepgp.py`
