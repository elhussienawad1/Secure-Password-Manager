# Secure Password Manager

A cryptographic password manager built for CMPS426 — Security Course Project at Cairo University, Faculty of Engineering.

---

## Requirements

- Python 3.8 or higher
- `pycryptodome` library

Install dependencies:

```bash
pip install pycryptodome
```


## How to Run

### Option 1 — Graphical Interface (GUI)

```bash
python gui.py
```

### Option 2 — Command-Line Interface (CLI)

```bash
python main.py
```

---

## Full Workflow

The correct order for a new user is: **Initialize Account → Initialize Vault → Add Credentials**.

---

### Step 1 — Initialize Account (Generate Keys)

Generates the user's ElGamal key pair. The private key is saved locally; the public key is exported to `data/Export/` for others to use when verifying signatures.

- **GUI:** Click **Initialize Account**.
- **CLI:** Select option `1`.

>  This must be done **before** initializing the vault or performing any credential operation. Without a key pair, signing is impossible.

---

### Step 2 — Initialize Vault / Set Master Password

Creates an empty encrypted vault protected by the chosen master password. This is a separate step from key generation, allowing users to set (and potentially change) their master password independently.

- **CLI:** Select option `10`.
- Enter and confirm your master password when prompted.

>  The master password is **never stored**. If you lose it, your vault cannot be decrypted.

>  You must complete Step 1 (account initialization) before this step, as vault creation requires signing with your private key.

---

### Step 3 — Add Credentials

Provide your master password, website, username, and password for the site.

- **GUI:** Click **Add Credential**, fill in the form, and click **Save**.
- **CLI:** Select option `2`.

The vault is decrypted in memory, the new entry is appended, and the vault is re-encrypted with AES-GCM and re-signed with ElGamal. A warning is shown if the password is already used elsewhere, but the credential is still saved.

---

### Step 4 — Retrieve / Update / Delete Credentials

All operations require the master password. The vault is decrypted in memory, the operation is performed, then the vault is re-encrypted and re-signed.

| Action | CLI Option | GUI Button |
|--------|-----------|------------|
| Retrieve | `3` | Retrieve Credential |
| Update | `4` | Update Credential |
| Delete | `5` | Delete Credential |
| List All | `6` | List All Credentials |

For **Update**, leave the username or password field blank to keep the existing value.

---

### Step 5 — Verify Vault Integrity

Checks the ElGamal digital signature on the encrypted vault without decrypting it. Any modification to the vault file — even a single byte — causes verification to fail.

- **GUI:** Click **Verify Vault Integrity**.
- **CLI:** Select option `7`.

---

### Step 6 — Export Vault to Another User

Securely transfers your encrypted vault to another user using Diffie-Hellman key exchange. Both users must have completed Steps 1 and 2 first (so their key files exist).

- **GUI:** Click **Export Vault**, enter your master password and the recipient's username.
- **CLI:** Select option `8`. The recipient's public key must exist at `data/Export/<recipient>_public.json`.

An export package is created at `data/Export/<sender>_to_<recipient>.json`.

---

### Step 7 — Import Vault from Another User

The recipient imports the exported vault and assigns a new master password to it.

- **GUI:** Click **Import Vault**, enter the sender's username and a new master password.
- **CLI:** Select option `9`.

The vault is decrypted using the session key, re-encrypted under the recipient's master password, and re-signed with the recipient's private key. The temporary session file is deleted after import.

---

