import os
import random
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from src.utltis import generate_large_prime
from src.sign_verify import sign_vault, verify_vault
from src.vault import decrypt_data, encrypt_data, load_vault, normalize_website, save_vault, vault_is_initialized
from src.keygen import load_parameters 

def generate_dh_parameters(bits: int = 512) -> dict:
    q = generate_large_prime(bits)
    alpha = 2
    return {"q": hex(q), "alpha": hex(alpha)}

def save_dh_parameters(parameters: dict, filename: str):
    with open(filename, "w") as f:
        json.dump(parameters, f)

def load_dh_parameters(filename: str) -> dict:
    if not os.path.exists(filename):
        print(f"[!] {filename} not found.")
        return None
    with open(filename, "r") as f:
        data = json.load(f)
    # convert hex strings back to ints
    return {"q": int(data["q"], 16), "alpha": int(data["alpha"], 16)}

def generate_private_key(q: int) -> int:
    return random.randint(2, q - 2)

def generate_public_key(X: int, alpha: int, q: int) -> int:
    return pow(alpha, X, q)

def compute_shared_secret(public: int, private: int, q: int) -> int:
    return pow(public, private, q) 

def derive_session_key(shared_secret: int) -> bytes:
    # Derive a 256-bit AES key from the shared secret using SHA-256
    return hashlib.sha256(str(shared_secret).encode()).digest()


def export_vault(username: str, master_password: str, recipient: str):
    # --- Load DH parameters ---
    q,alpha = load_parameters()


    # --- Device 1 generates ephemeral DH key pair ---
    d1_priv = generate_private_key(q)
    d1_pub  = generate_public_key(d1_priv, alpha, q)

    # --- Device 1 signs its DH public key ---
    d1_pub_sig = sign_vault(username, str(d1_pub))
    r1, s1 = d1_pub_sig["r"], d1_pub_sig["s"]
    print(f"[+] Device 1 DH public key generated and signed (r={r1}, s={s1})")

    # --- Device 2 generates ephemeral DH key pair ---
    d2_priv = generate_private_key(q)
    d2_pub  = generate_public_key(d2_priv, alpha, q)

    # --- Device 2 signs its DH public key ---
    d2_pub_sig = sign_vault(recipient, str(d2_pub))
    r2, s2 = d2_pub_sig["r"], d2_pub_sig["s"]
    print(f"[+] Device 2 DH public key generated and signed (r={r2}, s={s2})")

    # --- Device 1 verifies Device 2's signature ---
    print("[*] Verifying Device 2's DH public key signature...")
    if not verify_vault(recipient, str(d2_pub), r2, s2):
        print("[!!!] Device 2 DH public key signature invalid. Aborting export.")
        return (False, "Device 2 DH public key signature invalid.")

    # --- Device 2 verifies Device 1's signature ---
    print("[*] Verifying Device 1's DH public key signature...")
    if not verify_vault(username, str(d1_pub), r1, s1):
        print("[!!!] Device 1 DH public key signature invalid. Aborting export.")
        return (False, "Device 1 DH public key signature invalid.")

    print("[+] Both DH public key signatures verified successfully.")

    # --- Load Device 1's vault (encrypted + verified master password) ---
    if not vault_is_initialized(username):
        print("[!] Vault not found.")
        return (False, "Vault not found.")

    credentials = load_vault(username, master_password)
    if credentials is None:
        print("[!] Invalid master password or vault unreadable.")
        return (False, "Invalid master password or vault unreadable.")

    plaintext_entries = json.dumps(credentials)
    if len(credentials) == 0:
        print("[!] Cannot export empty vault. Add credentials first.")
        return (False, "Cannot export empty vault. Add credentials first.")

    # --- Compute shared secret and derive session key ---
    shared_secret = compute_shared_secret(d2_pub, d1_priv, q)
    session_key   = derive_session_key(shared_secret)

    # --- Encrypt plaintext entries with session key ---
    session_encrypted = encrypt_data(session_key, plaintext_entries)

# --- Sign the session-encrypted ciphertext with Device 1's private key ---
    transfer_sig = sign_vault(username, session_encrypted)
    tr, ts = transfer_sig["r"], transfer_sig["s"]
    print("[+] Transfer payload signed by Device 1.")

    # --- Build and save export package ---
    export_package = {
        "sender":            username,
        "recipient":         recipient,
        "d1_dh_public":      d1_pub,
        "d2_dh_public":      d2_pub,
        "session_encrypted": session_encrypted,
        "signature":         f"{tr}:{ts}",
    }

    export_dir = os.path.join("data", "Export")
    os.makedirs(export_dir, exist_ok=True)
    export_path = os.path.join(export_dir, f"{username}_to_{recipient}.json")
    with open(export_path, "w") as f:
        json.dump(export_package, f, indent=2)

    # --- Save d2_priv temporarily so import can recompute shared secret ---
    session_path = os.path.join(export_dir, f"{username}_to_{recipient}_session.json")
    with open(session_path, "w") as f:
        json.dump({"d2_priv": d2_priv}, f)

    print(f"[+] Vault exported successfully to {export_path}")
    return (True, "Vault exported successfully.")


def import_vault(username: str, master_password: str, sender: str):
    # --- Load export package ---
    export_path = os.path.join("data", "Export", f"{sender}_to_{username}.json")
    if not os.path.exists(export_path):
        print(f"[!] Export package not found: {export_path}")
        return

    with open(export_path, "r") as f:
        package = json.load(f)

    # --- Load DH parameters ---
    q, alpha = load_parameters()

    # --- Load d2_priv from temp session file ---
    session_path = os.path.join("data", "Export", f"{sender}_to_{username}_session.json")
    if not os.path.exists(session_path):
        print("[!] DH session data not found. Cannot derive shared secret.")
        return

    with open(session_path, "r") as f:
        d2_priv = json.load(f)["d2_priv"]

    # --- Recompute shared secret and session key ---
    d1_pub = package["d1_dh_public"]
    shared_secret = compute_shared_secret(d1_pub, d2_priv, q)
    session_key = derive_session_key(shared_secret)

    # --- Verify Device 1's signature over the session-encrypted data ---
    session_encrypted = package["session_encrypted"]
    tr, ts = package["signature"].split(":")

    print("[*] Verifying transfer signature...")
    if not verify_vault(sender, session_encrypted, tr, ts):
        print("[!!!] Transfer signature invalid. Aborting import.")
        return

    print("[+] Transfer signature verified successfully.")

    # --- Decrypt session-encrypted payload (JSON list of credential dicts) ---
    plaintext_entries = decrypt_data(session_key, session_encrypted)
    if plaintext_entries is None:
        print("[!!!] Decryption failed. Data may be corrupted.")
        return

    try:
        incoming_credentials = json.loads(plaintext_entries)
    except json.JSONDecodeError:
        print("[!!!] Imported payload is not valid credential data.")
        return

    if not isinstance(incoming_credentials, list):
        print("[!!!] Imported payload must be a list of credentials.")
        return

    # --- Existing local vault (same format as vault.py: signature + AES-GCM) ---
    vault_path = os.path.join("data", username, "vault.json")
    existing_credentials = []
    if os.path.exists(vault_path):
        existing_credentials = load_vault(username, master_password)
        if existing_credentials is None:
            print("[!] Failed to decrypt or verify existing vault. Wrong master password?")
            return
        print(f"[+] Loaded {len(existing_credentials)} existing credential(s).")

    # Merge on (username, normalized website); imported entry wins on conflict
    merged = {
        (entry["username"], normalize_website(entry["website"])): entry
        for entry in existing_credentials
    }

    duplicates = 0
    added = 0
    for entry in incoming_credentials:
        key = (entry["username"], normalize_website(entry["website"]))
        if key in merged:
            duplicates += 1
        else:
            added += 1
        merged[key] = entry

    merged_list = list(merged.values())

    print(
        f"[+] Merge complete: {added} new entry/entries added, "
        f"{duplicates} duplicate(s) overwritten with imported data."
    )

    save_vault(username, master_password, merged_list)

    os.remove(session_path)

    print(f"[+] Vault imported and merged successfully for '{username}'.")
