import os
import random
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from src.utltis import generate_large_prime
from src.sign_verify import sign_vault, verify_vault
from src.vault import get_aes_key, encrypt_data, decrypt_data
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

    # --- Load Device 1's vault ---
    vault_path = os.path.join("data", username, "vault.json")
    if not os.path.exists(vault_path):
        print("[!] Vault not found.")
        return (False, "Vault not found.")

    with open(vault_path, "r") as f:
        vault_file = json.load(f)

    # --- Decrypt vault with master password ---
    aes_key = get_aes_key(master_password)
    try:
        plaintext_entries = decrypt_data(aes_key, vault_file["encrypted_vault"])
    except Exception:
        print("[!] Failed to decrypt vault. Wrong master password?")
        return (False, "Failed to decrypt vault. Wrong master password?")

    # --- Check if vault is empty ---
    credentials = json.loads(plaintext_entries)
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
    q,alpha = load_parameters()
    
    # --- Load d2_priv from temp session file ---
    session_path = os.path.join("data", "Export", f"{sender}_to_{username}_session.json")
    if not os.path.exists(session_path):
        print("[!] DH session data not found. Cannot derive shared secret.")
        return

    with open(session_path, "r") as f:
        d2_priv = json.load(f)["d2_priv"]

    # --- Recompute shared secret and session key ---
    d1_pub        = package["d1_dh_public"]
    shared_secret = compute_shared_secret(d1_pub, d2_priv, q)
    session_key   = derive_session_key(shared_secret)

    # --- Verify Device 1's signature over the session-encrypted data ---
    session_encrypted = package["session_encrypted"]
    tr, ts = package["signature"].split(":")

    print("[*] Verifying transfer signature...")
    if not verify_vault(sender, session_encrypted, tr, ts):
        print("[!!!] Transfer signature invalid. Aborting import.")
        return

    print("[+] Transfer signature verified successfully.")

    # --- Decrypt session-encrypted data ---
    try:
        plaintext_entries = decrypt_data(session_key, session_encrypted)
    except Exception:
        print("[!!!] Decryption failed. Data may be corrupted.")
        return

    # --- Re-encrypt with Device 2's master password ---
    aes_key           = get_aes_key(master_password)
    new_encrypted_vault = encrypt_data(aes_key, plaintext_entries)

    # --- Sign new vault with Device 2's private key ---
    new_sig = sign_vault(username, new_encrypted_vault)
    nr, ns  = new_sig["r"], new_sig["s"]

    # --- Save vault ---
    os.makedirs(os.path.join("data", username), exist_ok=True)
    vault_path = os.path.join("data", username, "vault.json")
    with open(vault_path, "w") as f:
        json.dump({
            "encrypted_vault": new_encrypted_vault,
            "signature":       f"{nr}:{ns}",
        }, f, indent=2)

    # --- Clean up temp session file ---
    os.remove(session_path)

    print(f"[+] Vault imported successfully for '{username}'.")    
