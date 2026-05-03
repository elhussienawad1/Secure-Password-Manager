import os
import json
import hashlib
from Crypto.Cipher import AES

from src.sign_verify import sign_vault, verify_vault


def _vault_path(username):
    return os.path.join("data", username, "vault.json")


def normalize_website(website):
    """Case-insensitive site matching; used by vault and vault import/export merge logic."""
    return website.strip().lower()


def vault_is_initialized(username):
    return os.path.isfile(_vault_path(username))


def get_aes_key(master_password):
    bytePassword = master_password.encode()
    key = hashlib.sha256(bytePassword).digest()
    return key


def initialize_vault(username, master_password):
    if vault_is_initialized(username):
        print("[!] Vault already initialized.")
        return
    save_vault(username, master_password, [])
    print("[+] Vault initialized successfully.")


def encrypt_data(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)
    bytePlaintext = plaintext.encode()
    ciphertext, tag = cipher.encrypt_and_digest(bytePlaintext)

    nonce_hex = cipher.nonce.hex()
    ciphertext_hex = ciphertext.hex()
    tag_hex = tag.hex()

    return nonce_hex + ":" + ciphertext_hex + ":" + tag_hex


def decrypt_data(key, encrypted_data):
    parts = encrypted_data.split(":")

    nonce = bytes.fromhex(parts[0])
    ciphertext = bytes.fromhex(parts[1])
    tag = bytes.fromhex(parts[2])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except ValueError:
        print("[!] Wrong master password. Could not decrypt vault.")
        return None


def load_vault(username, master_password):
    path = _vault_path(username)

    if not os.path.exists(path):
        return None

    with open(path, "r") as f:
        vault_file = json.load(f)

    encrypted_vault = vault_file["encrypted_vault"]

    sig_parts = vault_file["signature"].split(":")
    r = sig_parts[0]
    s = sig_parts[1]

    if not verify_vault(username, encrypted_vault, r, s):
        print("[!!!] ALERT: Vault has been tampered with. Aborting.")
        return None

    key = get_aes_key(master_password)
    credentials_plain = decrypt_data(key, encrypted_vault)

    if credentials_plain is None:
        return None

    return json.loads(credentials_plain)


def save_vault(username, master_password, vault_data):
    vault_path = _vault_path(username)
    os.makedirs(os.path.join("data", username), exist_ok=True)

    key = get_aes_key(master_password)
    plaintext = json.dumps(vault_data)
    encrypted_vault = encrypt_data(key, plaintext)

    signature = sign_vault(username, encrypted_vault)

    vault_file = {
        "encrypted_vault": encrypted_vault,
        "signature": signature["r"] + ":" + signature["s"],
    }

    with open(vault_path, "w") as f:
        json.dump(vault_file, f, indent=4)

    print("[+] Vault saved successfully.")


def add_credential(username, master_password, website, user, password):
    if not vault_is_initialized(username):
        print("[!] Vault not initialized. Use 'Initialize vault / set master password' first.")
        return

    credentials = load_vault(username, master_password)

    if credentials is None:
        print("[!!!] Cannot add. Aborting.")
        return

    normalized_website = normalize_website(website)

    for entry in credentials:
        if normalize_website(entry["website"]) == normalized_website and entry["username"] == user:
            print("[!] This username on this website already exists.")
            return

    for entry in credentials:
        if entry["password"] == password:
            print(f"[!] Warning: this password is already used on {entry['website']}.")

    credentials.append({
        "website": website,
        "username": user,
        "password": password
    })

    save_vault(username, master_password, credentials)
    print(f"[+] Credential for {website} added.")


def retrieve_credential(username, master_password, website):
    if not vault_is_initialized(username):
        print("[!] Vault not initialized. Use 'Initialize vault / set master password' first.")
        return

    credentials = load_vault(username, master_password)

    if credentials is None:
        print("[!!!] Cannot retrieve. Aborting.")
        return

    normalized_website = normalize_website(website)

    for entry in credentials:
        if normalize_website(entry["website"]) == normalized_website:
            print(f"\n  Website:  {entry['website']}")
            print(f"  Username: {entry['username']}")
            print(f"  Password: {entry['password']}")
            return

    print(f"[!] No credential found for {website}.")


def update_credential(username, master_password, website, new_user, new_password):
    if not vault_is_initialized(username):
        print("[!] Vault not initialized. Use 'Initialize vault / set master password' first.")
        return

    credentials = load_vault(username, master_password)

    if credentials is None:
        print("[!!!] Cannot update. Aborting.")
        return

    normalized_website = normalize_website(website)

    for entry in credentials:
        if normalize_website(entry["website"]) == normalized_website:

            if new_password != "" and new_password == entry["password"]:
                print("[!] Warning: new password is the same as the current one.")

            if new_user != "":
                entry["username"] = new_user
            if new_password != "":
                entry["password"] = new_password

            save_vault(username, master_password, credentials)
            print(f"[+] Credential for {website} updated.")
            return

    print(f"[!] No credential found for {website}.")


def delete_credential(username, master_password, website):
    if not vault_is_initialized(username):
        print("[!] Vault not initialized. Use 'Initialize vault / set master password' first.")
        return

    credentials = load_vault(username, master_password)

    if credentials is None:
        print("[!!!] Cannot delete. Aborting.")
        return

    normalized_website = normalize_website(website)

    for i, entry in enumerate(credentials):
        if normalize_website(entry["website"]) == normalized_website:
            credentials.pop(i)
            save_vault(username, master_password, credentials)
            print(f"[+] Credential for {website} deleted.")
            return

    print(f"[!] No credential found for {website}.")


def list_credentials(username, master_password):
    if not vault_is_initialized(username):
        print("[!] Vault not initialized. Use 'Initialize vault / set master password' first.")
        return

    credentials = load_vault(username, master_password)

    if credentials is None:
        print("[!!!] Cannot list. Aborting.")
        return

    if len(credentials) == 0:
        print("[!] Vault is empty.")
        return

    print(f"\n  {'Website':<25} {'Username':<25} {'Password'}")
    print("  " + "-" * 65)
    for entry in credentials:
        print(f"  {entry['website']:<25} {entry['username']:<25} {entry['password']}")
