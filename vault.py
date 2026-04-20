import os
import json
from Crypto.Cipher import AES
import hashlib
from sign_verify import sign_vault, verify_vault

# Get AES key from master password
# same output for same input 
def get_aes_key(master_password):
    bytePassword = master_password.encode() # Convert string to bytes
    key = hashlib.sha256(bytePassword).digest() #.digest() returns bytes
    return key

# encrypt the vault data using AES-GCM
def encrypt_data(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM) # Create a new AES cipher in GCM mode and generate a random nonce
    bytePlaintext = plaintext.encode()
    ciphertext, tag = cipher.encrypt_and_digest(bytePlaintext) # Encrypt the plaintext and compute the tag
    
    nonce_hex = cipher.nonce.hex() 
    ciphertext_hex = ciphertext.hex()
    tag_hex = tag.hex()
    
    return nonce_hex + ":" + ciphertext_hex + ":" + tag_hex


# decrypt the vault data using AES-GCM
def decrypt_data(key, encrypted_data):
    parts = encrypted_data.split(":") # Split the encrypted data into nonce, ciphertext, and tag

    # convert the hex strings back to bytes
    nonce = bytes.fromhex(parts[0]) 
    ciphertext = bytes.fromhex(parts[1]) 
    tag = bytes.fromhex(parts[2]) 

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce) # Create a new AES cipher in GCM mode with the nonce already saved
    plaintext = cipher.decrypt_and_verify(ciphertext, tag) # Decrypt the ciphertext and verify the tag

    return plaintext.decode()  # Convert the decrypted plaintext from bytes to string and return it 


def load_vault(username, master_password):
    vault_path = os.path.join("data", username, "vault.json") #build path
    
    if not os.path.exists(vault_path):  #if vault doesn't exist return empty array
        return []
    
    with open(vault_path, "r") as f:
        vault_file = json.load(f) #reads the whole vault.json into a Python dictionary
    
    encrypted_vault = vault_file["encrypted_vault"] # get encrypted string from vault file

    # Extract r and s from the signature
    sig_parts = vault_file["signature"].split(":")
    r = sig_parts[0]
    s = sig_parts[1]
    
    # Verify the vault's integrity using the signature before decryption
    if not verify_vault(username, encrypted_vault, r, s):
        print("[!!!] ALERT: Vault has been tampered with. Aborting.")
        return None
    
    key = get_aes_key(master_password)
    credentials = decrypt_data(key, encrypted_vault)
    
    return json.loads(credentials) # Convert the decrypted JSON string back to a Python list 


def save_vault(username, master_password, vault_data):
    vault_path = os.path.join("data", username, "vault.json")
    
    key = get_aes_key(master_password)
    plaintext = json.dumps(vault_data) # converts your Python list back into a JSON string 
    encrypted_vault = encrypt_data(key, plaintext)
    
    signature = sign_vault(username, encrypted_vault)
    
    # create a dictionary to store the encrypted vault and its signature, then save it to the vault.json file
    vault_file = {
        "encrypted_vault": encrypted_vault,
        "signature": signature["r"] + ":" + signature["s"]
    }
    
    with open(vault_path, "w") as f:
        json.dump(vault_file, f, indent=4)
    
    print("[+] Vault saved successfully.")


def add_credential(username, master_password, website, user, password):
    credentials = load_vault(username, master_password)
    
    if credentials is None:
        print("[!!!] Cannot add. Vault integrity check failed.")
        return
    
    for entry in credentials:
        if entry["website"] == website and entry["username"] == user: # user can't be on the same website twice
            print("[!] This username on this website already exists.")
            return
    
    for entry in credentials:
        if entry["password"] == password: #give warning if password is already used for another account, but still allow it to be added
            print(f"[!] Warning: this password is already used on {entry['website']}.")
    
    credentials.append({
        "website": website,
        "username": user,
        "password": password
    })
    
    save_vault(username, master_password, credentials)
    print(f"[+] Credential for {website} added.")


def retrieve_credential(username, master_password, website):
    credentials = load_vault(username, master_password)

    if credentials is None:
        print("[!!!] Cannot retrieve. Vault integrity check failed.")
        return

    #search for selected entery and print it if found, otherwise print not found message
    for entry in credentials:
        if entry["website"] == website:
            print(f"\n  Website:  {entry['website']}")
            print(f"  Username: {entry['username']}")
            print(f"  Password: {entry['password']}")
            return

    print(f"[!] No credential found for {website}.")


def update_credential(username, master_password, website, new_user, new_password):
    credentials = load_vault(username, master_password)

    if credentials is None:
        print("[!!!] Cannot update. Vault integrity check failed.")
        return

    for entry in credentials:
        if entry["website"] == website:

            if new_password != "" and new_password == entry["password"]:
                print("[!] Warning: new password is the same as the current one.")

            #if the user leaves either field blank, it won't be updated, save old value instead
            if new_user != "":
                entry["username"] = new_user
            if new_password != "":
                entry["password"] = new_password

            save_vault(username, master_password, credentials)
            print(f"[+] Credential for {website} updated.")
            return

    print(f"[!] No credential found for {website}.")


def delete_credential(username, master_password, website):
    credentials = load_vault(username, master_password)

    if credentials is None:
        print("[!!!] Cannot delete. Vault integrity check failed.")
        return

    #search for the selected entry and delete it if found
    for i, entry in enumerate(credentials):
        if entry["website"] == website:
            credentials.pop(i)
            save_vault(username, master_password, credentials)
            print(f"[+] Credential for {website} deleted.")
            return

    print(f"[!] No credential found for {website}.")


def list_credentials(username, master_password):
    credentials = load_vault(username, master_password)

    if credentials is None:
        print("[!!!] Cannot list. Vault integrity check failed.")
        return

    if len(credentials) == 0:
        print("[!] Vault is empty.")
        return

    print(f"\n  {'Website':<25} {'Username':<25} {'Password'}")
    print("  " + "-" * 65)
    for entry in credentials:
        print(f"  {entry['website']:<25} {entry['username']:<25} {entry['password']}")