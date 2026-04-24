import os
import json
import secrets
import hashlib
from math import gcd

def load_private_key(username):
    path = os.path.join("data", username, "private.json")
    with open(path, "r") as f:
        return json.load(f)

def load_public_key(username):
    path = os.path.join("data", "Export", f"{username}_public.json")
    with open(path, "r") as f:
        return json.load(f)
   
#data -> bytes for SHA-256 -> hex -> int for math 
def sha256_int(data):
    h = hashlib.sha256(data.encode("utf-8")).hexdigest()
    return int(h, 16)

def vault_to_string(encrypted_vault: str) -> str:
    if not isinstance(encrypted_vault, str):
        raise TypeError("encrypted_vault must be a packed base64 string")
    return encrypted_vault


def sign_vault(username, vault_data):
    priv = load_private_key(username)

    p     = int(priv["p"])
    alpha = int(priv["alpha"])
    x     = int(priv["x"])
    
    vault_string = vault_to_string(vault_data)
    h = sha256_int(vault_string)

    while True:
        # 2 ≤ k ≤ q-1 coprime with q so that k⁻¹ mod q exists
        k = secrets.randbelow(p - 3) + 2
        if gcd(k, p - 1) == 1:
            break

    #r = α^k mod p O(k) → O(log k)
    r = pow(alpha, k, p)
    
    #k_inv = k^-1 mod q
    k_inv = pow(k, -1, p - 1)
    
    #s = k⁻¹ · (H - x·r) mod q
    s = (k_inv * (h - x * r)) % (p - 1)
    
    while s == 0:
        while True:
            # 2 ≤ k ≤ q-1 coprime with q so that k⁻¹ mod q exists
            k = secrets.randbelow(p - 3) + 2
            if gcd(k, p - 1) == 1:
                break

        #r = α^k mod p O(k) → O(log k)
        r = pow(alpha, k, p)
        
        #k_inv = k^-1 mod q
        k_inv = pow(k, -1, p - 1)
        
        #s = k⁻¹ · (H - x·r) mod q
        s = (k_inv * (h - x * r)) % (p - 1)

    return {"r": str(r), "s": str(s)}


def verify_vault(username, vault_data, r, s):
    pub  = load_public_key(username)
    priv = load_private_key(username)

    p     = int(pub["p"])
    alpha = int(pub["alpha"])
    y     = int(pub["y"])
    x     = int(priv["x"])
   

    expected_y = pow(alpha, x, p)
    # print(f"DEBUG keys match: {y == expected_y}")

    r = int(r)  
    s = int(s)  

    if not (1 <= r <= p - 1):
        print("[!] Invalid signature: r out of range.")
        return False

    vault_string = vault_to_string(vault_data)
    h = sha256_int(vault_string)

        # print(f"DEBUG h={h}")
        # print(f"DEBUG r={r}")
        # print(f"DEBUG s={s}")

    # Verify: α^h ≡ y^r · r^s (mod p)
    left  = pow(alpha, h, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p

    # print(f"DEBUG left={left}")
    # print(f"DEBUG right={right}")

    return left == right


