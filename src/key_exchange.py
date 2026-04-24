import os
import random  # fix: was "from random import random"
import json
from utltis import generate_large_prime

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

def export_vault(username: str, master_password: str, recipient: str):
    # This function would implement the logic to export the vault data encrypted with the recipient's public key
    pass