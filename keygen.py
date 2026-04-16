import os
import json
import random
import secrets




def load_parameters():
    if not os.path.exists("key.json"):
        print("[!] key.json not found.")

    with open("key.json", "r") as f:
        params = json.load(f)

    p = int(params["p"], 16)
    alpha = params["alpha"]
    return p, alpha

def generate_elgamal_keypair(username):
    p, alpha = load_parameters()

    #1 < x < p - 1
    #2 ≤ x ≤ p - 2
    
    # x = random.randint(2, p - 2)
    
    x = secrets.randbelow(p - 3) + 2

    # y = alpha^x mod p
    y = pow(alpha, x, p)
    
    base_folder = "data"

    # Save private key in the user's own folder
    user_folder = os.path.join(base_folder, username)
    os.makedirs(user_folder, exist_ok=True)

    private_key = {
        "username": username,
        "p": str(p),
        "alpha": str(alpha),
        "x": str(x)
    }

    with open(os.path.join(user_folder, "private.json"), "w") as f:
        json.dump(private_key, f, indent=4)
    print(f"[+] Private key saved to {user_folder}/private.json")

    # Export public key to the Export folder
    export_folder = os.path.join(base_folder, "Export")
    os.makedirs(export_folder, exist_ok=True)

    public_key = {
        "username": username,
        "p": str(p),
        "alpha": str(alpha),
        "y": str(y)
    }

    with open(os.path.join(export_folder, f"{username}_public.json"), "w") as f:
        json.dump(public_key, f, indent=4)
    print(f"[+] Public key exported to {export_folder}/{username}_public.json")

    return private_key, public_key

