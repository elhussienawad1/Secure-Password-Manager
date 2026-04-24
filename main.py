import os
import json
from keygen import generate_elgamal_keypair
from sign_verify import sign_vault, verify_vault
from vault import add_credential, retrieve_credential, update_credential, delete_credential, list_credentials
from src.key_exchange import export_vault


def main():
    print("=" * 50)
    print("   Secure Password Manager")
    print("=" * 50)

    # Get current user
    username = input("\nEnter your username: ").strip()

    while True:
        print(f"\n[Logged in as: {username}]")
        print("\n--- Main Menu ---")
        print("1. Initialize account (generate keys)")
        print("2. Add credential")
        print("3. Retrieve credential")
        print("4. Update credential")
        print("5. Delete credential")
        print("6. List all credentials")
        print("7. Verify vault integrity")
        print("8. Export vault to another user")
        print("9. Import vault from another user")
        print("0. Exit")

        choice = input("\nChoice: ").strip()

        if choice == "1":
            # Module 1
            if not os.path.exists("key.json"):
                raise FileNotFoundError("[!] key.json not found.")
            
            if os.path.exists(os.path.join("data", username, "private.json")):
                print("[!] Account already initialized.")
            else:
                generate_elgamal_keypair(username)
                print("[+] Account initialized successfully.")

        elif choice == "2":
            # Module 2 - Add
            # if not os.path.exists(f"{username}_private.json"):
            #     print("[!] Please initialize your account first (option 1).")
            #     continue
            master_password = input("Master password: ").strip()
            website  = input("Website: ").strip()
            user     = input("Username for site: ").strip()
            password = input("Password for site: ").strip()
            add_credential(username, master_password, website, user, password)

        elif choice == "3":
            # Module 2 - Retrieve
            # if not os.path.exists(f"{username}_private.json"):
            #     print("[!] Please initialize your account first (option 1).")
            #     continue
            master_password = input("Master password: ").strip()
            website = input("Website to retrieve: ").strip()
            retrieve_credential(username, master_password, website)

        elif choice == "4":
            # Module 2 - Update
            # if not os.path.exists(f"{username}_private.json"):
            #     print("[!] Please initialize your account first (option 1).")
            #     continue
            master_password  = input("Master password: ").strip()
            website          = input("Website to update: ").strip()
            new_user         = input("New username (leave blank to keep): ").strip()
            new_password     = input("New password (leave blank to keep): ").strip()
            update_credential(username, master_password, website, new_user, new_password)

        elif choice == "5":
            # Module 2 - Delete
            # if not os.path.exists(f"{username}_private.json"):
            #     print("[!] Please initialize your account first (option 1).")
            #     continue
            master_password = input("Master password: ").strip()
            website         = input("Website to delete: ").strip()
            delete_credential(username, master_password, website)

        elif choice == "6":
            # Module 2 - List all
            # if not os.path.exists(f"{username}_private.json"):
            #     print("[!] Please initialize your account first (option 1).")
            #     continue
            master_password = input("Master password: ").strip()
            list_credentials(username, master_password)

        elif choice == "7":
            if not os.path.exists(f"data/{username}/private.json"):
                print("[!] Please initialize your account first (option 1).")
                continue

            vault_path = os.path.join("data", username, "vault.json")
            if not os.path.exists(vault_path):
                print("[!] No vault found. Add a credential first.")
                continue

            with open(vault_path, "r") as f:
                vault_file = json.load(f)

            encrypted_vault = vault_file["encrypted_vault"]
            sig_parts = vault_file["signature"].split(":")
            r = sig_parts[0]
            s = sig_parts[1]

            result = verify_vault(username, encrypted_vault, r, s)
            if result:
                print("[+] Vault integrity verified. No tampering detected.")
            else:
                print("[!!!] ALERT: Vault integrity check FAILED. Vault may have been tampered with!")

        elif choice == "8":
        #     # Module 4 - Export
        #     if not os.path.exists(f"{username}_private.json"):
        #         print("[!] Please initialize your account first (option 1).")
        #         continue
            master_password = input("Master password: ").strip()
            recipient       = input("Recipient username: ").strip()
            if not os.path.exists(f"{recipient}_public.json"):
                print(f"[!] Public key for '{recipient}' not found.")
                continue
            export_vault(username, master_password, recipient)

        # elif choice == "9":
        #     # Module 4 - Import
        #     if not os.path.exists(f"{username}_private.json"):
        #         print("[!] Please initialize your account first (option 1).")
        #         continue
        #     sender          = input("Sender username: ").strip()
        #     master_password = input("Enter your new master password for the imported vault: ").strip()
        #     import_vault(username, master_password, sender)

        elif choice == "0":
            print("\nGoodbye!")
            break

        else:
            print("[!] Invalid choice. Please try again.")


if __name__ == "__main__":
    main()