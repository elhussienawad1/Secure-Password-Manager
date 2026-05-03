import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os
import json
from src.keygen import generate_elgamal_keypair
from src.sign_verify import sign_vault, verify_vault
from src.vault import (
    add_credential, retrieve_credential, update_credential,
    delete_credential, list_credentials
)
from src.key_exchange import export_vault, import_vault


class SecurePasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("700x600")
        self.root.configure(bg="#f0f0f0")
        
        self.username = None
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.show_login_screen()
    
    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_login_screen(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True)
        
        title = ttk.Label(frame, text="Secure Password Manager", font=("Arial", 24, "bold"))
        title.pack(pady=20)
        
        ttk.Label(frame, text="Username:").pack(pady=5)
        username_entry = ttk.Entry(frame, width=30)
        username_entry.pack(pady=5)
        
        def login():
            user = username_entry.get().strip()
            if not user:
                messagebox.showerror("Error", "Username cannot be empty!")
                return
            self.username = user
            self.show_main_menu()
        
        ttk.Button(frame, text="Login", command=login).pack(pady=20)
    
    def show_main_menu(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill="both", expand=True)
        
        title = ttk.Label(frame, text=f"Welcome, {self.username}!", font=("Arial", 18, "bold"))
        title.pack(pady=20)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="both", expand=True, pady=10)
        
        buttons = [
            ("Initialize Account", self.show_init_account),
            ("Add Credential", self.show_add_credential),
            ("Retrieve Credential", self.show_retrieve_credential),
            ("Update Credential", self.show_update_credential),
            ("Delete Credential", self.show_delete_credential),
            ("List All Credentials", self.show_list_credentials),
            ("Verify Vault Integrity", self.show_verify_vault),
            ("Export Vault", self.show_export_vault),
            ("Import Vault", self.show_import_vault),
            ("Logout", self.show_login_screen),
        ]
        
        for text, command in buttons:
            btn = ttk.Button(button_frame, text=text, command=command, width=30)
            btn.pack(pady=8)
    
    def show_init_account(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True)
        
        ttk.Label(frame, text="Initialize Account", font=("Arial", 16, "bold")).pack(pady=20)
        
        if not os.path.exists("key.json"):
            messagebox.showerror("Error", "key.json not found!")
            self.show_main_menu()
            return
        
        user_folder = os.path.join("data", self.username)
        if os.path.exists(os.path.join(user_folder, "private.json")):
            messagebox.showwarning("Warning", "Account already initialized!")
            self.show_main_menu()
            return
        
        try:
            generate_elgamal_keypair(self.username)
            messagebox.showinfo("Success", "Account initialized successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize account: {str(e)}")
        
        self.show_main_menu()
    
    def show_add_credential(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Add Credential", font=("Arial", 16, "bold")).pack(pady=20)
        
        form_frame = ttk.Frame(frame)
        form_frame.pack(fill="both", padx=10, pady=10)
        
        ttk.Label(form_frame, text="Master Password:").pack(anchor="w", pady=5)
        master_pwd = ttk.Entry(form_frame, show="*", width=40)
        master_pwd.pack(anchor="w", pady=5)
        
        ttk.Label(form_frame, text="Website:").pack(anchor="w", pady=5)
        website = ttk.Entry(form_frame, width=40)
        website.pack(anchor="w", pady=5)
        
        ttk.Label(form_frame, text="Username:").pack(anchor="w", pady=5)
        username = ttk.Entry(form_frame, width=40)
        username.pack(anchor="w", pady=5)
        
        ttk.Label(form_frame, text="Password:").pack(anchor="w", pady=5)
        password = ttk.Entry(form_frame, show="*", width=40)
        password.pack(anchor="w", pady=5)
        
        result_frame = ttk.LabelFrame(frame, text="Result", padding="10")
        result_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        result_text = tk.Text(result_frame, height=6, width=50)
        result_text.pack(fill="both", expand=True)
        
        def save():
            try:
                success, message = add_credential(
                    self.username,
                    master_pwd.get(),
                    website.get(),
                    username.get(),
                    password.get()
                )
                result_text.config(state="normal")
                result_text.delete(1.0, tk.END)
                if success:
                    result_text.insert(tk.END, f"Success: {message}")
                    master_pwd.delete(0, tk.END)
                    website.delete(0, tk.END)
                    username.delete(0, tk.END)
                    password.delete(0, tk.END)
                else:
                    result_text.insert(tk.END, f"Error: {message}")
                result_text.config(state="disabled")
            except Exception as e:
                result_text.config(state="normal")
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"Error: {str(e)}")
                result_text.config(state="disabled")
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Save", command=save).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu).pack(side="left", padx=5)
    
    def show_retrieve_credential(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Retrieve Credential", font=("Arial", 16, "bold")).pack(pady=20)
        
        form_frame = ttk.Frame(frame)
        form_frame.pack(fill="both", padx=10, pady=10)
        
        ttk.Label(form_frame, text="Master Password:").pack(anchor="w", pady=5)
        master_pwd = ttk.Entry(form_frame, show="*", width=40)
        master_pwd.pack(anchor="w", pady=5)
        
        ttk.Label(form_frame, text="Website:").pack(anchor="w", pady=5)
        website = ttk.Entry(form_frame, width=40)
        website.pack(anchor="w", pady=5)
        
        result_frame = ttk.LabelFrame(frame, text="Result", padding="10")
        result_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        result_text = tk.Text(result_frame, height=8, width=50)
        result_text.pack(fill="both", expand=True)
        
        def retrieve():
            try:
                success, message, credential = retrieve_credential(self.username, master_pwd.get(), website.get())
                result_text.config(state="normal")
                result_text.delete(1.0, tk.END)
                
                if success:
                    result = f"Website:  {credential['website']}\n"
                    result += f"Username: {credential['username']}\n"
                    result += f"Password: {credential['password']}"
                    result_text.insert(tk.END, result)
                else:
                    result_text.insert(tk.END, f"Error: {message}")
                result_text.config(state="disabled")
            except Exception as e:
                result_text.config(state="normal")
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"Error: {str(e)}")
                result_text.config(state="disabled")
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Retrieve", command=retrieve).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu).pack(side="left", padx=5)
    
    def show_update_credential(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Update Credential", font=("Arial", 16, "bold")).pack(pady=20)
        
        form_frame = ttk.Frame(frame)
        form_frame.pack(fill="both", padx=10, pady=10)
        
        ttk.Label(form_frame, text="Master Password:").pack(anchor="w", pady=5)
        master_pwd = ttk.Entry(form_frame, show="*", width=40)
        master_pwd.pack(anchor="w", pady=5)
        
        ttk.Label(form_frame, text="Website:").pack(anchor="w", pady=5)
        website = ttk.Entry(form_frame, width=40)
        website.pack(anchor="w", pady=5)
        
        ttk.Label(form_frame, text="New Username (leave blank to keep):").pack(anchor="w", pady=5)
        new_user = ttk.Entry(form_frame, width=40)
        new_user.pack(anchor="w", pady=5)
        
        ttk.Label(form_frame, text="New Password (leave blank to keep):").pack(anchor="w", pady=5)
        new_pwd = ttk.Entry(form_frame, show="*", width=40)
        new_pwd.pack(anchor="w", pady=5)
        
        result_frame = ttk.LabelFrame(frame, text="Result", padding="10")
        result_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        result_text = tk.Text(result_frame, height=6, width=50)
        result_text.pack(fill="both", expand=True)
        
        def update():
            try:
                success, message = update_credential(
                    self.username,
                    master_pwd.get(),
                    website.get(),
                    new_user.get(),
                    new_pwd.get()
                )
                result_text.config(state="normal")
                result_text.delete(1.0, tk.END)
                if success:
                    result_text.insert(tk.END, f"Success: {message}")
                else:
                    result_text.insert(tk.END, f"Error: {message}")
                result_text.config(state="disabled")
            except Exception as e:
                result_text.config(state="normal")
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"Error: {str(e)}")
                result_text.config(state="disabled")
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Update", command=update).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu).pack(side="left", padx=5)
    
    def show_delete_credential(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Delete Credential", font=("Arial", 16, "bold")).pack(pady=20)
        
        form_frame = ttk.Frame(frame)
        form_frame.pack(fill="both", padx=10, pady=10)
        
        ttk.Label(form_frame, text="Master Password:").pack(anchor="w", pady=5)
        master_pwd = ttk.Entry(form_frame, show="*", width=40)
        master_pwd.pack(anchor="w", pady=5)
        
        ttk.Label(form_frame, text="Website:").pack(anchor="w", pady=5)
        website = ttk.Entry(form_frame, width=40)
        website.pack(anchor="w", pady=5)
        
        result_frame = ttk.LabelFrame(frame, text="Result", padding="10")
        result_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        result_text = tk.Text(result_frame, height=6, width=50)
        result_text.pack(fill="both", expand=True)
        
        def delete():
            if messagebox.askyesno("Confirm", "Are you sure you want to delete this credential?"):
                try:
                    success, message = delete_credential(self.username, master_pwd.get(), website.get())
                    result_text.config(state="normal")
                    result_text.delete(1.0, tk.END)
                    if success:
                        result_text.insert(tk.END, f"Success: {message}")
                    else:
                        result_text.insert(tk.END, f"Error: {message}")
                    result_text.config(state="disabled")
                except Exception as e:
                    result_text.config(state="normal")
                    result_text.delete(1.0, tk.END)
                    result_text.insert(tk.END, f"Error: {str(e)}")
                    result_text.config(state="disabled")
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Delete", command=delete).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu).pack(side="left", padx=5)
    
    def show_list_credentials(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="List Credentials", font=("Arial", 16, "bold")).pack(pady=20)
        
        form_frame = ttk.Frame(frame)
        form_frame.pack(fill="both", padx=10, pady=10)
        
        ttk.Label(form_frame, text="Master Password:").pack(anchor="w", pady=5)
        master_pwd = ttk.Entry(form_frame, show="*", width=40)
        master_pwd.pack(anchor="w", pady=5)
        
        result_frame = ttk.LabelFrame(frame, text="Credentials", padding="10")
        result_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create a text widget with scrollbar to display credentials
        text_frame = ttk.Frame(result_frame)
        text_frame.pack(fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")
        
        result_text = tk.Text(text_frame, height=12, width=60, yscrollcommand=scrollbar.set)
        result_text.pack(fill="both", expand=True)
        scrollbar.config(command=result_text.yview)
        
        def list_creds():
            try:
                success, message, credentials = list_credentials(self.username, master_pwd.get())
                result_text.config(state="normal")
                result_text.delete(1.0, tk.END)
                
                if not success:
                    result_text.insert(tk.END, f"Error: {message}")
                elif len(credentials) == 0:
                    result_text.insert(tk.END, "Vault is empty.")
                else:
                    header = f"{'Website':<25} {'Username':<25} {'Password'}\n"
                    header += "-" * 65 + "\n"
                    result_text.insert(tk.END, header)
                    for entry in credentials:
                        line = f"{entry['website']:<25} {entry['username']:<25} {entry['password']}\n"
                        result_text.insert(tk.END, line)
                
                result_text.config(state="disabled")
            except Exception as e:
                result_text.config(state="normal")
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"Error: {str(e)}")
                result_text.config(state="disabled")
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Load", command=list_creds).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu).pack(side="left", padx=5)
    
    def show_verify_vault(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True)
        
        ttk.Label(frame, text="Verify Vault Integrity", font=("Arial", 16, "bold")).pack(pady=20)
        
        vault_path = os.path.join("data", self.username, "vault.json")
        if not os.path.exists(vault_path):
            messagebox.showwarning("Warning", "No vault found. Add a credential first.")
            self.show_main_menu()
            return
        
        try:
            with open(vault_path, "r") as f:
                vault_file = json.load(f)
            
            encrypted_vault = vault_file["encrypted_vault"]
            sig_parts = vault_file["signature"].split(":")
            r = sig_parts[0]
            s = sig_parts[1]
            
            result = verify_vault(self.username, encrypted_vault, r, s)
            if result:
                messagebox.showinfo("Success", "Vault integrity verified. No tampering detected.")
            else:
                messagebox.showerror("Alert", "VAULT INTEGRITY CHECK FAILED! Vault may have been tampered with!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify vault: {str(e)}")
        
        self.show_main_menu()
    
    def show_export_vault(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Export Vault", font=("Arial", 16, "bold")).pack(pady=20)
        
        form_frame = ttk.Frame(frame)
        form_frame.pack(fill="both", padx=10, pady=10)
        
        ttk.Label(form_frame, text="Master Password:").pack(anchor="w", pady=5)
        master_pwd = ttk.Entry(form_frame, show="*", width=40)
        master_pwd.pack(anchor="w", pady=5)
        
        ttk.Label(form_frame, text="Recipient Username:").pack(anchor="w", pady=5)
        recipient = ttk.Entry(form_frame, width=40)
        recipient.pack(anchor="w", pady=5)
        
        result_frame = ttk.LabelFrame(frame, text="Result", padding="10")
        result_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        result_text = tk.Text(result_frame, height=8, width=50)
        result_text.pack(fill="both", expand=True)
        
        def export():
            try:
                if not os.path.exists(f"data/Export/{recipient.get()}_public.json"):
                    result_text.config(state="normal")
                    result_text.delete(1.0, tk.END)
                    result_text.insert(tk.END, f"Error: Public key for '{recipient.get()}' not found.")
                    result_text.config(state="disabled")
                    return
                
                success, message = export_vault(self.username, master_pwd.get(), recipient.get())
                result_text.config(state="normal")
                result_text.delete(1.0, tk.END)
                if success:
                    result_text.insert(tk.END, f"Success: {message}")
                else:
                    result_text.insert(tk.END, f"Error: {message}")
                result_text.config(state="disabled")
            except Exception as e:
                result_text.config(state="normal")
                result_text.delete(1.0, tk.END)
                result_text.insert(tk.END, f"Error: {str(e)}")
                result_text.config(state="disabled")
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Export", command=export).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu).pack(side="left", padx=5)
    
    def show_import_vault(self):
        self.clear_window()
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Import Vault", font=("Arial", 16, "bold")).pack(pady=20)
        
        form_frame = ttk.Frame(frame)
        form_frame.pack(fill="both", padx=10, pady=10)
        
        ttk.Label(form_frame, text="Sender Username:").pack(anchor="w", pady=5)
        sender = ttk.Entry(form_frame, width=40)
        sender.pack(anchor="w", pady=5)
        
        ttk.Label(form_frame, text="New Master Password for Imported Vault:").pack(anchor="w", pady=5)
        master_pwd = ttk.Entry(form_frame, show="*", width=40)
        master_pwd.pack(anchor="w", pady=5)
        
        def import_v():
            try:
                import_vault(self.username, master_pwd.get(), sender.get())
                messagebox.showinfo("Success", "Vault imported successfully!")
                self.show_main_menu()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import vault: {str(e)}")
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Import", command=import_v).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu).pack(side="left", padx=5)


def main():
    root = tk.Tk()
    app = SecurePasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
