import io
import json
import os
import tkinter as tk
from contextlib import redirect_stdout
from tkinter import messagebox, ttk

from src.key_exchange import export_vault, import_vault
from src.keygen import generate_elgamal_keypair
from src.sign_verify import verify_vault
from src.vault import (
    add_credential,
    delete_credential,
    initialize_vault,
    load_vault,
    update_credential,
    vault_is_initialized,
)


class SecurePasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("860x650")
        self.root.minsize(780, 560)

        self.username = None
        self.style = ttk.Style(self.root)
        self.style.theme_use("clam")
        self._configure_styles()

        self.show_login_screen()

    def _configure_styles(self):
        self.root.configure(bg="#10172a")
        self.style.configure("Root.TFrame", background="#10172a")
        self.style.configure("Card.TFrame", background="#f8fafc")
        self.style.configure("Title.TLabel", font=("Segoe UI", 24, "bold"), background="#f8fafc", foreground="#0f172a")
        self.style.configure("Subtitle.TLabel", font=("Segoe UI", 11), background="#f8fafc", foreground="#334155")
        self.style.configure("CardTitle.TLabel", font=("Segoe UI", 17, "bold"), background="#f8fafc", foreground="#0f172a")
        self.style.configure("Label.TLabel", font=("Segoe UI", 10), background="#f8fafc", foreground="#1e293b")
        self.style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=8)
        self.style.configure("Secondary.TButton", font=("Segoe UI", 10), padding=8)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def _root_frame(self):
        root_frame = ttk.Frame(self.root, style="Root.TFrame", padding=18)
        root_frame.pack(fill="both", expand=True)
        return root_frame

    def _card(self, parent):
        card = ttk.Frame(parent, style="Card.TFrame", padding=18)
        card.pack(fill="both", expand=True)
        return card

    def _result_box(self, parent, title="Result", height=8):
        result_frame = ttk.LabelFrame(parent, text=title, padding=10)
        result_frame.pack(fill="both", expand=True, padx=6, pady=8)
        text = tk.Text(
            result_frame,
            height=height,
            wrap="word",
            bg="#f8fafc",
            fg="#0f172a",
            relief="flat",
            font=("Consolas", 10),
        )
        text.pack(fill="both", expand=True)
        text.config(state="disabled")
        return text

    def _set_result(self, box, text):
        box.config(state="normal")
        box.delete("1.0", tk.END)
        box.insert(tk.END, text.strip() if text else "")
        box.config(state="disabled")

    def _run_action(self, action, *args):
        capture = io.StringIO()
        with redirect_stdout(capture):
            result = action(*args)
        output = capture.getvalue().strip()
        return result, output

    def _require_fields(self, fields):
        for field_name, value in fields:
            if not value.strip():
                messagebox.showerror("Missing Input", f"{field_name} is required.")
                return False
        return True

    def show_login_screen(self):
        self.clear_window()

        root_frame = self._root_frame()
        card = self._card(root_frame)
        ttk.Label(card, text="Secure Password Manager", style="Title.TLabel").pack(pady=(20, 8))
        ttk.Label(
            card,
            text="Manage credentials with encrypted vault storage.",
            style="Subtitle.TLabel",
        ).pack(pady=(0, 22))

        ttk.Label(card, text="Username", style="Label.TLabel").pack(anchor="w")
        username_entry = ttk.Entry(card, width=40)
        username_entry.pack(anchor="w", pady=(4, 14))
        username_entry.focus_set()

        def login():
            user = username_entry.get().strip()
            if not user:
                messagebox.showerror("Error", "Username cannot be empty!")
                return
            self.username = user
            self.show_main_menu()

        ttk.Button(card, text="Login", command=login, style="Primary.TButton").pack(anchor="w", pady=4)

    def show_main_menu(self):
        self.clear_window()

        root_frame = self._root_frame()
        card = self._card(root_frame)
        ttk.Label(card, text=f"Welcome, {self.username}", style="Title.TLabel").pack(pady=(4, 4))
        ttk.Label(card, text="Choose an action", style="Subtitle.TLabel").pack(pady=(0, 14))

        button_frame = ttk.Frame(card, style="Card.TFrame")
        button_frame.pack(fill="both", expand=True)

        buttons = [
            ("Initialize Account", self.show_init_account),
            ("Initialize Vault / Master Password", self.show_initialize_vault),
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
            btn = ttk.Button(button_frame, text=text, command=command, style="Secondary.TButton", width=32)
            btn.pack(pady=6)

    def show_init_account(self):
        self.clear_window()
        root_frame = self._root_frame()
        card = self._card(root_frame)
        ttk.Label(card, text="Initialize Account", style="CardTitle.TLabel").pack(pady=12)

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

    def show_initialize_vault(self):
        self.clear_window()
        root_frame = self._root_frame()
        card = self._card(root_frame)
        priv_path = os.path.join("data", self.username, "private.json")
        if not os.path.exists(priv_path):
            messagebox.showerror(
                "Account not ready",
                "Initialize Account (generate signing keys) first, then initialize the vault.",
            )
            self.show_main_menu()
            return
        ttk.Label(card, text="Initialize Vault", style="CardTitle.TLabel").pack(pady=(4, 8))
        ttk.Label(
            card,
            text="Create your encrypted vault and set the master password once. You will use it for all vault operations.",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(0, 14))

        form_frame = ttk.Frame(card, style="Card.TFrame")
        form_frame.pack(fill="x", padx=6)
        master_pwd = self._form_entry(form_frame, "Master Password", show="*")
        confirm_pwd = self._form_entry(form_frame, "Confirm Master Password", show="*")

        result_text = self._result_box(card, "Result", height=6)

        def submit():
            if not self._require_fields(
                [("Master Password", master_pwd.get()), ("Confirmation", confirm_pwd.get())]
            ):
                return
            if master_pwd.get() != confirm_pwd.get():
                self._set_result(result_text, "Passwords do not match.")
                return
            if vault_is_initialized(self.username):
                self._set_result(result_text, "Vault already exists for this user.")
                return
            try:
                _, output = self._run_action(initialize_vault, self.username, master_pwd.get())
                self._set_result(result_text, output or "Done.")
                master_pwd.delete(0, tk.END)
                confirm_pwd.delete(0, tk.END)
            except Exception as e:
                self._set_result(result_text, f"Error: {str(e)}")

        button_frame = ttk.Frame(card, style="Card.TFrame")
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Create Vault", command=submit, style="Primary.TButton").pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu, style="Secondary.TButton").pack(side="left", padx=5)

    def _form_entry(self, parent, label, show=None):
        ttk.Label(parent, text=label, style="Label.TLabel").pack(anchor="w", pady=(6, 2))
        row = ttk.Frame(parent, style="Card.TFrame")
        row.pack(anchor="w", fill="x")
        entry = ttk.Entry(row, width=48, show=show)
        entry.pack(side="left")
        if show == "*":
            toggle_btn = ttk.Button(
                row,
                text="Show",
                style="Secondary.TButton",
                command=lambda e=entry, b=None: self._toggle_password(e, toggle_btn),
                width=8,
            )
            toggle_btn.pack(side="left", padx=(8, 0))
        return entry

    def _toggle_password(self, entry, button):
        is_hidden = entry.cget("show") == "*"
        entry.config(show="" if is_hidden else "*")
        button.config(text="Hide" if is_hidden else "Show")

    def _normalize_website(self, website):
        return website.strip().lower()

    def show_add_credential(self):
        self.clear_window()
        root_frame = self._root_frame()
        card = self._card(root_frame)
        ttk.Label(card, text="Add Credential", style="CardTitle.TLabel").pack(pady=(4, 12))

        form_frame = ttk.Frame(card, style="Card.TFrame")
        form_frame.pack(fill="x", padx=6)
        master_pwd = self._form_entry(form_frame, "Master Password", show="*")
        website = self._form_entry(form_frame, "Website")
        username = self._form_entry(form_frame, "Username")
        password = self._form_entry(form_frame, "Password", show="*")

        result_text = self._result_box(card, "Result", height=7)

        def save():
            if not self._require_fields(
                [
                    ("Master Password", master_pwd.get()),
                    ("Website", website.get()),
                    ("Username", username.get()),
                    ("Password", password.get()),
                ]
            ):
                return

            try:
                _, output = self._run_action(
                    add_credential,
                    self.username,
                    master_pwd.get(),
                    website.get(),
                    username.get(),
                    password.get(),
                )
                if output:
                    self._set_result(result_text, output)
                else:
                    self._set_result(result_text, "Credential operation completed.")
                if "[+] Credential for" in output:
                    master_pwd.delete(0, tk.END)
                    website.delete(0, tk.END)
                    username.delete(0, tk.END)
                    password.delete(0, tk.END)
            except Exception as e:
                self._set_result(result_text, f"Error: {str(e)}")

        button_frame = ttk.Frame(card, style="Card.TFrame")
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Save", command=save, style="Primary.TButton").pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu, style="Secondary.TButton").pack(side="left", padx=5)

    def show_retrieve_credential(self):
        self.clear_window()
        root_frame = self._root_frame()
        card = self._card(root_frame)
        ttk.Label(card, text="Retrieve Credential", style="CardTitle.TLabel").pack(pady=(4, 12))

        form_frame = ttk.Frame(card, style="Card.TFrame")
        form_frame.pack(fill="x", padx=6)
        master_pwd = self._form_entry(form_frame, "Master Password", show="*")
        website = self._form_entry(form_frame, "Website")

        result_text = self._result_box(card, "Result", height=9)

        def retrieve():
            if not self._require_fields(
                [
                    ("Master Password", master_pwd.get()),
                    ("Website", website.get()),
                ]
            ):
                return

            try:
                if not vault_is_initialized(self.username):
                    self._set_result(
                        result_text,
                        "Vault not initialized. Use 'Initialize Vault / Master Password' first.",
                    )
                    return
                credentials = load_vault(self.username, master_pwd.get())
                if credentials is None:
                    self._set_result(result_text, "Invalid master password or vault could not be read.")
                    return

                selected = None
                normalized_input = self._normalize_website(website.get())
                for entry in credentials:
                    if self._normalize_website(entry["website"]) == normalized_input:
                        selected = entry
                        break

                if selected is None:
                    self._set_result(result_text, f"No credential found for {website.get().strip()}.")
                    return

                result = (
                    f"Website:  {selected['website']}\n"
                    f"Username: {selected['username']}\n"
                    f"Password: {selected['password']}"
                )
                self._set_result(result_text, result)
            except Exception as e:
                self._set_result(result_text, f"Error: {str(e)}")

        button_frame = ttk.Frame(card, style="Card.TFrame")
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Retrieve", command=retrieve, style="Primary.TButton").pack(side="left", padx=5)
        ttk.Button(
            button_frame,
            text="Copy Password",
            command=lambda: self.root.clipboard_append(
                result_text.get("1.0", tk.END).split("Password: ", 1)[-1].strip()
            )
            if "Password:" in result_text.get("1.0", tk.END)
            else None,
            style="Secondary.TButton",
        ).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu, style="Secondary.TButton").pack(side="left", padx=5)

    def show_update_credential(self):
        self.clear_window()
        root_frame = self._root_frame()
        card = self._card(root_frame)
        ttk.Label(card, text="Update Credential", style="CardTitle.TLabel").pack(pady=(4, 12))

        form_frame = ttk.Frame(card, style="Card.TFrame")
        form_frame.pack(fill="x", padx=6)
        master_pwd = self._form_entry(form_frame, "Master Password", show="*")
        website = self._form_entry(form_frame, "Website")
        new_user = self._form_entry(form_frame, "New Username (optional)")
        new_pwd = self._form_entry(form_frame, "New Password (optional)", show="*")

        result_text = self._result_box(card, "Result", height=7)

        def update():
            if not self._require_fields(
                [
                    ("Master Password", master_pwd.get()),
                    ("Website", website.get()),
                ]
            ):
                return
            if not new_user.get().strip() and not new_pwd.get().strip():
                self._set_result(result_text, "Enter at least one field to update.")
                return

            try:
                _, output = self._run_action(
                    update_credential,
                    self.username,
                    master_pwd.get(),
                    website.get(),
                    new_user.get(),
                    new_pwd.get(),
                )
                if output:
                    self._set_result(result_text, output)
                else:
                    self._set_result(result_text, "Credential operation completed.")
            except Exception as e:
                self._set_result(result_text, f"Error: {str(e)}")

        button_frame = ttk.Frame(card, style="Card.TFrame")
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Update", command=update, style="Primary.TButton").pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu, style="Secondary.TButton").pack(side="left", padx=5)

    def show_delete_credential(self):
        self.clear_window()
        root_frame = self._root_frame()
        card = self._card(root_frame)
        ttk.Label(card, text="Delete Credential", style="CardTitle.TLabel").pack(pady=(4, 12))

        form_frame = ttk.Frame(card, style="Card.TFrame")
        form_frame.pack(fill="x", padx=6)
        master_pwd = self._form_entry(form_frame, "Master Password", show="*")
        website = self._form_entry(form_frame, "Website")

        result_text = self._result_box(card, "Result", height=7)

        def delete():
            if messagebox.askyesno("Confirm", "Are you sure you want to delete this credential?"):
                if not self._require_fields(
                    [
                        ("Master Password", master_pwd.get()),
                        ("Website", website.get()),
                    ]
                ):
                    return
                try:
                    _, output = self._run_action(
                        delete_credential, self.username, master_pwd.get(), website.get()
                    )
                    if output:
                        self._set_result(result_text, output)
                    else:
                        self._set_result(result_text, "Credential operation completed.")
                except Exception as e:
                    self._set_result(result_text, f"Error: {str(e)}")

        button_frame = ttk.Frame(card, style="Card.TFrame")
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Delete", command=delete, style="Primary.TButton").pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu, style="Secondary.TButton").pack(side="left", padx=5)

    def show_list_credentials(self):
        self.clear_window()
        root_frame = self._root_frame()
        card = self._card(root_frame)
        ttk.Label(card, text="List Credentials", style="CardTitle.TLabel").pack(pady=(4, 12))

        form_frame = ttk.Frame(card, style="Card.TFrame")
        form_frame.pack(fill="x", padx=6)
        master_pwd = self._form_entry(form_frame, "Master Password", show="*")

        result_text = self._result_box(card, "Credentials", height=14)

        def list_creds():
            if not self._require_fields([("Master Password", master_pwd.get())]):
                return

            try:
                if not vault_is_initialized(self.username):
                    self._set_result(
                        result_text,
                        "Vault not initialized. Use 'Initialize Vault / Master Password' first.",
                    )
                    return
                credentials = load_vault(self.username, master_pwd.get())
                if credentials is None:
                    self._set_result(result_text, "Invalid master password or vault could not be read.")
                    return
                if not credentials:
                    self._set_result(result_text, "Vault is empty.")
                    return

                lines = [
                    f"{'Website':<25} {'Username':<25} {'Password'}",
                    "-" * 72,
                ]
                for entry in credentials:
                    lines.append(
                        f"{entry['website']:<25} {entry['username']:<25} {entry['password']}"
                    )
                self._set_result(result_text, "\n".join(lines))
            except Exception as e:
                self._set_result(result_text, f"Error: {str(e)}")

        button_frame = ttk.Frame(card, style="Card.TFrame")
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Load", command=list_creds, style="Primary.TButton").pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu, style="Secondary.TButton").pack(side="left", padx=5)

    def show_verify_vault(self):
        self.clear_window()
        root_frame = self._root_frame()
        card = self._card(root_frame)
        ttk.Label(card, text="Verify Vault Integrity", style="CardTitle.TLabel").pack(pady=20)

        vault_path = os.path.join("data", self.username, "vault.json")
        if not os.path.exists(vault_path):
            messagebox.showwarning(
                "Warning",
                "No vault found. Use 'Initialize Vault / Master Password' first, then add credentials.",
            )
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
        root_frame = self._root_frame()
        card = self._card(root_frame)
        ttk.Label(card, text="Export Vault", style="CardTitle.TLabel").pack(pady=(4, 12))

        form_frame = ttk.Frame(card, style="Card.TFrame")
        form_frame.pack(fill="x", padx=6)
        master_pwd = self._form_entry(form_frame, "Master Password", show="*")
        recipient = self._form_entry(form_frame, "Recipient Username")
        result_text = self._result_box(card, "Result", height=8)

        def export():
            try:
                if not self._require_fields(
                    [
                        ("Master Password", master_pwd.get()),
                        ("Recipient Username", recipient.get()),
                    ]
                ):
                    return

                recipient_user = recipient.get().strip()
                if not os.path.exists(f"data/Export/{recipient_user}_public.json"):
                    self._set_result(result_text, f"Public key for '{recipient_user}' not found.")
                    return

                result, output = self._run_action(export_vault, self.username, master_pwd.get(), recipient_user)
                success, message = result if isinstance(result, tuple) and len(result) == 2 else (False, "Export failed.")
                if success:
                    self._set_result(result_text, message if not output else f"{message}\n\n{output}")
                else:
                    self._set_result(result_text, message if not output else f"{message}\n\n{output}")
            except Exception as e:
                self._set_result(result_text, f"Error: {str(e)}")

        button_frame = ttk.Frame(card, style="Card.TFrame")
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Export", command=export, style="Primary.TButton").pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu, style="Secondary.TButton").pack(side="left", padx=5)

    def show_import_vault(self):
        self.clear_window()
        root_frame = self._root_frame()
        card = self._card(root_frame)
        ttk.Label(card, text="Import Vault", style="CardTitle.TLabel").pack(pady=(4, 12))

        form_frame = ttk.Frame(card, style="Card.TFrame")
        form_frame.pack(fill="x", padx=6)
        sender = self._form_entry(form_frame, "Sender Username")
        master_pwd = self._form_entry(form_frame, "New Master Password", show="*")
        existing_pwd = self._form_entry(form_frame, "Existing Master Password", show="*")
        result_text = self._result_box(card, "Result", height=8)

        def import_v():
            try:
                if not self._require_fields(
                    [
                        ("Sender Username", sender.get()),
                        ("New Master Password", master_pwd.get()),
                        ("Existing Master Password", existing_pwd.get()),
                    ]
                ):
                    return

                _, output = self._run_action(import_vault, self.username, existing_pwd.get().strip(), master_pwd.get(), sender.get().strip())
                if "imported successfully" in output.lower():
                    self._set_result(result_text, output)
                elif output:
                    self._set_result(result_text, output)
                else:
                    self._set_result(result_text, "Import finished. Check vault status.")
            except Exception as e:
                self._set_result(result_text, f"Error: {str(e)}")

        button_frame = ttk.Frame(card, style="Card.TFrame")
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Import", command=import_v, style="Primary.TButton").pack(side="left", padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_menu, style="Secondary.TButton").pack(side="left", padx=5)


def main():
    root = tk.Tk()
    app = SecurePasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
