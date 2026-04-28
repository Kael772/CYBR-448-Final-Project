import tkinter as tk
from tkinter import filedialog, ttk
import os
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class AESAppUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES File Tool")
        self.root.geometry("700x600")


        self.aes_mode = tk.StringVar(value="128")

        mode_frame = ttk.LabelFrame(root, text="AES Mode")
        mode_frame.pack(fill="x", padx=10, pady=5)

        ttk.Radiobutton(mode_frame, text="AES-128", variable=self.aes_mode, value="128").pack(side="left", padx=10)
        ttk.Radiobutton(mode_frame, text="AES-192", variable=self.aes_mode, value="192").pack(side="left", padx=10)
        ttk.Radiobutton(mode_frame, text="AES-256", variable=self.aes_mode, value="256").pack(side="left", padx=10)


        key_frame = ttk.LabelFrame(root, text="Key Options")
        key_frame.pack(fill="x", padx=10, pady=5)

        row = ttk.Frame(key_frame)
        row.pack(fill="x")

        self.key_mode = tk.StringVar(value="generate")

        ttk.Radiobutton(row, text="Generate Key", variable=self.key_mode, value="generate",
                        command=self.toggle_password).pack(side="left", padx=10)

        ttk.Radiobutton(row, text="Use Password", variable=self.key_mode, value="password",
                        command=self.toggle_password).pack(side="left", padx=10)

        self.password_entry = ttk.Entry(row, state="disabled", width=30)
        self.password_entry.pack(side="left", padx=10)


        key_row = ttk.Frame(key_frame)
        key_row.pack(fill="x", pady=5)

        self.key_output = ttk.Entry(key_row, width=60)
        self.key_output.pack(side="left", padx=10)
        self.key_output.insert(0, "Generated key will appear here")

        ttk.Button(key_row, text="Generate Key", command=self.generate_key_ui).pack(side="left", padx=5)
        ttk.Button(key_row, text="Copy Key", command=self.copy_key).pack(side="left", padx=5)


        file_frame = ttk.LabelFrame(root, text="Files")
        file_frame.pack(fill="both", expand=True, padx=10, pady=5)

        btns = ttk.Frame(file_frame)
        btns.pack(fill="x")

        ttk.Button(btns, text="Add Files", command=self.add_files).pack(side="left", padx=5)
        ttk.Button(btns, text="Add Folder", command=self.add_folder).pack(side="left", padx=5)
        ttk.Button(btns, text="Remove Selected", command=self.remove_selected).pack(side="left", padx=5)
        ttk.Button(btns, text="Remove All", command=self.remove_all).pack(side="left", padx=5)

        self.file_list = tk.Listbox(file_frame, height=12, selectmode=tk.EXTENDED)
        self.file_list.pack(fill="both", expand=True, padx=5, pady=5)


        action = ttk.Frame(root)
        action.pack(fill="x", padx=10, pady=10)

        ttk.Button(action, text="Encrypt", command=self.encrypt_ui).pack(side="left", padx=10)
        ttk.Button(action, text="Decrypt", command=self.decrypt_ui).pack(side="left", padx=10)

        decrypt_frame = ttk.LabelFrame(root, text="Decrypt Input")
        decrypt_frame.pack(fill="x", padx=10, pady=5)

        self.decrypt_mode = tk.StringVar(value="password")

        ttk.Radiobutton(decrypt_frame, text="Password", variable=self.decrypt_mode,
                        value="password", command=self.toggle_decrypt_input).pack(side="left", padx=10)

        ttk.Radiobutton(decrypt_frame, text="Raw Key", variable=self.decrypt_mode,
                        value="key", command=self.toggle_decrypt_input).pack(side="left", padx=10)

        self.decrypt_entry = ttk.Entry(decrypt_frame, width=50)
        self.decrypt_entry.pack(side="left", padx=10)

        self.key_status = ttk.Label(decrypt_frame, text="")
        self.key_status.pack(side="left", padx=10)


        status_frame = ttk.LabelFrame(root, text="Status Log")
        status_frame.pack(fill="both", expand=False, padx=10, pady=5)

        self.status_box = tk.Text(status_frame, height=8, wrap="word", state="disabled")
        self.status_box.pack(fill="both", expand=True)


    def set_status(self, msg, level="INFO"):
        self.status_box.config(state="normal")

        prefix = {
            "INFO": "ℹ️ ",
            "SUCCESS": "",
            "ERROR": ""
        }.get(level, "ℹ️ ")

        self.status_box.insert(tk.END, prefix + msg + "\n")
        self.status_box.see(tk.END)

        lines = int(self.status_box.index('end-1c').split('.')[0])
        if lines > 50:
            self.status_box.delete("1.0", "10.0")

        self.status_box.config(state="disabled")


    def toggle_password(self):
        if self.key_mode.get() == "password":
            self.password_entry.config(state="normal")
        else:
            self.password_entry.delete(0, tk.END)
            self.password_entry.config(state="disabled")

    def toggle_decrypt_input(self):
        self.decrypt_entry.delete(0, tk.END)

    def add_files(self):
        file_added = False
        paths = filedialog.askopenfilenames()
        for p in paths:
            if p not in self.file_list.get(0, tk.END):
                self.file_list.insert(tk.END, p)
                file_added = True

        if file_added:
            self.set_status("Files added")

    def add_folder(self):
        folder = filedialog.askdirectory()
        if not folder:
            return

        for root_dir, _, files in os.walk(folder):
            for file in files:
                full = os.path.join(root_dir, file)
                if full not in self.file_list.get(0, tk.END):
                    self.file_list.insert(tk.END, full)

        self.set_status("Folder added")

    def remove_selected(self):
        selected = list(self.file_list.curselection())
        for i in reversed(selected):
            self.file_list.delete(i)

        self.set_status("Selected removed")

    def remove_all(self):
        self.file_list.delete(0, tk.END)
        self.set_status("All files cleared")

    def encrypt_file(self, file_path, password):
        if not os.path.isfile(file_path):
            self.set_status(f"Skipping folder: {file_path}")
            return

        with open(file_path, "rb") as file:
            data = file.read()

        key_len = int(self.aes_mode.get()) // 8
        salt = get_random_bytes(16)

        key = PBKDF2(
            password.encode(),
            salt,
            dkLen=key_len,
            count=200000
        )

        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        with open(file_path + ".enc", "wb") as file:
            file.write(salt + cipher.nonce + tag + ciphertext)

        self.set_status(f"Encrypted: {file_path}")

    def decrypt_file(self, file_path, password):
        try:
            with open(file_path, "rb") as file:
                raw = file.read()

            salt = raw[:16]
            nonce = raw[16:32]
            tag = raw[32:48]
            ciphertext = raw[48:]

            key_len = int(self.aes_mode.get()) // 8

            key = PBKDF2(
                password.encode(),
                salt,
                dkLen=key_len,
                count=200000
            )

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            with open(file_path.replace(".enc", ""), "wb") as file:
                file.write(plaintext)

            self.set_status(f"Decrypted: {file_path}")

        except Exception:
            self.set_status(f"Failed: {file_path}", "ERROR")


    def generate_key_ui(self):
        key = get_random_bytes(int(self.aes_mode.get()) // 8)

        self.generated_key = key
        hex_key = key.hex()

        self.key_output.delete(0, tk.END)
        self.key_output.insert(0, hex_key)

        self.set_status("Key generated", "SUCCESS")

    def copy_key(self):
        key = self.key_output.get()

        if not key or "appear" in key:
            self.set_status("No key to copy", "ERROR")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(key)
        self.set_status("Key copied", "SUCCESS")

    def validate_hex_key(self, key_hex):
        try:
            key = bytes.fromhex(key_hex.strip().replace(" ", ""))
        except ValueError:
            return None

        expected = int(self.aes_mode.get()) // 8
        if len(key) != expected:
            return None

        return key

    def get_encryption_key(self):
        mode = self.key_mode.get()

        if mode == "generate":
            key = self.validate_hex_key(self.key_output.get())
            if not key:
                self.set_status("Invalid generated key", "ERROR")
            return key

        elif mode == "password":
            pw = self.password_entry.get().strip()
            if not pw:
                self.set_status("Password required", "ERROR")
                return None

            return pw.encode()

        return None

    def encrypt_ui(self):
        if not self.file_list.get(0):
            self.set_status("No files selected", "ERROR")
            return

        mode = self.key_mode.get()

        if mode == "password":
            password = self.password_entry.get()
        else:
            password = self.key_output.get()

        if not password:
            self.set_status("No password/key provided", "ERROR")
            return

        for file in self.file_list.get(0, tk.END):
            self.encrypt_file(file, password)

    def decrypt_ui(self):
        if not self.file_list.get(0):
            self.set_status("No files selected", "ERROR")
            return

        mode = self.decrypt_mode.get()

        if mode == "password":
            password = self.decrypt_entry.get()
        else:
            password = self.decrypt_entry.get()

        if not password:
            self.set_status("No password/key provided", "ERROR")
            return

        for file in self.file_list.get(0, tk.END):
            self.decrypt_file(file, password)


if __name__ == "__main__":
    root = tk.Tk()
    app = AESAppUI(root)
    root.mainloop()