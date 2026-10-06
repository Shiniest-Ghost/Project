import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptographyTool:
    def __init__(self, master):
        self.master = master
        self.master.title("Cryptography Tool")
        self.master.minsize(560, 640)

        self.private_key = None
        self.public_key = None

        self._build_menu()
        self._build_ui()
        self._on_algo_change()
        self.apply_theme()   

    # ---------- UI ----------
    def _build_menu(self):
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Generate RSA Key Pair", command=self.generate_rsa_key_pair)
        file_menu.add_separator()
        file_menu.add_command(label="Save Public Key...", command=self.save_public_key)
        file_menu.add_command(label="Save Private Key...", command=self.save_private_key)
        file_menu.add_command(label="Load Public Key...", command=self.load_public_key)
        file_menu.add_command(label="Load Private Key...", command=self.load_private_key)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)

    def apply_theme(self):
        bg = "#000000"         # window background (pure black)
        fg = "#9c9797"         # text color
        field_bg = "#121212"   # input/output boxes
        accent = "#2b2b2b"     # buttons
        hover = "#3d3d3d"      # button hover

        self.master.configure(bg=bg)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TLabelframe", background=bg, bordercolor=accent)
        style.configure("TLabelframe.Label", background=bg, foreground=fg)
        style.configure("TButton", background=accent, foreground=fg, bordercolor=accent)
        style.map("TButton", background=[("active", hover)])
        style.configure("TEntry", fieldbackground=field_bg, foreground=fg, insertcolor=fg)
        style.configure("TCombobox", fieldbackground=field_bg, background=accent,
                        foreground=fg, arrowcolor=fg)
        style.map("TCombobox",
                fieldbackground=[("readonly", field_bg)],
                foreground=[("readonly", fg)],
                selectbackground=[("readonly", field_bg)],
                selectforeground=[("readonly", fg)])

        # Dropdown list of the combobox
        self.master.option_add("*TCombobox*Listbox.background", field_bg)
        self.master.option_add("*TCombobox*Listbox.foreground", fg)
        self.master.option_add("*TCombobox*Listbox.selectBackground", hover)
        self.master.option_add("*TCombobox*Listbox.selectForeground", fg)

    # Plain tk.Text widgets aren't affected by ttk styles
        for box in (self.text_input, self.text_output):
            box.configure(bg=field_bg, fg=fg, insertbackground=fg,
                        selectbackground=hover, relief="flat",
                        highlightthickness=1, highlightbackground=accent,
                        highlightcolor=accent)

    def _build_ui(self):
        frame = ttk.Frame(self.master, padding=10)
        frame.pack(fill="both", expand=True)

        # Algorithm selector
        top = ttk.Frame(frame)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="Algorithm:").pack(side="left")
        self.encryption_type = tk.StringVar(value="AES")
        self.dropdown = ttk.Combobox(
            top, textvariable=self.encryption_type,
            values=["AES", "RSA"], state="readonly", width=8,
        )
        self.dropdown.pack(side="left", padx=8)
        self.dropdown.bind("<<ComboboxSelected>>", self._on_algo_change)

        # AES key row
        self.aes_frame = ttk.LabelFrame(frame, text="AES-256 key (hex)", padding=6)
        self.aes_frame.pack(fill="x", pady=(0, 8))
        self.aes_key_var = tk.StringVar()
        ttk.Entry(self.aes_frame, textvariable=self.aes_key_var).pack(
            side="left", fill="x", expand=True, padx=(0, 6)
        )
        ttk.Button(self.aes_frame, text="Generate", command=self.generate_aes_key).pack(side="left")

        # RSA status
        self.rsa_status = tk.StringVar(value="No RSA keys loaded")
        self.rsa_label = ttk.Label(frame, textvariable=self.rsa_status, foreground="gray")

        # Input
        ttk.Label(frame, text="Input:").pack(anchor="w")
        self.text_input = tk.Text(frame, wrap="word", height=10, width=60)
        self.text_input.pack(fill="both", expand=True, pady=(0, 8))

        # Buttons
        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(0, 8))
        ttk.Button(btns, text="Encrypt", command=self.encrypt).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Decrypt", command=self.decrypt).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Copy Output", command=self.copy_output).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Clear", command=self.clear_all).pack(side="left")

        # Output
        ttk.Label(frame, text="Output:").pack(anchor="w")
        self.text_output = tk.Text(frame, wrap="word", height=10, width=60)
        self.text_output.pack(fill="both", expand=True)

        self._on_algo_change()
        self.apply_theme()   # must come after text_input and text_output exist

        self._on_algo_change()

    def _on_algo_change(self, _event=None):
        if self.encryption_type.get() == "AES":
            self.rsa_label.pack_forget()
            self.aes_frame.pack(fill="x", pady=(0, 8), after=self.dropdown.master)
        else:
            self.aes_frame.pack_forget()
            self.rsa_label.pack(anchor="w", pady=(0, 8), after=self.dropdown.master)

    # ---------- Helpers ----------
    def get_input(self):
        return self.text_input.get("1.0", tk.END).strip()

    def set_output(self, text):
        self.text_output.delete("1.0", tk.END)
        self.text_output.insert(tk.END, text)

    def copy_output(self):
        text = self.text_output.get("1.0", tk.END).strip()
        if text:
            self.master.clipboard_clear()
            self.master.clipboard_append(text)

    def clear_all(self):
        self.text_input.delete("1.0", tk.END)
        self.text_output.delete("1.0", tk.END)

    def _update_rsa_status(self):
        if self.private_key:
            self.rsa_status.set("RSA key pair loaded (can encrypt and decrypt)")
        elif self.public_key:
            self.rsa_status.set("RSA public key loaded (encrypt only)")
        else:
            self.rsa_status.set("No RSA keys loaded")

    @staticmethod
    def _oaep():
        return asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )

    # ---------- RSA keys ----------
    def generate_rsa_key_pair(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self._update_rsa_status()
        messagebox.showinfo("Success", "RSA key pair generated.")

    def save_public_key(self):
        if not self.public_key:
            messagebox.showerror("Error", "No public key to save.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pem", filetypes=[("PEM files", "*.pem")]
        )
        if not path:
            return
        pem = self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(path, "wb") as f:
            f.write(pem)

    def save_private_key(self):
        if not self.private_key:
            messagebox.showerror("Error", "No private key to save.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pem", filetypes=[("PEM files", "*.pem")]
        )
        if not path:
            return
        # NOTE: saved without a password. Keep this file private.
        pem = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with open(path, "wb") as f:
            f.write(pem)

    def load_public_key(self):
        path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                self.public_key = serialization.load_pem_public_key(f.read())
            self.private_key = None
            self._update_rsa_status()
        except Exception as e:
            messagebox.showerror("Error", f"Could not load public key:\n{e}")

    def load_private_key(self):
        path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            self.public_key = self.private_key.public_key()
            self._update_rsa_status()
        except Exception as e:
            messagebox.showerror("Error", f"Could not load private key:\n{e}")

    # ---------- AES key ----------
    def generate_aes_key(self):
        self.aes_key_var.set(AESGCM.generate_key(bit_length=256).hex())

    def _get_aes_key(self):
        try:
            key = bytes.fromhex(self.aes_key_var.get().strip())
        except ValueError:
            raise ValueError("AES key must be hexadecimal.")
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 32, 48, or 64 hex characters (128/192/256-bit).")
        return key

    # ---------- Encrypt / Decrypt ----------
    def encrypt(self):
        text = self.get_input()
        if not text:
            messagebox.showwarning("Empty", "Enter some text first.")
            return
        data = text.encode("utf-8")

        try:
            if self.encryption_type.get() == "AES":
                key = self._get_aes_key()
                nonce = os.urandom(12)
                ct = AESGCM(key).encrypt(nonce, data, None)
                self.set_output(base64.b64encode(nonce + ct).decode())
            else:
                if not self.public_key:
                    messagebox.showerror("Error", "Generate or load an RSA key first.")
                    return
                ct = self.public_key.encrypt(data, self._oaep())
                self.set_output(base64.b64encode(ct).decode())
        except ValueError as e:
            messagebox.showerror("Encryption failed", str(e))
        except Exception as e:
            messagebox.showerror("Encryption failed", str(e))

    def decrypt(self):
        text = self.get_input()
        if not text:
            messagebox.showwarning("Empty", "Paste the encrypted text into the input box.")
            return

        try:
            raw = base64.b64decode(text)

            if self.encryption_type.get() == "AES":
                key = self._get_aes_key()
                nonce, ct = raw[:12], raw[12:]
                pt = AESGCM(key).decrypt(nonce, ct, None)
            else:
                if not self.private_key:
                    messagebox.showerror("Error", "A private key is needed to decrypt.")
                    return
                pt = self.private_key.decrypt(raw, self._oaep())

            self.set_output(pt.decode("utf-8"))
        except InvalidTag:
            messagebox.showerror("Decryption failed", "Wrong key or the data was modified.")
        except Exception as e:
            messagebox.showerror("Decryption failed", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptographyTool(root)
    root.mainloop()