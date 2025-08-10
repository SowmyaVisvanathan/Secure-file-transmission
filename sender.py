import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import StringVar, IntVar
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
import os

def generate_key(password, salt, key_length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_aes_key(aes_key, public_key_path):
    try:
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_aes_key
    except Exception as e:
        print(f"Error encrypting AES key: {e}")
        raise

def encrypt_file(file_path, password, public_key_path, algorithm, key_length):
    try:
        salt = os.urandom(16)
        key = generate_key(password, salt, key_length)
        iv = os.urandom(16)
        encrypted_key = encrypt_aes_key(key, public_key_path)

        with open(file_path, 'rb') as f:
            data = f.read()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        if algorithm == 'AES':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        else:
            raise ValueError("Unsupported algorithm selected.")

        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        with open(file_path + '.enc', 'wb') as f:
            f.write(salt + iv + encrypted_key + encrypted_data)

        print(f"Encryption complete. Salt: {salt.hex()}, IV: {iv.hex()}")
        messagebox.showinfo("Success", f"File encrypted successfully: {file_path}.enc")
    except Exception as e:
        print(f"Error encrypting file: {e}")
        messagebox.showerror("Error", f"Error encrypting file: {e}")

def browse_file(entry):
    file_path = filedialog.askopenfilename()
    if file_path:
        entry.set(file_path)

def browse_key(entry):
    key_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
    if key_path:
        entry.set(key_path)

def on_encrypt():
    file_path = file_path_var.get()
    password = password_var.get()
    public_key_path = public_key_path_var.get()
    algorithm = algorithm_var.get()
    key_size_value = key_size_var.get()
    
    if not all([file_path, password, public_key_path, algorithm]):
        messagebox.showerror("Error", "Please fill in all required fields.")
        return

    try:
        key_length = 32 if key_size_value == 256 else (24 if key_size_value == 192 else 16)
        encrypt_file(file_path, password, public_key_path, algorithm, key_length)
    except Exception as e:
        print(f"Error during encryption: {e}")
        messagebox.showerror("Error", "Encryption failed.")

def main():
    root = tk.Tk()
    root.title("File Encryption")

    global file_path_var, password_var, public_key_path_var, algorithm_var, key_size_var

    file_path_var = StringVar()
    password_var = StringVar()
    public_key_path_var = StringVar()
    algorithm_var = StringVar(value='AES')
    key_size_var = IntVar(value=256)

    tk.Label(root, text="File Path:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
    tk.Entry(root, textvariable=file_path_var, width=50).grid(row=0, column=1, padx=10, pady=10)
    tk.Button(root, text="Browse", command=lambda: browse_file(file_path_var)).grid(row=0, column=2, padx=10, pady=10)

    tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
    tk.Entry(root, textvariable=password_var, show="*", width=50).grid(row=1, column=1, padx=10, pady=10)

    tk.Label(root, text="Public Key Path (Encrypt):").grid(row=2, column=0, padx=10, pady=10, sticky="e")
    tk.Entry(root, textvariable=public_key_path_var, width=50).grid(row=2, column=1, padx=10, pady=10)
    tk.Button(root, text="Browse", command=lambda: browse_key(public_key_path_var)).grid(row=2, column=2, padx=10, pady=10)

    tk.Label(root, text="Algorithm:").grid(row=3, column=0, padx=10, pady=10, sticky="e")
    tk.OptionMenu(root, algorithm_var, 'AES').grid(row=3, column=1, padx=10, pady=10)

    tk.Label(root, text="Key Size:").grid(row=4, column=0, padx=10, pady=10, sticky="e")
    tk.Radiobutton(root, text="128-bit", variable=key_size_var, value=128).grid(row=4, column=1, padx=10, pady=10, sticky="w")
    tk.Radiobutton(root, text="192-bit", variable=key_size_var, value=192).grid(row=4, column=1, padx=10, pady=10)
    tk.Radiobutton(root, text="256-bit", variable=key_size_var, value=256).grid(row=4, column=1, padx=10, pady=10, sticky="e")

    tk.Button(root, text="Encrypt", command=on_encrypt).grid(row=5, column=0, padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()

