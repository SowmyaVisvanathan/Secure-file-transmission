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
import os


def decrypt_aes_key(encrypted_aes_key, private_key_path):
    try:
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key
    except Exception as e:
        print(f"Error decrypting AES key: {e}")
        raise


def decrypt_file(file_path, password, private_key_path, algorithm, key_length, output_file_path):
    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            encrypted_key = f.read(256)  # Assumes 2048-bit RSA key
            encrypted_data = f.read()

        key = decrypt_aes_key(encrypted_key, private_key_path)

        if algorithm == 'AES':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        else:
            raise ValueError("Unsupported algorithm selected.")

        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        with open(output_file_path, 'wb') as f:
            f.write(data)

        print(f"Decryption complete. File saved as: {output_file_path}")
        messagebox.showinfo("Success", f"File decrypted successfully: {output_file_path}")
    except Exception as e:
        print(f"Error decrypting file: {e}")
        messagebox.showerror("Error", f"Error decrypting file: {e}")


def browse_file(entry):
    file_path = filedialog.askopenfilename()
    if file_path:
        entry.set(file_path)


def browse_key(entry):
    key_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
    if key_path:
        entry.set(key_path)


def browse_output_file(entry):
    file_path = filedialog.asksaveasfilename(defaultextension="", filetypes=[("All Files", "*.*")])
    if file_path:
        entry.set(file_path)


def on_decrypt():
    file_path = file_path_var.get()
    password = password_var.get()
    private_key_path = private_key_path_var.get()
    output_file_path = output_file_path_var.get()
    algorithm = algorithm_var.get()
    key_size_value = key_size_var.get()

    if not all([file_path, password, private_key_path, output_file_path, algorithm]):
        messagebox.showerror("Error", "Please fill in all required fields.")
        return

    try:
        key_length = 32 if key_size_value == 256 else (24 if key_size_value == 192 else 16)
        decrypt_file(file_path, password, private_key_path, algorithm, key_length, output_file_path)
    except Exception as e:
        print(f"Error during decryption: {e}")
        messagebox.showerror("Error", "Decryption failed.")


def main():
    root = tk.Tk()
    root.title("File Decryption")

    global file_path_var, password_var, private_key_path_var, output_file_path_var, algorithm_var, key_size_var

    file_path_var = StringVar()
    password_var = StringVar()
    private_key_path_var = StringVar()
    output_file_path_var = StringVar()
    algorithm_var = StringVar(value='AES')
    key_size_var = IntVar(value=256)

    tk.Label(root, text="File Path:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
    tk.Entry(root, textvariable=file_path_var, width=50).grid(row=0, column=1, padx=10, pady=10)
    tk.Button(root, text="Browse", command=lambda: browse_file(file_path_var)).grid(row=0, column=2, padx=10, pady=10)

    tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
    tk.Entry(root, textvariable=password_var, show="*", width=50).grid(row=1, column=1, padx=10, pady=10)

    tk.Label(root, text="Private Key Path (Decrypt):").grid(row=2, column=0, padx=10, pady=10, sticky="e")
    tk.Entry(root, textvariable=private_key_path_var, width=50).grid(row=2, column=1, padx=10, pady=10)
    tk.Button(root, text="Browse", command=lambda: browse_key(private_key_path_var)).grid(row=2, column=2, padx=10, pady=10)

    tk.Label(root, text="Output File Path:").grid(row=3, column=0, padx=10, pady=10, sticky="e")
    tk.Entry(root, textvariable=output_file_path_var, width=50).grid(row=3, column=1, padx=10, pady=10)
    tk.Button(root, text="Browse", command=lambda: browse_output_file(output_file_path_var)).grid(row=3, column=2, padx=10, pady=10)

    tk.Label(root, text="Algorithm:").grid(row=4, column=0, padx=10, pady=10, sticky="e")
    tk.OptionMenu(root, algorithm_var, 'AES').grid(row=4, column=1, padx=10, pady=10)

    tk.Label(root, text="Key Size:").grid(row=5, column=0, padx=10, pady=10, sticky="e")
    tk.Radiobutton(root, text="128-bit", variable=key_size_var, value=128).grid(row=5, column=1, padx=10, pady=10, sticky="w")
    tk.Radiobutton(root, text="192-bit", variable=key_size_var, value=192).grid(row=5, column=1, padx=10, pady=10)
    tk.Radiobutton(root, text="256-bit", variable=key_size_var, value=256).grid(row=5, column=1, padx=10, pady=10, sticky="e")

    tk.Button(root, text="Decrypt", command=on_decrypt).grid(row=6, column=0, padx=10, pady=10)

    root.mainloop()


if __name__ == "__main__":
    main()
