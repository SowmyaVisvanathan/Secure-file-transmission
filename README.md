# Secure-file-transmission using AES and RSA

### **1. Overview**

The **Secure File Transmission System** is designed to send files between two or more users over a network while ensuring **confidentiality**, **integrity**, and **authenticity** of the data.
It prevents **unauthorized access**, **data tampering**, and **eavesdropping** during transmission.

---

### **2. Problem Statement**

Traditional file transfer methods (FTP, email attachments) have security weaknesses:

* Files are often sent **unencrypted** → vulnerable to interception.
* No way to verify **file integrity** after transfer.
* No built-in **authentication** of sender and receiver.

---

### **3. Solution Approach**

1. **Encryption** – Files are encrypted before sending.
2. **Secure Key Exchange** – Using **RSA** for exchanging the encryption key.
3. **Integrity Verification** – Using **SHA-256** hashing to check if file was modified in transit.
4. **Authentication** – Public-key cryptography to confirm sender and receiver identity.

---

1. **Sender Side**

   * Selects file to send.
   * Generates a random **AES symmetric key**.
   * Encrypts the file using **AES-256**.
   * Encrypts AES key using **receiver’s RSA public key**.
   * Sends encrypted file + encrypted key + file hash to receiver.

2. **Receiver Side**

   * Decrypts AES key using **their RSA private key**.
   * Decrypts file using the decrypted AES key.
   * Generates SHA-256 hash of received file and compares with sender’s hash.
   * If matched → confirms file integrity.

---

### **5. Technologies Used**

| Component             | Technology                                          |
| --------------------- | --------------------------------------------------- |
| Language              | Python (or Java, depending on your implementation)  |
| Symmetric Encryption  | AES-256                                             |
| Asymmetric Encryption | RSA-2048                                            |
| Integrity Check       | SHA-256                                             |
| Libraries Used        | `cryptography`, `pycryptodome`, `socket`, `hashlib` |

---

### **6. Security Features**

* **End-to-End Encryption** – No plaintext leaves sender’s machine.
* **Man-in-the-Middle Protection** – RSA ensures keys are exchanged securely.
* **Tamper Detection** – SHA-256 hash comparison.
* **Authentication** – Only registered users with valid public keys can send/receive.

---

### **7. Example Use Case**

* A company wants to share **confidential salary slips** with remote employees.
* The **HR server** runs the receiver script.
* Employees run the sender script to transmit encrypted files.
* Only the HR server can decrypt and verify them.

---

### **9. Advantages**

* Strong encryption ensures **confidentiality**.
* Hash verification ensures **integrity**.
* RSA authentication prevents **impersonation**.
* Works over **any network**.

---

### **10. Future Improvements**

* Add **GUI** for easier use.
* Implement **multi-file transfer** in a single session.
* Use **TLS/SSL** for an additional security layer.
* Add **digital signatures** for non-repudiation.

---

If you want, I can also write a **shorter, recruiter-friendly version** of this explanation that you can **paste in your GitHub README under "About the Project"** so it’s crisp but still impressive.

Do you want me to prepare that compact version next?

## Sender end (encryption):
<img width="1107" height="607" alt="image" src="https://github.com/user-attachments/assets/5d3e96f6-999e-4431-97ea-83344f193368" />
## Receiver end (decryption):
<img width="939" height="642" alt="image" src="https://github.com/user-attachments/assets/d84187e3-281a-4009-b664-62789a4ea353" />
