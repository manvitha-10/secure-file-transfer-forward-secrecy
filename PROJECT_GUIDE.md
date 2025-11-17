# Project Guide: Secure File Transfer with Forward Secrecy

## Quick Start

### Running the Application

**GUI Mode (Recommended for demonstration):**
```bash
python3 gui.py
```

**CLI Test Mode (For verification):**
```bash
python3 test_cli.py
```

## Project Overview

This project implements a **secure file transfer system** with the following key features:

### Core Cryptographic Features
1. **Diffie-Hellman Key Exchange** (implemented from scratch)
   - 2048-bit prime modulus
   - Generates shared secret without transmitting the secret key
   - Each party contributes to the final encryption key

2. **Forward Secrecy**
   - NEW keys generated for EACH file transfer
   - Past communications remain secure even if current keys are compromised
   - Each session is cryptographically independent

3. **Chunk-Based Encryption**
   - Files split into 4KB chunks
   - Each chunk encrypted with rotating XOR key
   - Efficient for large files

4. **Integrity Verification**
   - SHA-256 checksums ensure file hasn't been tampered with
   - Automatic verification after transfer

## How to Use the GUI

### Step-by-Step Demo Instructions

1. **Launch the Application**
   ```bash
   python3 gui.py
   ```

2. **Select a File (Sender Side - Left Panel)**
   - Click "Choose File"
   - Select `test_file.txt` (or any file you want to transfer)
   - File info will display

3. **Initiate Handshake**
   - Click "Initiate Handshake" button
   - This performs Diffie-Hellman key exchange
   - Both sender and receiver panels will show:
     - Session ID
     - Status: "HANDSHAKE_COMPLETE"
     - Public keys
     - Shared encryption key

4. **Encrypt & Transfer File**
   - Click "Encrypt & Send File" on sender side
   - Watch the progress bars:
     - Sender: Shows encryption progress
     - Receiver: Shows transfer and decryption progress
   - Transfer log shows detailed steps

5. **Verify Results**
   - Receiver panel shows verification status
   - Check the "Verification" section for checksum validation
   - Received file saved as `received_[filename]` in output directory

6. **Test Forward Secrecy**
   - Click "Reset (New Session)"
   - Transfer another file
   - Notice completely different keys are generated!

## Project Structure

```
Test/
├── crypto_utils.py           # Core cryptography (DH, encryption)
│   ├── DiffieHellman class   # Key exchange implementation
│   └── FileEncryptor class   # Chunk-based encryption
│
├── transfer_protocol.py      # Transfer logic
│   ├── TransferSession       # Session management
│   └── SecureFileTransfer    # Protocol implementation
│
├── gui.py                    # GUI application (MAIN ENTRY)
│   └── SecureFileTransferGUI # Tkinter interface
│
├── test_cli.py               # Command-line testing
├── test_file.txt             # Sample test file
├── README.md                 # Documentation
└── PROJECT_GUIDE.md          # This file
```

## Understanding the Code

### 1. Diffie-Hellman Implementation (crypto_utils.py:8-71)

```python
class DiffieHellman:
    def __init__(self):
        self.prime = [large safe prime]      # Public
        self.generator = 2                   # Public
        self.private_key = random(2, p-2)    # SECRET - never shared
        self.public_key = g^private mod p    # Shared

    def compute_shared_secret(self, other_public):
        # Compute: other_public^private_key mod prime
        # Both parties compute the SAME value!
        shared_secret = pow(other_public, self.private_key, self.prime)
        return SHA256(shared_secret)  # 256-bit encryption key
```

**How DH Works:**
```
Alice                           Bob
-----                           ---
a = random()                    b = random()
A = g^a mod p                   B = g^b mod p

        A ------------>
        <---------- B

s = B^a mod p                   s = A^b mod p
  = (g^b)^a mod p                 = (g^a)^b mod p
  = g^(ab) mod p                  = g^(ab) mod p

Both have the same secret 's'!
```

### 2. File Encryption (crypto_utils.py:74-156)

```python
class FileEncryptor:
    def encrypt_file_chunks(self, filepath):
        chunks = []
        checksum = SHA256()

        for each 4KB chunk in file:
            checksum.update(chunk)              # Calculate checksum
            encrypted = chunk XOR rotating_key   # Encrypt
            chunks.append(encrypted)

        return chunks, checksum
```

**XOR Encryption:**
```
Original:  01101010
Key:       11001100
          ---------- XOR
Encrypted: 10100110

Decryption (XOR is symmetric):
Encrypted: 10100110
Key:       11001100
          ---------- XOR
Original:  01101010
```

### 3. Transfer Protocol (transfer_protocol.py)

**Protocol Flow:**
```
PHASE 1: HANDSHAKE
Sender                          Receiver
------                          --------
Create DH keys                  Create DH keys
Send public key ------------>
                    <---------- Send public key
Compute shared secret           Compute shared secret
[Both have same encryption key]

PHASE 2: ENCRYPT
Read file → Split into chunks → Encrypt each chunk → Generate checksum

PHASE 3: TRANSFER
Send encrypted chunks -------->
Send metadata --------------->
                                Store encrypted chunks

PHASE 4: DECRYPT & VERIFY
                                Decrypt chunks
                                Compute checksum
                                Verify checksum matches
                                Save file
```

## Security Analysis

### What This Demonstrates

✅ **Public Key Cryptography**: DH key exchange allows two parties to establish a shared secret over an insecure channel

✅ **Forward Secrecy**: Each file transfer uses completely new keys - if today's key is compromised, yesterday's transfers remain secure

✅ **Integrity Protection**: SHA-256 checksums detect any tampering or corruption

✅ **No Pre-Shared Secrets**: No need to exchange keys beforehand

### Educational Limitations

⚠️ **XOR Cipher**: Used for simplicity - production should use AES-256-GCM

⚠️ **No Authentication**: Doesn't verify who you're talking to (vulnerable to MITM)

⚠️ **No Network Security**: Local simulation - real network needs TLS

⚠️ **No Key Verification**: Should implement key fingerprint verification

### Production Improvements

For real-world use, you would add:
- **AES-256-GCM** instead of XOR (authenticated encryption)
- **Digital Signatures** (RSA/ECDSA) for authentication
- **Certificate Validation** to prevent MITM attacks
- **Perfect Forward Secrecy** with ephemeral ECDH keys
- **TLS 1.3** for network transport
- **Key Fingerprint Display** for user verification

## Demo Script for Presentation

### 5-Minute Demo

**[1 min] Introduction**
"This project demonstrates secure file transfer with forward secrecy. It implements Diffie-Hellman key exchange from scratch and shows how two parties can securely exchange files without ever sharing the encryption key."

**[2 min] Show the Code**
1. Open `crypto_utils.py` - show DH implementation
2. Explain: "Here's the DH key exchange - each party generates a private key and computes a public key. They exchange public keys and both compute the same shared secret!"

**[2 min] Demo the GUI**
1. Launch `python3 gui.py`
2. Select test file
3. Click "Initiate Handshake" - explain key exchange happening
4. Click "Encrypt & Send" - show encryption, transfer, verification
5. Show received file is identical to original

**[1 min] Show Forward Secrecy**
1. Click "Reset (New Session)"
2. Transfer another file
3. Show logs: "Notice the keys are completely different! That's forward secrecy - each transfer is independent."

### 10-Minute Deep Dive

1. **Explain DH Math (2 min)**
   - Draw the DH exchange on whiteboard
   - Show `g^a mod p` and `g^b mod p`
   - Explain discrete logarithm problem

2. **Run CLI Tests (3 min)**
   ```bash
   python3 test_cli.py
   ```
   - Show all 4 tests passing
   - Explain each test

3. **Code Walkthrough (3 min)**
   - DH implementation
   - Encryption logic
   - Protocol flow

4. **Demo GUI (2 min)**
   - Full transfer demonstration
   - Show logs and verification

## Test Results

All tests pass successfully:
```
✅ PASS - Diffie-Hellman Key Exchange
✅ PASS - File Encryption/Decryption
✅ PASS - Complete Secure Transfer
✅ PASS - Forward Secrecy

Results: 4/4 tests passed
```

## Common Questions

**Q: Why use XOR instead of AES?**
A: This is an educational project to demonstrate concepts. XOR makes it easy to understand the encryption process. Production systems should use AES-256-GCM.

**Q: Is this secure for real use?**
A: No - it's designed for learning. It lacks authentication, uses simplified encryption, and doesn't implement network security protocols like TLS.

**Q: What is forward secrecy?**
A: Forward secrecy means that if your encryption key is compromised today, past communications remain secure because each session used different keys. This project generates new DH keys for every file transfer.

**Q: How big are the files it can handle?**
A: Any size! Files are processed in 4KB chunks, so memory usage is constant regardless of file size.

**Q: Can I modify this for my project?**
A: Absolutely! The code is well-commented and modular. You can swap out the XOR cipher for AES, add network support, implement authentication, etc.

## Further Learning

To enhance this project, try:
1. Replace XOR with **AES-256-GCM** using `cryptography` library
2. Add **digital signatures** for authentication
3. Implement **real network transfer** using sockets
4. Add **ECDH** (Elliptic Curve DH) for smaller keys
5. Implement **key fingerprint verification** (like Signal)
6. Add **progress persistence** (resume interrupted transfers)
7. Implement **multi-file transfer**

## Resources

- Diffie-Hellman: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
- Forward Secrecy: https://en.wikipedia.org/wiki/Forward_secrecy
- Signal Protocol: https://signal.org/docs/
- Cryptography Best Practices: https://www.owasp.org/

## Troubleshooting

**GUI doesn't launch:**
- Ensure you have Tkinter installed: `python3 -m tkinter`
- On Linux: `sudo apt-get install python3-tk`

**Tests fail:**
- Check Python version: `python3 --version` (need 3.7+)
- Ensure all files are in the same directory

**File not found errors:**
- Make sure `test_file.txt` exists
- Check file permissions

---

**Project completed successfully!** All components working and tested.

Good luck with your presentation! 🎓🔒
