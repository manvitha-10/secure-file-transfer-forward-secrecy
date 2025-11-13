"""
Secure File Transfer System with Forward Secrecy
================================================
A cryptographically secure file transfer system implementing:
- Diffie-Hellman key exchange from scratch
- Forward secrecy (new keys per session)
- Chunk-based file encryption
- Transfer protocol with verification
"""

import os
import hashlib
import json
import socket
import threading
from pathlib import Path
from typing import Tuple, Optional
import secrets


class DiffieHellman:
    """
    Diffie-Hellman Key Exchange Implementation
    Uses safe prime for enhanced security
    """
    
    # Safe prime (2048-bit) - p where (p-1)/2 is also prime
    # In production, use larger primes (3072 or 4096 bit)
    PRIME = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    
    GENERATOR = 2  # Standard generator
    
    def __init__(self):
        """Initialize DH with random private key"""
        self.private_key = secrets.randbelow(self.PRIME - 2) + 1
        self.public_key = pow(self.GENERATOR, self.private_key, self.PRIME)
        self.shared_secret: Optional[int] = None
    
    def generate_public_key(self) -> int:
        """Return public key for transmission"""
        return self.public_key
    
    def compute_shared_secret(self, other_public_key: int) -> bytes:
        """
        Compute shared secret from other party's public key
        Returns 32-byte key suitable for encryption
        """
        self.shared_secret = pow(other_public_key, self.private_key, self.PRIME)
        # Use SHA-256 to derive fixed-size key
        return hashlib.sha256(str(self.shared_secret).encode()).digest()


class SecureFileEncryptor:
    """
    Chunk-based file encryption with rotating key stream
    Implements a stream cipher using key derivation
    """
    
    CHUNK_SIZE = 64 * 1024  # 64 KB chunks
    
    def __init__(self, key: bytes):
        """Initialize with shared secret key"""
        self.key = key
    
    def _generate_keystream(self, length: int, nonce: bytes) -> bytes:
        """
        Generate keystream using SHA-256 in counter mode
        More secure than simple XOR
        """
        keystream = b''
        counter = 0
        
        while len(keystream) < length:
            # Derive key block: SHA256(key || nonce || counter)
            block = hashlib.sha256(
                self.key + nonce + counter.to_bytes(8, 'big')
            ).digest()
            keystream += block
            counter += 1
        
        return keystream[:length]
    
    def encrypt_chunk(self, data: bytes, chunk_index: int) -> Tuple[bytes, bytes]:
        """
        Encrypt a single chunk with unique nonce
        Returns (encrypted_data, nonce)
        """
        nonce = secrets.token_bytes(16)
        keystream = self._generate_keystream(len(data), nonce)
        
        # XOR encryption
        encrypted = bytes(a ^ b for a, b in zip(data, keystream))
        return encrypted, nonce
    
    def decrypt_chunk(self, encrypted_data: bytes, nonce: bytes) -> bytes:
        """Decrypt a chunk using its nonce"""
        keystream = self._generate_keystream(len(encrypted_data), nonce)
        return bytes(a ^ b for a, b in zip(encrypted_data, keystream))
    
    def encrypt_file(self, filepath: str) -> list:
        """
        Encrypt file in chunks
        Returns list of (encrypted_chunk, nonce, checksum) tuples
        """
        chunks = []
        
        with open(filepath, 'rb') as f:
            chunk_index = 0
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                
                encrypted, nonce = self.encrypt_chunk(chunk, chunk_index)
                checksum = hashlib.sha256(chunk).hexdigest()
                
                chunks.append({
                    'data': encrypted.hex(),
                    'nonce': nonce.hex(),
                    'checksum': checksum,
                    'size': len(chunk)
                })
                chunk_index += 1
        
        return chunks
    
    def decrypt_file(self, chunks: list, output_path: str) -> bool:
        """
        Decrypt chunks and write to file
        Returns True if all checksums valid
        """
        with open(output_path, 'wb') as f:
            for chunk_info in chunks:
                encrypted = bytes.fromhex(chunk_info['data'])
                nonce = bytes.fromhex(chunk_info['nonce'])
                
                decrypted = self.decrypt_chunk(encrypted, nonce)
                
                # Verify checksum
                checksum = hashlib.sha256(decrypted).hexdigest()
                if checksum != chunk_info['checksum']:
                    return False
                
                f.write(decrypted)
        
        return True


class SecureFileTransferProtocol:
    """
    Transfer protocol implementing handshake and file transfer
    """
    
    def __init__(self, host: str = 'localhost', port: int = 5555):
        self.host = host
        self.port = port
        self.dh: Optional[DiffieHellman] = None
        self.encryptor: Optional[SecureFileEncryptor] = None
    
    def _send_message(self, sock: socket.socket, message: dict):
        """Send JSON message with length prefix"""
        data = json.dumps(message).encode()
        length = len(data).to_bytes(4, 'big')
        sock.sendall(length + data)
    
    def _receive_message(self, sock: socket.socket) -> dict:
        """Receive JSON message with length prefix"""
        length_bytes = sock.recv(4)
        if not length_bytes:
            return {}
        
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        
        while len(data) < length:
            chunk = sock.recv(min(length - len(data), 4096))
            if not chunk:
                break
            data += chunk
        
        return json.loads(data.decode())
    
    def send_file(self, filepath: str, receiver_host: str = None):
        """
        Send file to receiver (client mode)
        """
        if receiver_host:
            self.host = receiver_host
        
        print(f"[SENDER] Connecting to {self.host}:{self.port}")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.host, self.port))
            
            # Step 1: DH Handshake
            print("[SENDER] Initiating DH key exchange...")
            self.dh = DiffieHellman()
            
            self._send_message(sock, {
                'type': 'handshake',
                'public_key': self.dh.generate_public_key()
            })
            
            response = self._receive_message(sock)
            if response['type'] != 'handshake_ack':
                print("[ERROR] Handshake failed")
                return
            
            # Compute shared secret
            shared_key = self.dh.compute_shared_secret(response['public_key'])
            self.encryptor = SecureFileEncryptor(shared_key)
            print(f"[SENDER] Shared key established: {shared_key[:8].hex()}...")
            
            # Step 2: Send file metadata
            filename = Path(filepath).name
            filesize = os.path.getsize(filepath)
            
            print(f"[SENDER] Encrypting {filename} ({filesize} bytes)...")
            encrypted_chunks = self.encryptor.encrypt_file(filepath)
            
            self._send_message(sock, {
                'type': 'file_transfer',
                'filename': filename,
                'filesize': filesize,
                'chunks': len(encrypted_chunks)
            })
            
            # Step 3: Send encrypted chunks
            for i, chunk in enumerate(encrypted_chunks):
                self._send_message(sock, {
                    'type': 'chunk',
                    'index': i,
                    'data': chunk
                })
                print(f"[SENDER] Sent chunk {i+1}/{len(encrypted_chunks)}")
            
            # Step 4: Wait for verification
            result = self._receive_message(sock)
            if result['type'] == 'transfer_complete':
                print(f"[SENDER] ✓ Transfer successful! Checksum verified.")
            else:
                print(f"[ERROR] Transfer failed: {result.get('error')}")
    
    def receive_file(self, output_dir: str = './received'):
        """
        Receive file (server mode)
        """
        os.makedirs(output_dir, exist_ok=True)
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(1)
            
            print(f"[RECEIVER] Listening on {self.host}:{self.port}")
            
            conn, addr = server.accept()
            with conn:
                print(f"[RECEIVER] Connected to {addr}")
                
                # Step 1: DH Handshake
                handshake = self._receive_message(conn)
                if handshake['type'] != 'handshake':
                    return
                
                print("[RECEIVER] Performing DH key exchange...")
                self.dh = DiffieHellman()
                
                self._send_message(conn, {
                    'type': 'handshake_ack',
                    'public_key': self.dh.generate_public_key()
                })
                
                # Compute shared secret
                shared_key = self.dh.compute_shared_secret(handshake['public_key'])
                self.encryptor = SecureFileEncryptor(shared_key)
                print(f"[RECEIVER] Shared key established: {shared_key[:8].hex()}...")
                
                # Step 2: Receive file metadata
                metadata = self._receive_message(conn)
                if metadata['type'] != 'file_transfer':
                    return
                
                filename = metadata['filename']
                total_chunks = metadata['chunks']
                print(f"[RECEIVER] Receiving {filename} ({total_chunks} chunks)...")
                
                # Step 3: Receive chunks
                chunks = []
                for i in range(total_chunks):
                    chunk_msg = self._receive_message(conn)
                    chunks.append(chunk_msg['data'])
                    print(f"[RECEIVER] Received chunk {i+1}/{total_chunks}")
                
                # Step 4: Decrypt and verify
                output_path = os.path.join(output_dir, filename)
                print(f"[RECEIVER] Decrypting to {output_path}...")
                
                success = self.encryptor.decrypt_file(chunks, output_path)
                
                if success:
                    self._send_message(conn, {'type': 'transfer_complete'})
                    print(f"[RECEIVER] ✓ File saved successfully!")
                else:
                    self._send_message(conn, {
                        'type': 'transfer_failed',
                        'error': 'Checksum verification failed'
                    })
                    print("[ERROR] Checksum verification failed!")


def demo_usage():
    """
    Demonstration of the secure file transfer system
    """
    print("=" * 60)
    print("Secure File Transfer System - Demo")
    print("=" * 60)
    
    # Create a test file
    test_file = "test_document.txt"
    with open(test_file, 'w') as f:
        f.write("This is a confidential document.\n" * 100)
        f.write("It contains sensitive information that must be encrypted.\n")
    
    print(f"\n1. Created test file: {test_file}")
    
    # Start receiver in separate thread
    protocol_receiver = SecureFileTransferProtocol()
    receiver_thread = threading.Thread(
        target=protocol_receiver.receive_file,
        args=('./received',)
    )
    receiver_thread.start()
    
    # Give receiver time to start
    import time
    time.sleep(1)
    
    # Send file
    print("\n2. Initiating secure transfer...")
    protocol_sender = SecureFileTransferProtocol()
    protocol_sender.send_file(test_file)
    
    # Wait for completion
    receiver_thread.join()
    
    print("\n" + "=" * 60)
    print("Demo completed! Check './received' directory for decrypted file")
    print("=" * 60)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) == 1:
        # Run demo
        demo_usage()
    elif sys.argv[1] == 'send' and len(sys.argv) >= 3:
        # python secure_transfer.py send <file> [host]
        filepath = sys.argv[2]
        host = sys.argv[3] if len(sys.argv) > 3 else 'localhost'
        
        protocol = SecureFileTransferProtocol()
        protocol.send_file(filepath, host)
    elif sys.argv[1] == 'receive':
        # python secure_transfer.py receive [output_dir]
        output_dir = sys.argv[2] if len(sys.argv) > 2 else './received'
        
        protocol = SecureFileTransferProtocol()
        protocol.receive_file(output_dir)
    else:
        print("Usage:")
        print("  Demo:    python secure_transfer.py")
        print("  Send:    python secure_transfer.py send <file> [host]")
        print("  Receive: python secure_transfer.py receive [output_dir]")
