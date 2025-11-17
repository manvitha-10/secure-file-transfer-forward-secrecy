"""
Cryptographic Utilities for Secure File Transfer
Implements Diffie-Hellman Key Exchange and File Encryption from Scratch
"""

import random
import hashlib
import os
from typing import Tuple


class DiffieHellman:
    """
    Diffie-Hellman Key Exchange Implementation from Scratch
    Provides forward secrecy by generating new keys for each session
    """

    def __init__(self):
        # Using a safe 2048-bit prime (Sophie Germain prime)
        # In production, use larger primes. This is for educational purposes.
        self.prime = int(
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
        # Generator (commonly used value)
        self.generator = 2
        # Private key (random)
        self.private_key = self._generate_private_key()
        # Public key (g^private mod p)
        self.public_key = self._generate_public_key()
        # Shared secret (computed after key exchange)
        self.shared_secret = None

    def _generate_private_key(self) -> int:
        """Generate a random private key"""
        # Private key should be in range [2, prime-2]
        return random.randint(2, self.prime - 2)

    def _generate_public_key(self) -> int:
        """Generate public key: g^private_key mod prime"""
        return pow(self.generator, self.private_key, self.prime)

    def get_public_key(self) -> int:
        """Return the public key to share with the other party"""
        return self.public_key

    def compute_shared_secret(self, other_public_key: int) -> bytes:
        """
        Compute the shared secret using the other party's public key
        shared_secret = other_public_key^private_key mod prime
        """
        self.shared_secret = pow(other_public_key, self.private_key, self.prime)
        # Derive a 256-bit key from the shared secret using SHA-256
        return hashlib.sha256(str(self.shared_secret).encode()).digest()

    def reset(self):
        """Reset keys for a new session (forward secrecy)"""
        self.private_key = self._generate_private_key()
        self.public_key = self._generate_public_key()
        self.shared_secret = None


class FileEncryptor:
    """
    Chunk-based File Encryption using XOR with a rotating key
    Simple but effective encryption for educational purposes
    """

    def __init__(self, key: bytes, chunk_size: int = 4096):
        """
        Initialize encryptor with a key

        Args:
            key: 32-byte encryption key from DH exchange
            chunk_size: Size of each chunk in bytes
        """
        self.key = key
        self.chunk_size = chunk_size
        # Expand key using SHA-256 for rotation
        self.expanded_key = self._expand_key(key, 1024)

    def _expand_key(self, key: bytes, size: int) -> bytes:
        """Expand the key to a larger size for rotation"""
        expanded = key
        while len(expanded) < size:
            expanded += hashlib.sha256(expanded).digest()
        return expanded[:size]

    def _xor_encrypt_chunk(self, chunk: bytes, key_offset: int) -> bytes:
        """
        XOR encrypt a chunk with a rotating key

        Args:
            chunk: Data chunk to encrypt
            key_offset: Offset in the expanded key for rotation
        """
        encrypted = bytearray()
        key_len = len(self.expanded_key)

        for i, byte in enumerate(chunk):
            # Rotate through expanded key
            key_byte = self.expanded_key[(key_offset + i) % key_len]
            encrypted.append(byte ^ key_byte)

        return bytes(encrypted)

    def encrypt_file_chunks(self, filepath: str) -> Tuple[list, bytes]:
        """
        Encrypt a file in chunks

        Args:
            filepath: Path to the file to encrypt

        Returns:
            Tuple of (list of encrypted chunks, checksum)
        """
        encrypted_chunks = []
        checksum = hashlib.sha256()

        with open(filepath, 'rb') as f:
            chunk_index = 0
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break

                # Update checksum with original data
                checksum.update(chunk)

                # Encrypt chunk with rotating key
                key_offset = (chunk_index * self.chunk_size) % len(self.expanded_key)
                encrypted_chunk = self._xor_encrypt_chunk(chunk, key_offset)
                encrypted_chunks.append(encrypted_chunk)

                chunk_index += 1

        return encrypted_chunks, checksum.digest()

    def decrypt_file_chunks(self, encrypted_chunks: list, output_path: str) -> bytes:
        """
        Decrypt file chunks and write to output

        Args:
            encrypted_chunks: List of encrypted chunks
            output_path: Path to write decrypted file

        Returns:
            Checksum of decrypted data
        """
        checksum = hashlib.sha256()

        with open(output_path, 'wb') as f:
            for chunk_index, encrypted_chunk in enumerate(encrypted_chunks):
                # Decrypt chunk (XOR is symmetric)
                key_offset = (chunk_index * self.chunk_size) % len(self.expanded_key)
                decrypted_chunk = self._xor_encrypt_chunk(encrypted_chunk, key_offset)

                # Update checksum
                checksum.update(decrypted_chunk)

                # Write to file
                f.write(decrypted_chunk)

        return checksum.digest()


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string for display"""
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_str)
