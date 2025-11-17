"""
Secure File Transfer Protocol
Implements handshake, transfer, and verification with forward secrecy
"""

import os
import time
from typing import Callable, Optional
from crypto_utils import DiffieHellman, FileEncryptor, bytes_to_hex


class TransferSession:
    """Represents a single file transfer session"""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.dh = DiffieHellman()  # New DH instance for THIS session (forward secrecy)
        self.shared_key = None
        self.encryptor = None
        self.filename = None
        self.filesize = 0
        self.checksum = None
        self.chunks = []
        self.status = "INITIALIZED"
        self.created_at = time.time()

    def reset_keys(self):
        """Reset DH keys for a new transfer (forward secrecy)"""
        self.dh.reset()
        self.shared_key = None
        self.encryptor = None


class SecureFileTransfer:
    """
    Secure File Transfer Protocol with Forward Secrecy

    Protocol Steps:
    1. HANDSHAKE: Exchange DH public keys
    2. KEY_DERIVATION: Compute shared secret
    3. TRANSFER: Send encrypted file chunks
    4. VERIFY: Validate checksum
    """

    def __init__(self):
        self.sessions = {}
        self.session_counter = 0

    def create_session(self) -> TransferSession:
        """Create a new transfer session with fresh DH keys"""
        self.session_counter += 1
        session_id = f"SESSION_{self.session_counter}_{int(time.time())}"
        session = TransferSession(session_id)
        self.sessions[session_id] = session
        return session

    def sender_handshake(self, session: TransferSession, receiver_public_key: int) -> dict:
        """
        Sender initiates handshake with receiver

        Args:
            session: Transfer session
            receiver_public_key: Receiver's DH public key

        Returns:
            Handshake response with sender's public key
        """
        # Compute shared secret using receiver's public key
        session.shared_key = session.dh.compute_shared_secret(receiver_public_key)
        session.encryptor = FileEncryptor(session.shared_key)
        session.status = "HANDSHAKE_COMPLETE"

        return {
            "session_id": session.session_id,
            "sender_public_key": session.dh.get_public_key(),
            "status": "HANDSHAKE_OK",
            "timestamp": time.time()
        }

    def receiver_handshake(self, session: TransferSession, sender_public_key: int) -> dict:
        """
        Receiver completes handshake with sender

        Args:
            session: Transfer session
            sender_public_key: Sender's DH public key

        Returns:
            Handshake confirmation
        """
        # Compute shared secret using sender's public key
        session.shared_key = session.dh.compute_shared_secret(sender_public_key)
        session.encryptor = FileEncryptor(session.shared_key)
        session.status = "HANDSHAKE_COMPLETE"

        return {
            "session_id": session.session_id,
            "status": "HANDSHAKE_OK",
            "timestamp": time.time()
        }

    def encrypt_and_prepare_file(
        self,
        session: TransferSession,
        filepath: str,
        progress_callback: Optional[Callable] = None
    ) -> dict:
        """
        Encrypt file and prepare for transfer

        Args:
            session: Transfer session
            filepath: Path to file to encrypt
            progress_callback: Optional callback for progress updates

        Returns:
            Transfer package with encrypted chunks
        """
        if session.status != "HANDSHAKE_COMPLETE":
            raise Exception("Handshake must be completed before file transfer")

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        session.filename = os.path.basename(filepath)
        session.filesize = os.path.getsize(filepath)
        session.status = "ENCRYPTING"

        if progress_callback:
            progress_callback("Encrypting file...", 0)

        # Encrypt file in chunks
        encrypted_chunks, checksum = session.encryptor.encrypt_file_chunks(filepath)
        session.chunks = encrypted_chunks
        session.checksum = checksum
        session.status = "READY_TO_TRANSFER"

        if progress_callback:
            progress_callback("Encryption complete", 100)

        return {
            "session_id": session.session_id,
            "filename": session.filename,
            "filesize": session.filesize,
            "num_chunks": len(encrypted_chunks),
            "checksum": bytes_to_hex(checksum),
            "status": "ENCRYPTED"
        }

    def transfer_file(
        self,
        sender_session: TransferSession,
        receiver_session: TransferSession,
        progress_callback: Optional[Callable] = None
    ) -> dict:
        """
        Simulate file transfer from sender to receiver

        Args:
            sender_session: Sender's session
            receiver_session: Receiver's session
            progress_callback: Optional callback for progress updates

        Returns:
            Transfer result
        """
        if sender_session.status != "READY_TO_TRANSFER":
            raise Exception("Sender not ready to transfer")

        if receiver_session.status != "HANDSHAKE_COMPLETE":
            raise Exception("Receiver handshake not complete")

        sender_session.status = "TRANSFERRING"
        receiver_session.status = "RECEIVING"

        total_chunks = len(sender_session.chunks)

        # Simulate chunk-by-chunk transfer
        for i, chunk in enumerate(sender_session.chunks):
            # Transfer chunk (in real network scenario, this would be sent over socket)
            receiver_session.chunks.append(chunk)

            # Progress update
            progress = int(((i + 1) / total_chunks) * 100)
            if progress_callback:
                progress_callback(f"Transferring chunk {i+1}/{total_chunks}", progress)

            # Simulate network delay
            time.sleep(0.01)

        # Transfer metadata
        receiver_session.filename = sender_session.filename
        receiver_session.filesize = sender_session.filesize
        receiver_session.checksum = sender_session.checksum

        sender_session.status = "TRANSFER_COMPLETE"
        receiver_session.status = "TRANSFER_COMPLETE"

        return {
            "session_id": receiver_session.session_id,
            "status": "TRANSFER_COMPLETE",
            "chunks_transferred": total_chunks,
            "timestamp": time.time()
        }

    def decrypt_and_verify_file(
        self,
        session: TransferSession,
        output_path: str,
        progress_callback: Optional[Callable] = None
    ) -> dict:
        """
        Decrypt received file and verify checksum

        Args:
            session: Receiver's session
            output_path: Path to save decrypted file
            progress_callback: Optional callback for progress updates

        Returns:
            Verification result
        """
        if session.status != "TRANSFER_COMPLETE":
            raise Exception("Transfer must be complete before decryption")

        session.status = "DECRYPTING"

        if progress_callback:
            progress_callback("Decrypting file...", 0)

        # Decrypt chunks
        computed_checksum = session.encryptor.decrypt_file_chunks(
            session.chunks,
            output_path
        )

        if progress_callback:
            progress_callback("Decryption complete", 100)

        # Verify checksum
        checksum_valid = computed_checksum == session.checksum

        session.status = "COMPLETE" if checksum_valid else "VERIFICATION_FAILED"

        return {
            "session_id": session.session_id,
            "status": session.status,
            "checksum_valid": checksum_valid,
            "expected_checksum": bytes_to_hex(session.checksum),
            "computed_checksum": bytes_to_hex(computed_checksum),
            "output_path": output_path,
            "timestamp": time.time()
        }

    def get_session_info(self, session: TransferSession) -> dict:
        """Get detailed session information"""
        return {
            "session_id": session.session_id,
            "status": session.status,
            "filename": session.filename,
            "filesize": session.filesize,
            "num_chunks": len(session.chunks),
            "checksum": bytes_to_hex(session.checksum) if session.checksum else None,
            "has_shared_key": session.shared_key is not None,
            "created_at": session.created_at
        }
