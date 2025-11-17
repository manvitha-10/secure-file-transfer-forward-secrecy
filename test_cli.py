"""
Command-Line Test Script for Secure File Transfer
Demonstrates the system without GUI
"""

import os
import sys
from crypto_utils import DiffieHellman, FileEncryptor, bytes_to_hex
from transfer_protocol import SecureFileTransfer


def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def print_step(number, text):
    """Print formatted step"""
    print(f"\n[STEP {number}] {text}")
    print("-" * 70)


def test_diffie_hellman():
    """Test Diffie-Hellman key exchange"""
    print_header("TESTING DIFFIE-HELLMAN KEY EXCHANGE")

    print_step(1, "Creating two DH instances (Sender and Receiver)")
    sender_dh = DiffieHellman()
    receiver_dh = DiffieHellman()

    print(f"Sender private key: {hex(sender_dh.private_key)[:50]}...")
    print(f"Receiver private key: {hex(receiver_dh.private_key)[:50]}...")

    print_step(2, "Generating and exchanging public keys")
    sender_public = sender_dh.get_public_key()
    receiver_public = receiver_dh.get_public_key()

    print(f"Sender public key: {hex(sender_public)[:50]}...")
    print(f"Receiver public key: {hex(receiver_public)[:50]}...")

    print_step(3, "Computing shared secrets")
    sender_secret = sender_dh.compute_shared_secret(receiver_public)
    receiver_secret = receiver_dh.compute_shared_secret(sender_public)

    print(f"Sender's computed secret: {sender_secret.hex()[:50]}...")
    print(f"Receiver's computed secret: {receiver_secret.hex()[:50]}...")

    print_step(4, "Verifying secrets match")
    if sender_secret == receiver_secret:
        print("✅ SUCCESS: Both parties have the same shared secret!")
        print(f"Shared secret: {sender_secret.hex()}")
        return True
    else:
        print("❌ FAILED: Secrets don't match!")
        return False


def test_file_encryption():
    """Test file encryption and decryption"""
    print_header("TESTING FILE ENCRYPTION")

    # Create a test key
    test_key = b"0" * 32  # 32-byte key

    print_step(1, "Creating FileEncryptor with test key")
    encryptor = FileEncryptor(test_key)
    print(f"Key: {test_key.hex()}")
    print(f"Chunk size: {encryptor.chunk_size} bytes")

    print_step(2, "Encrypting test file")
    test_file = "test_file.txt"
    if not os.path.exists(test_file):
        print(f"❌ Test file '{test_file}' not found!")
        return False

    encrypted_chunks, original_checksum = encryptor.encrypt_file_chunks(test_file)
    print(f"✅ File encrypted into {len(encrypted_chunks)} chunks")
    print(f"Original checksum: {bytes_to_hex(original_checksum)}")

    print_step(3, "Decrypting file")
    output_file = "test_output.txt"
    computed_checksum = encryptor.decrypt_file_chunks(encrypted_chunks, output_file)
    print(f"Computed checksum: {bytes_to_hex(computed_checksum)}")

    print_step(4, "Verifying checksum")
    if original_checksum == computed_checksum:
        print("✅ SUCCESS: Checksums match - file integrity verified!")
        return True
    else:
        print("❌ FAILED: Checksum mismatch!")
        return False


def test_full_transfer():
    """Test complete file transfer with protocol"""
    print_header("TESTING COMPLETE SECURE FILE TRANSFER")

    # Initialize transfer protocol
    transfer = SecureFileTransfer()

    print_step(1, "Creating transfer sessions")
    sender_session = transfer.create_session()
    receiver_session = transfer.create_session()
    print(f"Sender session: {sender_session.session_id}")
    print(f"Receiver session: {receiver_session.session_id}")

    print_step(2, "Performing handshake (DH key exchange)")
    sender_public = sender_session.dh.get_public_key()
    receiver_public = receiver_session.dh.get_public_key()

    print(f"Exchanging public keys...")
    print(f"  Sender -> Receiver: {hex(sender_public)[:50]}...")
    print(f"  Receiver -> Sender: {hex(receiver_public)[:50]}...")

    sender_response = transfer.sender_handshake(sender_session, receiver_public)
    receiver_response = transfer.receiver_handshake(receiver_session, sender_public)

    print(f"Sender handshake: {sender_response['status']}")
    print(f"Receiver handshake: {receiver_response['status']}")

    # Verify shared secrets match
    if sender_session.shared_key == receiver_session.shared_key:
        print("✅ Shared keys match!")
    else:
        print("❌ Shared keys don't match!")
        return False

    print_step(3, "Encrypting and preparing file")
    test_file = "test_file.txt"

    def progress_callback(message, progress):
        print(f"  [{progress}%] {message}")

    encrypt_result = transfer.encrypt_and_prepare_file(
        sender_session,
        test_file,
        progress_callback
    )

    print(f"✅ File encrypted:")
    print(f"  Filename: {encrypt_result['filename']}")
    print(f"  Size: {encrypt_result['filesize']} bytes")
    print(f"  Chunks: {encrypt_result['num_chunks']}")
    print(f"  Checksum: {encrypt_result['checksum']}")

    print_step(4, "Transferring file")
    transfer_result = transfer.transfer_file(
        sender_session,
        receiver_session,
        progress_callback
    )

    print(f"✅ Transfer complete:")
    print(f"  Status: {transfer_result['status']}")
    print(f"  Chunks transferred: {transfer_result['chunks_transferred']}")

    print_step(5, "Decrypting and verifying file")
    output_file = "received_test_file.txt"
    verify_result = transfer.decrypt_and_verify_file(
        receiver_session,
        output_file,
        progress_callback
    )

    print(f"\nVerification result:")
    print(f"  Status: {verify_result['status']}")
    print(f"  Checksum valid: {verify_result['checksum_valid']}")
    print(f"  Expected: {verify_result['expected_checksum']}")
    print(f"  Computed: {verify_result['computed_checksum']}")
    print(f"  Output: {verify_result['output_path']}")

    if verify_result['checksum_valid']:
        print("\n✅ SUCCESS: File transferred and verified successfully!")

        # Compare original and received files
        print_step(6, "Comparing original and received files")
        with open(test_file, 'rb') as f1:
            original = f1.read()
        with open(output_file, 'rb') as f2:
            received = f2.read()

        if original == received:
            print("✅ Files are identical!")
        else:
            print("❌ Files differ!")
            return False

        return True
    else:
        print("\n❌ FAILED: Checksum verification failed!")
        return False


def test_forward_secrecy():
    """Test forward secrecy by creating multiple sessions"""
    print_header("TESTING FORWARD SECRECY")

    print("Forward secrecy ensures that each file transfer uses completely")
    print("different encryption keys. Even if one session is compromised,")
    print("previous sessions remain secure.")
    print()

    transfer = SecureFileTransfer()
    sessions_keys = []

    for i in range(3):
        print_step(i + 1, f"Creating session {i + 1}")

        sender = transfer.create_session()
        receiver = transfer.create_session()

        # Perform handshake
        sender_pub = sender.dh.get_public_key()
        receiver_pub = receiver.dh.get_public_key()

        transfer.sender_handshake(sender, receiver_pub)
        transfer.receiver_handshake(receiver, sender_pub)

        # Store the shared key
        sessions_keys.append(sender.shared_key)

        print(f"Session {i + 1} key: {sender.shared_key.hex()[:50]}...")

    print_step(4, "Verifying all keys are different")
    all_different = len(set([key.hex() for key in sessions_keys])) == len(sessions_keys)

    if all_different:
        print("✅ SUCCESS: All session keys are unique!")
        print("This demonstrates forward secrecy - each session uses different keys.")
        return True
    else:
        print("❌ FAILED: Some session keys are the same!")
        return False


def main():
    """Run all tests"""
    print("\n")
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║     SECURE FILE TRANSFER - COMMAND LINE TEST SUITE                ║")
    print("║     Demonstrating Forward Secrecy & Encrypted File Transfer       ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")

    tests = [
        ("Diffie-Hellman Key Exchange", test_diffie_hellman),
        ("File Encryption/Decryption", test_file_encryption),
        ("Complete Secure Transfer", test_full_transfer),
        ("Forward Secrecy", test_forward_secrecy),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ ERROR in {test_name}: {str(e)}")
            results.append((test_name, False))

    # Print summary
    print_header("TEST SUMMARY")
    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")

    print(f"\nResults: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All tests passed! The system is working correctly.")
        print("\nYou can now run the GUI with: python gui.py")
    else:
        print("\n⚠️  Some tests failed. Please check the output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
