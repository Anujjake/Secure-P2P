#!/usr/bin/env python3
"""
Example usage of the encryption module
Demonstrates X25519 key exchange, AES-256-GCM encryption, and forward secrecy
"""

import asyncio
from p2p_securemsg.encryption import (
    generate_keypair, derive_shared_key, encrypt_message, decrypt_message,
    secure_delete_keypair, generate_session_keypair, create_secure_session,
    encrypt_session_message, decrypt_session_message, encode_public_key,
    decode_public_key
)


def basic_encryption_example():
    """Basic encryption example between two parties"""
    print("=== Basic Encryption Example ===")
    
    # Generate key pairs for Alice and Bob
    print("Generating key pairs...")
    alice_keypair = generate_keypair()
    bob_keypair = generate_keypair()
    
    print(f"Alice's public key: {encode_public_key(alice_keypair.public_key)[:32]}...")
    print(f"Bob's public key: {encode_public_key(bob_keypair.public_key)[:32]}...")
    
    # Derive shared secret
    print("\nDeriving shared secret...")
    alice_shared = derive_shared_key(alice_keypair.private_key, bob_keypair.public_key)
    bob_shared = derive_shared_key(bob_keypair.private_key, alice_keypair.public_key)
    
    # Verify both parties have the same shared secret
    assert alice_shared == bob_shared
    print(f"Shared secret derived: {alice_shared.hex()[:32]}...")
    
    # Encrypt and decrypt a message
    message = b"Hello, this is a secret message!"
    print(f"\nOriginal message: {message.decode()}")
    
    # Alice encrypts message
    encrypted = encrypt_message(alice_shared, message)
    print(f"Encrypted message: {encrypted.ciphertext.hex()[:32]}...")
    
    # Bob decrypts message
    decrypted = decrypt_message(bob_shared, encrypted)
    print(f"Decrypted message: {decrypted.decode()}")
    
    # Securely delete keys
    secure_delete_keypair(alice_keypair)
    secure_delete_keypair(bob_keypair)
    print("\nKeys securely deleted from memory")


def forward_secrecy_example():
    """Example demonstrating forward secrecy with ephemeral keys"""
    print("\n=== Forward Secrecy Example ===")
    
    # Simulate a conversation with multiple sessions
    print("Starting secure conversation with forward secrecy...")
    
    # Session 1
    print("\n--- Session 1 ---")
    alice_session1, alice_pub1 = generate_session_keypair()
    bob_session1, bob_pub1 = generate_session_keypair()
    
    # Exchange public keys and create session
    session1_key = create_secure_session(alice_session1.private_key, decode_public_key(bob_pub1))
    
    message1 = b"First message in session 1"
    ciphertext1, nonce1, tag1 = encrypt_session_message(session1_key, message1)
    decrypted1 = decrypt_session_message(session1_key, ciphertext1, nonce1, tag1)
    print(f"Session 1 message: {decrypted1.decode()}")
    
    # Securely delete session 1 keys
    secure_delete_keypair(alice_session1)
    secure_delete_keypair(bob_session1)
    
    # Session 2 (new ephemeral keys)
    print("\n--- Session 2 ---")
    alice_session2, alice_pub2 = generate_session_keypair()
    bob_session2, bob_pub2 = generate_session_keypair()
    
    # Exchange public keys and create new session
    session2_key = create_secure_session(alice_session2.private_key, decode_public_key(bob_pub2))
    
    message2 = b"Second message in session 2"
    ciphertext2, nonce2, tag2 = encrypt_session_message(session2_key, message2)
    decrypted2 = decrypt_session_message(session2_key, ciphertext2, nonce2, tag2)
    print(f"Session 2 message: {decrypted2.decode()}")
    
    # Verify sessions are different
    assert session1_key != session2_key
    print(f"Session keys are different: {session1_key.hex()[:16]} != {session2_key.hex()[:16]}")
    
    # Securely delete session 2 keys
    secure_delete_keypair(alice_session2)
    secure_delete_keypair(bob_session2)
    print("Session keys securely deleted")


async def async_encryption_example():
    """Example demonstrating async usage of encryption"""
    print("\n=== Async Encryption Example ===")
    
    # Simulate async operations
    await asyncio.sleep(0.1)
    
    # Generate keys asynchronously
    keypair = generate_keypair()
    shared_key = derive_shared_key(keypair.private_key, keypair.public_key)
    
    # Encrypt message
    message = b"Async encrypted message"
    encrypted = encrypt_message(shared_key, message)
    
    # Simulate network delay
    await asyncio.sleep(0.1)
    
    # Decrypt message
    decrypted = decrypt_message(shared_key, encrypted)
    print(f"Async message: {decrypted.decode()}")
    
    # Clean up
    secure_delete_keypair(keypair)


def main():
    """Run all encryption examples"""
    print("P2P Secure Messaging - Encryption Examples")
    print("=" * 50)
    
    # Run basic example
    basic_encryption_example()
    
    # Run forward secrecy example
    forward_secrecy_example()
    
    # Run async example
    asyncio.run(async_encryption_example())
    
    print("\n" + "=" * 50)
    print("All examples completed successfully!")
    print("\nKey Features Demonstrated:")
    print("- X25519 key exchange")
    print("- AES-256-GCM encryption")
    print("- Forward secrecy with ephemeral keys")
    print("- Secure memory deletion")
    print("- Async compatibility")


if __name__ == "__main__":
    main() 