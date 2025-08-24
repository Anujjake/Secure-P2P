#!/usr/bin/env python3
"""
Example usage of the secure messenger module
Demonstrates interactive CLI, encrypted messaging, and file transfer
"""

import asyncio
import tempfile
import os
import time
from pathlib import Path
from p2p_securemsg.messenger import SecureMessenger
from p2p_securemsg.network import P2PNetwork
from p2p_securemsg.encryption import (
    generate_keypair, derive_shared_key, encrypt_message, decrypt_message,
    encode_public_key, decode_public_key
)


async def basic_messenger_example():
    """Basic messenger example with two instances"""
    print("=== Basic Messenger Example ===")
    
    # Create two messengers
    messenger1 = SecureMessenger()
    messenger2 = SecureMessenger()
    
    try:
        # Start both messengers
        print("Starting messengers...")
        await messenger1.start_network()
        await messenger2.start_network()
        
        print(f"Messenger 1: TCP {messenger1.network.tcp_port}, UDP {messenger1.network.udp_port}")
        print(f"Messenger 2: TCP {messenger2.network.tcp_port}, UDP {messenger2.network.udp_port}")
        
        # Set up peer information
        messenger1.peer_address = ("127.0.0.1", messenger2.network.tcp_port)
        messenger2.peer_address = ("127.0.0.1", messenger1.network.tcp_port)
        
        # Establish connections
        print("\nEstablishing secure connections...")
        success1 = await messenger1.establish_connection()
        success2 = await messenger2.establish_connection()
        
        if success1 and success2:
            print("✓ Secure connections established!")
            print(f"Messenger 1 shared key: {messenger1.peer_shared_key is not None}")
            print(f"Messenger 2 shared key: {messenger2.peer_shared_key is not None}")
        else:
            print("✗ Failed to establish connections")
            return
        
        # Test text messaging
        print("\nTesting text messaging...")
        test_message = "Hello from Messenger 1!"
        
        # Send message from messenger1 to messenger2
        await messenger1.send_text_message(test_message)
        
        # Wait for message processing
        await asyncio.sleep(1)
        
        # Check if message was received
        if messenger2.message_history:
            received_msg = messenger2.message_history[-1]
            print(f"✓ Message received: {received_msg['content']}")
        else:
            print("✗ No message received")
        
        # Test file transfer
        print("\nTesting file transfer...")
        
        # Create a test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("This is a test file for secure transfer!")
            test_file_path = f.name
        
        try:
            # Send file from messenger1 to messenger2
            await messenger1.send_file_message(test_file_path)
            
            # Wait for file processing
            await asyncio.sleep(1)
            
            # Check if file was received
            if messenger2.message_history:
                last_msg = messenger2.message_history[-1]
                if last_msg["type"] == "file_received":
                    print(f"✓ File received: {last_msg['content']}")
                else:
                    print("✗ File not received")
            else:
                print("✗ No file message received")
                
        finally:
            # Clean up test file
            if os.path.exists(test_file_path):
                os.unlink(test_file_path)
        
    finally:
        # Secure exit
        await messenger1.secure_exit()
        await messenger2.secure_exit()
        print("\nMessengers stopped securely")


async def encryption_demo():
    """Demonstrate encryption capabilities"""
    print("\n=== Encryption Demo ===")
    
    # Create key pairs
    alice_keypair = generate_keypair()
    bob_keypair = generate_keypair()
    
    print(f"Alice's public key: {encode_public_key(alice_keypair.public_key)[:32]}...")
    print(f"Bob's public key: {encode_public_key(bob_keypair.public_key)[:32]}...")
    
    # Derive shared keys
    alice_shared = derive_shared_key(alice_keypair.private_key, bob_keypair.public_key)
    bob_shared = derive_shared_key(bob_keypair.private_key, alice_keypair.public_key)
    
    print(f"Shared keys match: {alice_shared == bob_shared}")
    print(f"Shared key length: {len(alice_shared)} bytes")
    
    # Test encryption/decryption
    test_messages = [
        "Hello, secure world!",
        "This is a longer message with special characters: 🚀🔐💻",
        "Binary data: " + "".join([chr(i) for i in range(32, 127)])
    ]
    
    for message in test_messages:
        # Encrypt
        encrypted = encrypt_message(alice_shared, message.encode('utf-8'))
        
        # Decrypt
        decrypted = decrypt_message(bob_shared, encrypted)
        
        # Verify
        success = decrypted.decode('utf-8') == message
        print(f"✓ Message '{message[:20]}...' {'✓' if success else '✗'}")
    
    # Test file encryption
    print("\nTesting file encryption...")
    
    # Create test file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("This is a test file for encryption demo!")
        test_file_path = f.name
    
    try:
        # Read and encrypt file
        with open(test_file_path, 'rb') as f:
            file_data = f.read()
        
        # Encrypt file data
        encrypted_file = encrypt_message(alice_shared, file_data)
        
        # Decrypt file data
        decrypted_file = decrypt_message(bob_shared, encrypted_file)
        
        # Verify file integrity
        file_success = decrypted_file == file_data
        print(f"✓ File encryption/decryption: {'✓' if file_success else '✗'}")
        
    finally:
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)


async def performance_test():
    """Performance test for messenger operations"""
    print("\n=== Performance Test ===")
    
    # Test key generation performance
    print("Testing key generation...")
    start_time = time.time()
    for _ in range(100):
        generate_keypair()
    end_time = time.time()
    print(f"Generated 100 key pairs in {end_time - start_time:.3f} seconds")
    
    # Test encryption performance
    print("Testing encryption performance...")
    alice_keypair = generate_keypair()
    bob_keypair = generate_keypair()
    shared_key = derive_shared_key(alice_keypair.private_key, bob_keypair.public_key)
    
    test_message = "This is a test message for performance testing"
    
    start_time = time.time()
    for _ in range(1000):
        encrypted = encrypt_message(shared_key, test_message.encode('utf-8'))
        decrypted = decrypt_message(shared_key, encrypted)
        assert decrypted.decode('utf-8') == test_message
    end_time = time.time()
    
    print(f"Encrypted/decrypted 1000 messages in {end_time - start_time:.3f} seconds")
    print(f"Average: {(end_time - start_time) / 1000 * 1000:.2f} ms per message")


async def security_features_demo():
    """Demonstrate security features"""
    print("\n=== Security Features Demo ===")
    
    # Create messenger
    messenger = SecureMessenger()
    
    try:
        # Start network
        await messenger.start_network()
        
        # Add test data
        messenger.peer_shared_key = b"test_key_32_bytes_long_for_testing"
        messenger.message_history = [
            {"type": "sent", "content": "Secret message 1", "timestamp": time.time()},
            {"type": "received", "content": "Secret message 2", "timestamp": time.time()}
        ]
        
        # Create temp files
        temp_files = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(f"Secret file content {i}")
                temp_files.append(f.name)
                messenger.temp_files.append(f.name)
        
        print(f"Created {len(temp_files)} temporary files")
        print(f"Message history contains {len(messenger.message_history)} messages")
        print(f"Shared key established: {messenger.peer_shared_key is not None}")
        
        # Perform secure exit
        print("\nPerforming secure exit...")
        await messenger.secure_exit()
        
        # Verify cleanup
        print(f"✓ Messenger stopped: {not messenger.running}")
        print(f"✓ History cleared: {len(messenger.message_history) == 0}")
        print(f"✓ Temp files deleted: {all(not os.path.exists(f) for f in temp_files)}")
        
    except Exception as e:
        print(f"Error during security demo: {e}")
    finally:
        # Clean up any remaining files
        for temp_file in messenger.temp_files:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


async def interactive_demo():
    """Interactive demo of messenger features"""
    print("\n=== Interactive Demo ===")
    
    # Create messenger
    messenger = SecureMessenger()
    
    try:
        # Start network
        await messenger.start_network()
        
        print(f"Messenger started on TCP {messenger.network.tcp_port}")
        print(f"Your Node ID: {messenger.network.node_id}")
        print(f"Your Public Key: {encode_public_key(messenger.network.key_pair.public_key)[:32]}...")
        
        # Simulate peer connection
        print("\nSimulating peer connection...")
        
        # Create a mock peer
        peer_keypair = generate_keypair()
        shared_key = derive_shared_key(
            messenger.network.key_pair.private_key,
            peer_keypair.public_key
        )
        
        messenger.peer_shared_key = shared_key
        messenger.peer_id = "demo_peer"
        messenger.peer_address = ("127.0.0.1", 8080)
        
        print("✓ Mock peer connected")
        
        # Demo commands
        print("\nDemo commands:")
        print("1. Sending text message...")
        await messenger.send_text_message("Hello from interactive demo!")
        
        print("2. Showing status...")
        messenger.show_status()
        
        print("3. Showing history...")
        messenger.show_history()
        
        print("4. Creating and sending test file...")
        
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("This is a test file for the interactive demo!")
            test_file_path = f.name
        
        try:
            await messenger.send_file_message(test_file_path)
        finally:
            if os.path.exists(test_file_path):
                os.unlink(test_file_path)
        
        print("5. Showing updated history...")
        messenger.show_history()
        
    finally:
        await messenger.secure_exit()


async def main():
    """Run all messenger examples"""
    print("P2P Secure Messenger - Examples")
    print("=" * 50)
    
    # Run examples
    await basic_messenger_example()
    await encryption_demo()
    await performance_test()
    await security_features_demo()
    await interactive_demo()
    
    print("\n" + "=" * 50)
    print("All examples completed!")
    print("\nKey Features Demonstrated:")
    print("- Interactive CLI with Rich interface")
    print("- Secure peer-to-peer messaging")
    print("- File transfer with encryption")
    print("- Message history management")
    print("- Secure exit with memory wiping")
    print("- Performance optimization")
    print("- Security features and cleanup")


if __name__ == "__main__":
    asyncio.run(main()) 