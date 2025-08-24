#!/usr/bin/env python3
"""
Example usage of the enhanced network module
Demonstrates TCP/UDP connections, NAT traversal, and encrypted messaging
"""

import asyncio
import time
from p2p_securemsg.network import P2PNetwork, NetworkMessage
from p2p_securemsg.encryption import (
    generate_keypair, derive_shared_key, encrypt_message, decrypt_message,
    encode_public_key, decode_public_key
)


async def basic_network_example():
    """Basic network example with two peers"""
    print("=== Basic Network Example ===")
    
    # Create two networks
    network1 = P2PNetwork("127.0.0.1", 0, 0)
    network2 = P2PNetwork("127.0.0.1", 0, 0)
    
    try:
        # Start both networks
        print("Starting networks...")
        await network1.start()
        await network2.start()
        
        print(f"Network 1: TCP {network1.tcp_port}, UDP {network1.udp_port}")
        print(f"Network 2: TCP {network2.tcp_port}, UDP {network2.udp_port}")
        
        # Add custom message handler
        received_messages = []
        
        async def message_handler(message, reader, writer, addr):
            received_messages.append(message)
            print(f"Received message: {message.msg_type} from {message.sender_id}")
        
        network1.add_message_handler("custom", message_handler)
        
        # Connect network2 to network1
        print("\nConnecting networks...")
        success = await network2.connect_to_peer("127.0.0.1", network1.tcp_port)
        
        if success:
            print("✓ Networks connected successfully!")
            print(f"Network 1 peers: {len(network1.peers)}")
            print(f"Network 2 peers: {len(network2.peers)}")
        else:
            print("✗ Failed to connect networks")
        
        # Wait a bit for handshake to complete
        await asyncio.sleep(1)
        
        # Show peer information
        print("\nPeer Information:")
        for peer in network1.peers.values():
            print(f"  - {peer.id}: {peer.host}:{peer.port} ({peer.connection_type})")
        
    finally:
        # Clean up
        await network1.stop()
        await network2.stop()
        print("\nNetworks stopped")


async def encrypted_messaging_example():
    """Example of encrypted messaging between peers"""
    print("\n=== Encrypted Messaging Example ===")
    
    # Create networks
    network1 = P2PNetwork("127.0.0.1", 0, 0)
    network2 = P2PNetwork("127.0.0.1", 0, 0)
    
    try:
        # Start networks
        await network1.start()
        await network2.start()
        
        # Connect them
        await network2.connect_to_peer("127.0.0.1", network1.tcp_port)
        await asyncio.sleep(1)  # Wait for handshake
        
        # Get the shared key
        if network1.peers:
            peer = list(network1.peers.values())[0]
            shared_key = peer.shared_key
            
            if shared_key:
                print(f"✓ Shared key established: {shared_key.hex()[:16]}...")
                
                # Test encrypted messaging
                test_message = b"Hello, encrypted world!"
                print(f"Original message: {test_message.decode()}")
                
                # Encrypt and decrypt
                encrypted = encrypt_message(shared_key, test_message)
                decrypted = decrypt_message(shared_key, encrypted)
                
                print(f"Decrypted message: {decrypted.decode()}")
                print("✓ Encryption/decryption successful!")
                
                # Test sending encrypted message
                success = await network1.send_encrypted(shared_key, test_message)
                if success:
                    print("✓ Encrypted message sent successfully!")
                else:
                    print("✗ Failed to send encrypted message")
            else:
                print("✗ No shared key established")
        else:
            print("✗ No peers connected")
            
    finally:
        await network1.stop()
        await network2.stop()


async def nat_traversal_example():
    """Example of NAT traversal techniques"""
    print("\n=== NAT Traversal Example ===")
    
    # Create network
    network = P2PNetwork("127.0.0.1", 0, 0)
    
    try:
        await network.start()
        print(f"Network started on TCP {network.tcp_port}, UDP {network.udp_port}")
        
        # Add bootstrap peer
        network.add_bootstrap_peer("127.0.0.1", 8080)
        print("✓ Bootstrap peer added")
        
        # Test UDP hole punching simulation
        print("Testing UDP hole punching...")
        success = await network._try_udp_hole_punch("192.168.1.100", 8080)
        print(f"UDP hole punch result: {success}")
        
        # Test relay connection
        print("Testing relay connection...")
        success = await network._try_relay_connection("192.168.1.200", 8080)
        print(f"Relay connection result: {success}")
        
    finally:
        await network.stop()


async def performance_test():
    """Performance test for network operations"""
    print("\n=== Performance Test ===")
    
    # Create networks
    network1 = P2PNetwork("127.0.0.1", 0, 0)
    network2 = P2PNetwork("127.0.0.1", 0, 0)
    
    try:
        await network1.start()
        await network2.start()
        
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
        
        test_message = b"This is a test message for performance testing"
        
        start_time = time.time()
        for _ in range(1000):
            encrypted = encrypt_message(shared_key, test_message)
            decrypted = decrypt_message(shared_key, encrypted)
            assert decrypted == test_message
        end_time = time.time()
        
        print(f"Encrypted/decrypted 1000 messages in {end_time - start_time:.3f} seconds")
        print(f"Average: {(end_time - start_time) / 1000 * 1000:.2f} ms per message")
        
    finally:
        await network1.stop()
        await network2.stop()


async def stress_test():
    """Stress test with multiple connections"""
    print("\n=== Stress Test ===")
    
    # Create multiple networks
    networks = []
    try:
        # Create and start 5 networks
        for i in range(5):
            network = P2PNetwork("127.0.0.1", 0, 0)
            await network.start()
            networks.append(network)
            print(f"Network {i+1}: TCP {network.tcp_port}, UDP {network.udp_port}")
        
        # Connect them in a chain
        print("Connecting networks in a chain...")
        for i in range(len(networks) - 1):
            success = await networks[i+1].connect_to_peer("127.0.0.1", networks[i].tcp_port)
            if success:
                print(f"✓ Connected network {i+2} to network {i+1}")
            else:
                print(f"✗ Failed to connect network {i+2} to network {i+1}")
        
        # Wait for connections to stabilize
        await asyncio.sleep(2)
        
        # Show connection statistics
        total_peers = sum(len(network.peers) for network in networks)
        print(f"Total peer connections: {total_peers}")
        
        for i, network in enumerate(networks):
            print(f"Network {i+1} peers: {len(network.peers)}")
        
    finally:
        # Clean up
        for network in networks:
            await network.stop()
        print("All networks stopped")


async def main():
    """Run all network examples"""
    print("P2P Secure Messaging - Network Examples")
    print("=" * 50)
    
    # Run examples
    await basic_network_example()
    await encrypted_messaging_example()
    await nat_traversal_example()
    await performance_test()
    await stress_test()
    
    print("\n" + "=" * 50)
    print("All examples completed!")
    print("\nKey Features Demonstrated:")
    print("- TCP and UDP socket management")
    print("- Secure peer handshake with key exchange")
    print("- NAT traversal with UDP hole punching")
    print("- Relay connections through bootstrap peers")
    print("- Encrypted messaging with forward secrecy")
    print("- Performance optimization")
    print("- Stress testing with multiple connections")


if __name__ == "__main__":
    asyncio.run(main()) 