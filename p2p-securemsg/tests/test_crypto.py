"""
Tests for the crypto module
"""

import pytest
import asyncio
from p2p_securemsg.crypto import (
    KeyPair, Encryptor, encode_public_key, decode_public_key,
    generate_random_bytes, secure_memory_wipe
)


class TestKeyPair:
    """Test KeyPair class"""
    
    def test_generate_new_key_pair(self):
        """Test generating a new key pair"""
        key_pair = KeyPair()
        
        assert key_pair.public_key is not None
        assert len(key_pair.public_key) == 32
        assert key_pair.private_key is not None
        assert len(key_pair.private_key) == 32
    
    def test_create_key_pair_from_private_key(self):
        """Test creating key pair from existing private key"""
        # Generate a key pair
        original_key_pair = KeyPair()
        private_key_bytes = original_key_pair.private_key
        
        # Create new key pair from private key
        new_key_pair = KeyPair(private_key_bytes)
        
        # Both should have the same public key
        assert new_key_pair.public_key == original_key_pair.public_key
        assert new_key_pair.private_key == original_key_pair.private_key
    
    def test_derive_shared_secret(self):
        """Test deriving shared secret between two key pairs"""
        alice_key_pair = KeyPair()
        bob_key_pair = KeyPair()
        
        # Alice derives shared secret with Bob's public key
        alice_shared = alice_key_pair.derive_shared_secret(bob_key_pair.public_key)
        
        # Bob derives shared secret with Alice's public key
        bob_shared = bob_key_pair.derive_shared_secret(alice_key_pair.public_key)
        
        # Both should have the same shared secret
        assert alice_shared == bob_shared
        assert len(alice_shared) == 32
    
    def test_secure_wipe(self):
        """Test secure wiping of private key"""
        key_pair = KeyPair()
        private_key_bytes = key_pair.private_key
        
        # Wipe the private key
        key_pair.secure_wipe()
        
        # The wipe method should not raise an exception
        assert True


class TestEncryptor:
    """Test Encryptor class"""
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption"""
        # Create key pairs and derive shared secret
        alice_key_pair = KeyPair()
        bob_key_pair = KeyPair()
        shared_secret = alice_key_pair.derive_shared_secret(bob_key_pair.public_key)
        
        # Create encryptor
        encryptor = Encryptor(shared_secret)
        
        # Test message
        original_message = b"Hello, this is a test message!"
        
        # Encrypt
        ciphertext, nonce = encryptor.encrypt(original_message)
        
        # Decrypt
        decrypted_message = encryptor.decrypt(ciphertext, nonce)
        
        # Should match original
        assert decrypted_message == original_message
    
    def test_encrypt_different_messages(self):
        """Test that different messages produce different ciphertexts"""
        key_pair = KeyPair()
        # Use exactly 32 bytes for AES-256
        encryptor = Encryptor(b"12345678901234567890123456789012")
        
        message1 = b"First message"
        message2 = b"Second message"
        
        ciphertext1, nonce1 = encryptor.encrypt(message1)
        ciphertext2, nonce2 = encryptor.encrypt(message2)
        
        # Ciphertexts should be different
        assert ciphertext1 != ciphertext2
        assert nonce1 != nonce2


class TestUtilityFunctions:
    """Test utility functions"""
    
    def test_encode_decode_public_key(self):
        """Test encoding and decoding public keys"""
        key_pair = KeyPair()
        original_public_key = key_pair.public_key
        
        # Encode
        encoded = encode_public_key(original_public_key)
        assert isinstance(encoded, str)
        
        # Decode
        decoded = decode_public_key(encoded)
        assert decoded == original_public_key
    
    def test_generate_random_bytes(self):
        """Test generating random bytes"""
        length = 16
        random_bytes = generate_random_bytes(length)
        
        assert len(random_bytes) == length
        assert isinstance(random_bytes, bytes)
    
    def test_secure_memory_wipe(self):
        """Test secure memory wiping"""
        test_data = b"test data to wipe"
        
        # Should not raise an exception
        secure_memory_wipe(test_data)
        assert True


@pytest.mark.asyncio
async def test_async_compatibility():
    """Test that crypto functions work in async context"""
    # This test ensures our crypto functions can be used in async code
    key_pair = KeyPair()
    # Use exactly 32 bytes for AES-256
    encryptor = Encryptor(b"12345678901234567890123456789012")
    
    # Simulate async operation
    await asyncio.sleep(0.001)
    
    # Test encryption in async context
    message = b"Async test message"
    ciphertext, nonce = encryptor.encrypt(message)
    decrypted = encryptor.decrypt(ciphertext, nonce)
    
    assert decrypted == message 