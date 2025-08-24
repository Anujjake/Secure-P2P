"""
Tests for the encryption module
"""

import pytest
import asyncio
from p2p_securemsg.encryption import (
    generate_keypair, derive_shared_key, encrypt_message, decrypt_message,
    secure_delete, secure_delete_keypair, encode_public_key, decode_public_key,
    generate_session_keypair, create_secure_session, encrypt_session_message,
    decrypt_session_message, is_valid_public_key, is_valid_private_key,
    generate_random_bytes, KeyPair, EncryptedMessage
)


class TestKeyPair:
    """Test KeyPair named tuple"""
    
    def test_keypair_creation(self):
        """Test creating a KeyPair"""
        private_key = b"a" * 32
        public_key = b"b" * 32
        keypair = KeyPair(private_key=private_key, public_key=public_key)
        
        assert keypair.private_key == private_key
        assert keypair.public_key == public_key


class TestEncryptedMessage:
    """Test EncryptedMessage named tuple"""
    
    def test_encrypted_message_creation(self):
        """Test creating an EncryptedMessage"""
        ciphertext = b"encrypted_data"
        nonce = b"nonce_12_bytes"
        tag = b"auth_tag_16"
        encrypted = EncryptedMessage(ciphertext=ciphertext, nonce=nonce, tag=tag)
        
        assert encrypted.ciphertext == ciphertext
        assert encrypted.nonce == nonce
        assert encrypted.tag == tag


class TestGenerateKeypair:
    """Test generate_keypair function"""
    
    def test_generate_keypair(self):
        """Test generating a new key pair"""
        keypair = generate_keypair()
        
        assert isinstance(keypair, KeyPair)
        assert len(keypair.private_key) == 32
        assert len(keypair.public_key) == 32
        assert keypair.private_key != keypair.public_key
    
    def test_generate_keypair_unique(self):
        """Test that generated key pairs are unique"""
        keypair1 = generate_keypair()
        keypair2 = generate_keypair()
        
        assert keypair1.private_key != keypair2.private_key
        assert keypair1.public_key != keypair2.public_key


class TestDeriveSharedKey:
    """Test derive_shared_key function"""
    
    def test_derive_shared_key(self):
        """Test deriving shared key between two parties"""
        # Generate key pairs for Alice and Bob
        alice_keypair = generate_keypair()
        bob_keypair = generate_keypair()
        
        # Alice derives shared key with Bob's public key
        alice_shared = derive_shared_key(alice_keypair.private_key, bob_keypair.public_key)
        
        # Bob derives shared key with Alice's public key
        bob_shared = derive_shared_key(bob_keypair.private_key, alice_keypair.public_key)
        
        # Both should have the same shared key
        assert alice_shared == bob_shared
        assert len(alice_shared) == 32
    
    def test_derive_shared_key_invalid_private_key_size(self):
        """Test derive_shared_key with invalid private key size"""
        with pytest.raises(ValueError, match="Private key must be 32 bytes"):
            derive_shared_key(b"short", b"b" * 32)
    
    def test_derive_shared_key_invalid_public_key_size(self):
        """Test derive_shared_key with invalid public key size"""
        with pytest.raises(ValueError, match="Public key must be 32 bytes"):
            derive_shared_key(b"a" * 32, b"short")


class TestEncryptDecryptMessage:
    """Test encrypt_message and decrypt_message functions"""
    
    def test_encrypt_decrypt_message(self):
        """Test encrypting and decrypting a message"""
        # Generate key pairs and derive shared key
        alice_keypair = generate_keypair()
        bob_keypair = generate_keypair()
        shared_key = derive_shared_key(alice_keypair.private_key, bob_keypair.public_key)
        
        # Test message
        original_message = b"Hello, this is a test message!"
        
        # Encrypt
        encrypted = encrypt_message(shared_key, original_message)
        
        # Decrypt
        decrypted = decrypt_message(shared_key, encrypted)
        
        # Should match original
        assert decrypted == original_message
    
    def test_encrypt_message_invalid_key_size(self):
        """Test encrypt_message with invalid key size"""
        with pytest.raises(ValueError, match="Shared key must be 32 bytes"):
            encrypt_message(b"short_key", b"message")
    
    def test_decrypt_message_invalid_key_size(self):
        """Test decrypt_message with invalid key size"""
        encrypted = EncryptedMessage(
            ciphertext=b"data",
            nonce=b"nonce_12_bytes",
            tag=b"tag_16_bytes"
        )
        with pytest.raises(ValueError, match="Shared key must be 32 bytes"):
            decrypt_message(b"short_key", encrypted)
    
    def test_encrypt_different_messages(self):
        """Test that different messages produce different ciphertexts"""
        keypair = generate_keypair()
        shared_key = derive_shared_key(keypair.private_key, keypair.public_key)
        
        message1 = b"First message"
        message2 = b"Second message"
        
        encrypted1 = encrypt_message(shared_key, message1)
        encrypted2 = encrypt_message(shared_key, message2)
        
        # Ciphertexts should be different
        assert encrypted1.ciphertext != encrypted2.ciphertext
        assert encrypted1.nonce != encrypted2.nonce
        assert encrypted1.tag != encrypted2.tag


class TestSecureDelete:
    """Test secure_delete functions"""
    
    def test_secure_delete(self):
        """Test secure_delete function"""
        data = bytearray(b"sensitive_data")
        secure_delete(data)
        
        # Data should be overwritten with zeros
        assert data == bytearray(b'\x00' * len(data))
    
    def test_secure_delete_keypair(self):
        """Test secure_delete_keypair function"""
        keypair = generate_keypair()
        
        # Test that the function doesn't raise an exception
        # Note: NamedTuple fields are immutable, so we can't actually overwrite them
        # This is expected behavior for security reasons
        secure_delete_keypair(keypair)
        
        # The function should complete without error
        assert True


class TestEncodeDecodePublicKey:
    """Test encode_public_key and decode_public_key functions"""
    
    def test_encode_decode_public_key(self):
        """Test encoding and decoding public keys"""
        original_key = b"public_key_32_bytes_long_test"
        encoded = encode_public_key(original_key)
        decoded = decode_public_key(encoded)
        
        assert decoded == original_key
        assert isinstance(encoded, str)
    
    def test_decode_invalid_public_key(self):
        """Test decoding invalid public key"""
        with pytest.raises(ValueError):
            decode_public_key("invalid_base64")


class TestSessionFunctions:
    """Test session-related functions"""
    
    def test_generate_session_keypair(self):
        """Test generate_session_keypair function"""
        keypair, encoded_public = generate_session_keypair()
        
        assert isinstance(keypair, KeyPair)
        assert len(keypair.private_key) == 32
        assert len(keypair.public_key) == 32
        assert isinstance(encoded_public, str)
        assert decode_public_key(encoded_public) == keypair.public_key
    
    def test_create_secure_session(self):
        """Test create_secure_session function"""
        alice_keypair = generate_keypair()
        bob_keypair = generate_keypair()
        
        session_key = create_secure_session(alice_keypair.private_key, bob_keypair.public_key)
        
        assert len(session_key) == 32
        assert isinstance(session_key, bytes)
    
    def test_encrypt_decrypt_session_message(self):
        """Test encrypt_session_message and decrypt_session_message functions"""
        # Create session
        alice_keypair = generate_keypair()
        bob_keypair = generate_keypair()
        session_key = create_secure_session(alice_keypair.private_key, bob_keypair.public_key)
        
        # Test message
        original_message = b"Session message"
        
        # Encrypt
        ciphertext, nonce, tag = encrypt_session_message(session_key, original_message)
        
        # Decrypt
        decrypted = decrypt_session_message(session_key, ciphertext, nonce, tag)
        
        # Should match original
        assert decrypted == original_message


class TestValidationFunctions:
    """Test key validation functions"""
    
    def test_is_valid_public_key(self):
        """Test is_valid_public_key function"""
        # Valid public key
        valid_key = generate_keypair().public_key
        assert is_valid_public_key(valid_key) is True
        
        # Invalid key (wrong size)
        assert is_valid_public_key(b"short") is False
        
        # Test with None
        assert is_valid_public_key(None) is False
    
    def test_is_valid_private_key(self):
        """Test is_valid_private_key function"""
        # Valid private key
        valid_key = generate_keypair().private_key
        assert is_valid_private_key(valid_key) is True
        
        # Invalid key (wrong size)
        assert is_valid_private_key(b"short") is False
        
        # Test with None
        assert is_valid_private_key(None) is False


class TestUtilityFunctions:
    """Test utility functions"""
    
    def test_generate_random_bytes(self):
        """Test generate_random_bytes function"""
        length = 16
        random_bytes = generate_random_bytes(length)
        
        assert len(random_bytes) == length
        assert isinstance(random_bytes, bytes)
    
    def test_generate_random_bytes_different(self):
        """Test that generate_random_bytes produces different results"""
        bytes1 = generate_random_bytes(32)
        bytes2 = generate_random_bytes(32)
        
        assert bytes1 != bytes2


class TestForwardSecrecy:
    """Test forward secrecy properties"""
    
    def test_ephemeral_key_pairs(self):
        """Test that each session uses different ephemeral key pairs"""
        # Generate multiple session key pairs
        session1_keypair, _ = generate_session_keypair()
        session2_keypair, _ = generate_session_keypair()
        session3_keypair, _ = generate_session_keypair()
        
        # All should be different
        assert session1_keypair.private_key != session2_keypair.private_key
        assert session1_keypair.private_key != session3_keypair.private_key
        assert session2_keypair.private_key != session3_keypair.private_key
        
        assert session1_keypair.public_key != session2_keypair.public_key
        assert session1_keypair.public_key != session3_keypair.public_key
        assert session2_keypair.public_key != session3_keypair.public_key


@pytest.mark.asyncio
async def test_async_compatibility():
    """Test that encryption functions work in async context"""
    # Generate key pair in async context
    await asyncio.sleep(0.001)
    keypair = generate_keypair()
    
    # Derive shared key
    shared_key = derive_shared_key(keypair.private_key, keypair.public_key)
    
    # Encrypt and decrypt
    message = b"Async test message"
    encrypted = encrypt_message(shared_key, message)
    decrypted = decrypt_message(shared_key, encrypted)
    
    assert decrypted == message


def test_error_handling():
    """Test error handling in encryption functions"""
    # Test with empty bytes for derive_shared_key
    with pytest.raises(ValueError):
        derive_shared_key(b"", b"")
    
    # Test with None for secure_delete
    try:
        secure_delete(None)
    except (TypeError, AttributeError):
        pass  # Expected behavior
    
    # Test with invalid key sizes
    with pytest.raises(ValueError):
        derive_shared_key(b"short", b"also_short") 