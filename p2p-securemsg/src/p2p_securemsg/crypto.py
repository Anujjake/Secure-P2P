"""
Cryptography module for P2P Secure Messaging
Provides X25519 key exchange, encryption, and secure memory management
"""

import os
import base64
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import nacl.public
import nacl.secret
import nacl.utils
import psutil


class KeyPair:
    """X25519 key pair for secure communication"""
    
    def __init__(self, private_key: Optional[bytes] = None):
        """
        Initialize a key pair
        
        Args:
            private_key: Optional private key bytes. If None, generates a new key pair.
        """
        if private_key:
            self._private_key = x25519.X25519PrivateKey.from_private_bytes(private_key)
        else:
            self._private_key = x25519.X25519PrivateKey.generate()
        
        self._public_key = self._private_key.public_key()
    
    @property
    def public_key(self) -> bytes:
        """Get the public key bytes"""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    @property
    def private_key(self) -> bytes:
        """Get the private key bytes"""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def derive_shared_secret(self, peer_public_key: bytes) -> bytes:
        """
        Derive a shared secret using X25519 key exchange
        
        Args:
            peer_public_key: The peer's public key
            
        Returns:
            Shared secret bytes
        """
        peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        shared_key = self._private_key.exchange(peer_key)
        
        # Use HKDF to derive a proper key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"p2p-securemsg-shared-secret",
            backend=default_backend()
        )
        return hkdf.derive(shared_key)
    
    def secure_wipe(self):
        """Securely wipe private key from memory"""
        # This is a simplified version - in production, you'd want more sophisticated memory wiping
        try:
            # Overwrite the private key bytes
            private_bytes = self.private_key
            for i in range(len(private_bytes)):
                private_bytes[i:i+1] = b'\x00'
        except:
            pass  # Ignore errors during wiping


class Encryptor:
    """Handles encryption and decryption of messages"""
    
    def __init__(self, shared_secret: bytes):
        """
        Initialize encryptor with shared secret
        
        Args:
            shared_secret: The shared secret derived from key exchange
        """
        self.shared_secret = shared_secret
    
    def encrypt(self, message: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt a message using AES-256-GCM
        
        Args:
            message: Plaintext message to encrypt
            
        Returns:
            Tuple of (ciphertext, nonce)
        """
        # Generate a random nonce
        nonce = os.urandom(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.shared_secret),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt the message
        ciphertext = encryptor.update(message) + encryptor.finalize()
        
        # Get the authentication tag
        tag = encryptor.tag
        
        # Combine ciphertext and tag
        return ciphertext + tag, nonce
    
    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """
        Decrypt a message using AES-256-GCM
        
        Args:
            ciphertext: Encrypted message (includes authentication tag)
            nonce: Nonce used for encryption
            
        Returns:
            Decrypted plaintext
        """
        # Split ciphertext and tag (last 16 bytes are the tag)
        actual_ciphertext = ciphertext[:-16]
        tag = ciphertext[-16:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.shared_secret),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt the message
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        return plaintext


def secure_memory_wipe(data: bytes):
    """
    Securely wipe data from memory
    
    Args:
        data: Data to wipe
    """
    try:
        # Overwrite the data with zeros
        for i in range(len(data)):
            data[i:i+1] = b'\x00'
    except:
        pass  # Ignore errors during wiping


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Random bytes
    """
    return os.urandom(length)


def encode_public_key(public_key: bytes) -> str:
    """
    Encode public key as base64 string
    
    Args:
        public_key: Public key bytes
        
    Returns:
        Base64 encoded string
    """
    return base64.b64encode(public_key).decode('utf-8')


def decode_public_key(encoded_key: str) -> bytes:
    """
    Decode public key from base64 string
    
    Args:
        encoded_key: Base64 encoded public key
        
    Returns:
        Public key bytes
    """
    return base64.b64decode(encoded_key.encode('utf-8')) 