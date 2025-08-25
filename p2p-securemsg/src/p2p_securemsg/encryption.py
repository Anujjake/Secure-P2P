"""
Encryption module for P2P Secure Messaging
Provides X25519 key exchange, AES-256-GCM encryption, and forward secrecy
"""

import os
import base64
from typing import Tuple, Optional, NamedTuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import nacl.public
import nacl.secret
import nacl.utils
import psutil
from cryptography.hazmat.primitives import serialization


class KeyPair(NamedTuple):
    """Represents an X25519 key pair"""
    private_key: bytes
    public_key: bytes


class EncryptedMessage(NamedTuple):
    """Represents an encrypted message with metadata"""
    ciphertext: bytes
    nonce: bytes
    tag: bytes


def generate_keypair() -> KeyPair:
    """
    Generate a new X25519 key pair for ephemeral use
    
    Returns:
        KeyPair containing private and public keys
    """
    # Generate private key
    private_key = x25519.X25519PrivateKey.generate()
    
    # Get public key
    public_key = private_key.public_key()
    
    # Convert to raw bytes
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return KeyPair(private_key=private_bytes, public_key=public_bytes)


def derive_shared_key(private_key: bytes, peer_public_key: bytes) -> bytes:
    """
    Derive a shared secret key using X25519 key exchange
    
    Args:
        private_key: Our private key bytes
        peer_public_key: Peer's public key bytes
        
    Returns:
        Shared secret key (32 bytes)
        
    Raises:
        ValueError: If key sizes are invalid
        cryptography.exceptions.InvalidKey: If keys are malformed
    """
    if len(private_key) != 32:
        raise ValueError("Private key must be 32 bytes")
    if len(peer_public_key) != 32:
        raise ValueError("Public key must be 32 bytes")
    
    # Create key objects
    private_key_obj = x25519.X25519PrivateKey.from_private_bytes(private_key)
    peer_public_key_obj = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
    
    # Perform key exchange
    shared_secret = private_key_obj.exchange(peer_public_key_obj)
    
    # Use HKDF to derive a proper key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"p2p-securemsg-shared-key",
        backend=default_backend()
    )
    
    return hkdf.derive(shared_secret)


def encrypt_message(shared_key: bytes, plaintext: bytes) -> EncryptedMessage:
    """
    Encrypt a message using AES-256-GCM
    
    Args:
        shared_key: Shared secret key (32 bytes)
        plaintext: Message to encrypt
        
    Returns:
        EncryptedMessage containing ciphertext, nonce, and tag
        
    Raises:
        ValueError: If shared_key is not 32 bytes
    """
    if len(shared_key) != 32:
        raise ValueError("Shared key must be 32 bytes")
    # Use bytearray for sensitive buffers
    key_buf = bytearray(shared_key)
    nonce = os.urandom(12)
    cipher = Cipher(
        algorithms.AES(bytes(key_buf)),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext must be bytes or bytearray")
    pt_buf = bytearray(plaintext)
    ciphertext = encryptor.update(bytes(pt_buf)) + encryptor.finalize()
    tag = encryptor.tag
    # Securely wipe sensitive buffers
    secure_delete(key_buf)
    secure_delete(pt_buf)
    return EncryptedMessage(
        ciphertext=ciphertext,
        nonce=nonce,
        tag=tag
    )


def decrypt_message(shared_key: bytes, encrypted_message: EncryptedMessage) -> bytes:
    """
    Decrypt a message using AES-256-GCM
    
    Args:
        shared_key: Shared secret key (32 bytes)
        encrypted_message: EncryptedMessage containing ciphertext, nonce, and tag
        
    Returns:
        Decrypted plaintext
        
    Raises:
        ValueError: If shared_key is not 32 bytes
        cryptography.exceptions.InvalidKey: If decryption fails
    """
    if len(shared_key) != 32:
        raise ValueError("Shared key must be 32 bytes")
    key_buf = bytearray(shared_key)
    cipher = Cipher(
        algorithms.AES(bytes(key_buf)),
        modes.GCM(encrypted_message.nonce, encrypted_message.tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    ct_buf = bytearray(encrypted_message.ciphertext)
    plaintext = decryptor.update(bytes(ct_buf)) + decryptor.finalize()
    # Securely wipe sensitive buffers
    secure_delete(key_buf)
    secure_delete(ct_buf)
    return plaintext


def secure_delete(data: bytes) -> None:
    """
    Securely delete data from memory by overwriting with zeros.
    Only works for mutable types like bytearray.
    Args:
        data: Data to securely delete (must be bytearray)
    Raises:
        TypeError: If data is not a bytearray
    """
    if not isinstance(data, bytearray):
        raise TypeError("secure_delete only works on bytearray objects!")
    for i in range(len(data)):
        data[i] = 0


def secure_delete_keypair(keypair: KeyPair) -> None:
    """
    Securely delete a key pair from memory
    
    Args:
        keypair: KeyPair to securely delete
    """
    if isinstance(keypair.private_key, bytearray):
        secure_delete(keypair.private_key)
    if isinstance(keypair.public_key, bytearray):
        secure_delete(keypair.public_key)


def encode_public_key(public_key: bytes) -> str:
    """
    Encode public key as base64 string for transmission
    
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
        
    Raises:
        ValueError: If the encoded key is invalid
    """
    try:
        return base64.b64decode(encoded_key.encode('utf-8'))
    except Exception as e:
        raise ValueError(f"Invalid encoded public key: {e}")


def generate_session_keypair() -> Tuple[KeyPair, str]:
    """
    Generate a new ephemeral key pair for a session with forward secrecy
    
    Returns:
        Tuple of (KeyPair, encoded_public_key)
    """
    keypair = generate_keypair()
    encoded_public = encode_public_key(keypair.public_key)
    return keypair, encoded_public


def create_secure_session(my_private_key: bytes, peer_public_key: bytes) -> bytes:
    """
    Create a secure session by deriving a shared key
    
    Args:
        my_private_key: Our private key
        peer_public_key: Peer's public key
        
    Returns:
        Shared session key
    """
    return derive_shared_key(my_private_key, peer_public_key)


def encrypt_session_message(session_key: bytes, message: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt a message for a session
    
    Args:
        session_key: Session shared key
        message: Message to encrypt
        
    Returns:
        Tuple of (ciphertext, nonce, tag)
    """
    encrypted = encrypt_message(session_key, message)
    return encrypted.ciphertext, encrypted.nonce, encrypted.tag


def decrypt_session_message(session_key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt a message from a session
    
    Args:
        session_key: Session shared key
        ciphertext: Encrypted message
        nonce: Nonce used for encryption
        tag: Authentication tag
        
    Returns:
        Decrypted message
    """
    encrypted_message = EncryptedMessage(
        ciphertext=ciphertext,
        nonce=nonce,
        tag=tag
    )
    return decrypt_message(session_key, encrypted_message)


# Utility functions for key validation
def is_valid_public_key(public_key: bytes) -> bool:
    """
    Check if a public key is valid
    
    Args:
        public_key: Public key to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        if public_key is None or len(public_key) != 32:
            return False
        x25519.X25519PublicKey.from_public_bytes(public_key)
        return True
    except Exception:
        return False


def is_valid_private_key(private_key: bytes) -> bool:
    """
    Check if a private key is valid
    
    Args:
        private_key: Private key to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        if private_key is None or len(private_key) != 32:
            return False
        x25519.X25519PrivateKey.from_private_bytes(private_key)
        return True
    except Exception:
        return False


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Random bytes
    """
    return os.urandom(length) 