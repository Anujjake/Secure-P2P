# API Documentation

## Core Modules

### Crypto Module (`p2p_securemsg.crypto`)

#### KeyPair Class

Represents an X25519 key pair for secure communication.

```python
class KeyPair:
    def __init__(self, private_key: Optional[bytes] = None)
    @property
    def public_key(self) -> bytes
    @property
    def private_key(self) -> bytes
    def derive_shared_secret(self, peer_public_key: bytes) -> bytes
    def secure_wipe(self)
```

**Methods:**
- `derive_shared_secret(peer_public_key)`: Derive shared secret using X25519 key exchange
- `secure_wipe()`: Securely wipe private key from memory

#### Encryptor Class

Handles encryption and decryption of messages using AES-256-GCM.

```python
class Encryptor:
    def __init__(self, shared_secret: bytes)
    def encrypt(self, message: bytes) -> Tuple[bytes, bytes]
    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes
```

**Methods:**
- `encrypt(message)`: Encrypt message, returns (ciphertext, nonce)
- `decrypt(ciphertext, nonce)`: Decrypt message using ciphertext and nonce

### Network Module (`p2p_securemsg.network`)

#### P2PNode Class

Main P2P node for secure messaging.

```python
class P2PNode:
    def __init__(self, host: str = "0.0.0.0", port: int = 0)
    async def start(self)
    async def stop(self)
    async def connect_to_peer(self, host: str, port: int, peer_public_key: bytes) -> bool
    async def send_to_peer(self, peer_id: str, msg_type: str, payload: Any) -> bool
    async def broadcast(self, msg_type: str, payload: Any) -> int
    def add_message_handler(self, msg_type: str, handler: Callable)
    def get_peer_info(self) -> List[Dict[str, Any]]
```

**Key Methods:**
- `start()`: Start the P2P node
- `stop()`: Stop the P2P node and securely wipe keys
- `connect_to_peer(host, port, public_key)`: Connect to a peer
- `send_to_peer(peer_id, msg_type, payload)`: Send message to specific peer
- `broadcast(msg_type, payload)`: Broadcast message to all peers

#### Message Class

Represents a message in the P2P network.

```python
class Message:
    def __init__(self, msg_type: str, payload: Any, sender_id: str = "")
    def to_dict(self) -> Dict[str, Any]
    def to_bytes(self) -> bytes
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message'
    @classmethod
    def from_bytes(cls, data: bytes) -> 'Message'
```

### CLI Module (`p2p_securemsg.cli`)

#### SecureMessagingCLI Class

Rich command-line interface for the P2P messaging system.

```python
class SecureMessagingCLI:
    def __init__(self)
    async def run_interactive(self)
    async def start_node(self, host: str = "0.0.0.0", port: int = 0)
    async def connect_to_peer(self, host: str, port: int, public_key_str: str)
    async def send_message(self, peer_id: str, message_text: str)
    async def broadcast_message(self, message_text: str)
```

## Usage Examples

### Basic Key Exchange

```python
from p2p_securemsg.crypto import KeyPair, Encryptor

# Generate key pairs for Alice and Bob
alice_key_pair = KeyPair()
bob_key_pair = KeyPair()

# Derive shared secret
alice_shared = alice_key_pair.derive_shared_secret(bob_key_pair.public_key)
bob_shared = bob_key_pair.derive_shared_secret(alice_key_pair.public_key)

# Both should have the same shared secret
assert alice_shared == bob_shared

# Create encryptors
alice_encryptor = Encryptor(alice_shared)
bob_encryptor = Encryptor(bob_shared)

# Encrypt and decrypt a message
message = b"Hello, Bob!"
ciphertext, nonce = alice_encryptor.encrypt(message)
decrypted = bob_encryptor.decrypt(ciphertext, nonce)
assert decrypted == message
```

### P2P Node Setup

```python
import asyncio
from p2p_securemsg.network import P2PNode

async def main():
    # Create and start a P2P node
    node = P2PNode(host="0.0.0.0", port=8080)
    await node.start()
    
    # Add message handler
    def handle_message(message, reader, writer):
        print(f"Received: {message.payload}")
    
    node.add_message_handler("message", handle_message)
    
    # Connect to a peer
    peer_public_key = b"..."  # Get from peer
    success = await node.connect_to_peer("192.168.1.100", 8081, peer_public_key)
    
    # Send a message
    await node.send_to_peer("peer_id", "message", "Hello, peer!")
    
    # Keep running
    try:
        await asyncio.sleep(3600)  # Run for 1 hour
    finally:
        await node.stop()

asyncio.run(main())
```

### CLI Usage

```python
from p2p_securemsg.cli import SecureMessagingCLI
import asyncio

async def main():
    cli = SecureMessagingCLI()
    await cli.run_interactive()

asyncio.run(main())
```

## Security Considerations

1. **Key Management**: Always securely wipe private keys when no longer needed
2. **Message Validation**: Validate all incoming messages before processing
3. **Network Security**: Use TLS for additional transport layer security if needed
4. **Memory Protection**: Be aware of memory dumps and use secure memory wiping
5. **Key Verification**: Verify peer public keys through out-of-band channels

## Error Handling

The library provides comprehensive error handling:

- `KeyPair` operations may raise cryptography-related exceptions
- Network operations may raise connection and timeout exceptions
- CLI operations handle user input validation and network errors gracefully

Always wrap network operations in try-catch blocks and handle exceptions appropriately. 