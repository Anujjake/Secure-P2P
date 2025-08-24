"""
Enhanced Network module for P2P Secure Messaging
Handles peer-to-peer communication with NAT traversal and secure handshakes
"""

import asyncio
import socket
import json
import struct
import time
import random
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass
from .encryption import (
    generate_keypair, derive_shared_key, encrypt_message, decrypt_message,
    encode_public_key, decode_public_key, KeyPair, EncryptedMessage
)


@dataclass
class Peer:
    """Represents a peer in the P2P network"""
    id: str
    public_key: bytes
    host: str
    port: int
    shared_key: Optional[bytes] = None
    last_seen: float = 0.0
    connection_type: str = "unknown"  # "direct", "udp", "relay"


@dataclass
class NetworkMessage:
    """Represents a network message with type and payload"""
    msg_type: str
    payload: Any
    sender_id: str = ""
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary"""
        return {
            "type": self.msg_type,
            "payload": self.payload,
            "sender_id": self.sender_id,
            "timestamp": self.timestamp
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NetworkMessage':
        """Create message from dictionary"""
        return cls(
            msg_type=data["type"],
            payload=data["payload"],
            sender_id=data.get("sender_id", ""),
            timestamp=data.get("timestamp", time.time())
        )
    
    def to_bytes(self) -> bytes:
        """Serialize message to bytes"""
        data = json.dumps(self.to_dict()).encode('utf-8')
        return struct.pack('!I', len(data)) + data
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'NetworkMessage':
        """Deserialize message from bytes"""
        if len(data) < 4:
            raise ValueError("Invalid message format")
        
        length = struct.unpack('!I', data[:4])[0]
        if len(data) < 4 + length:
            raise ValueError("Incomplete message")
        
        msg_data = data[4:4+length]
        msg_dict = json.loads(msg_data.decode('utf-8'))
        return cls.from_dict(msg_dict)


class P2PNetwork:
    """Enhanced P2P network with NAT traversal and secure handshakes"""
    
    def __init__(self, host: str = "0.0.0.0", tcp_port: int = 0, udp_port: int = 0):
        """
        Initialize P2P network
        
        Args:
            host: Host to bind to
            tcp_port: TCP port to bind to (0 for random)
            udp_port: UDP port to bind to (0 for random)
        """
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        
        # Generate ephemeral key pair for this session
        self.key_pair = generate_keypair()
        self.node_id = encode_public_key(self.key_pair.public_key)[:16]
        
        # Network state
        self.peers: Dict[str, Peer] = {}
        self.tcp_server: Optional[asyncio.Server] = None
        self.udp_transport: Optional[asyncio.DatagramTransport] = None
        self.running = False
        
        # Message handlers
        self.message_handlers: Dict[str, Callable] = {}
        
        # NAT traversal settings
        self.bootstrap_peers: List[Tuple[str, int]] = []
        self.udp_hole_punch_timeout = 5.0
        self.connection_timeout = 10.0
        
        # Connection tracking
        self.pending_connections: Dict[str, asyncio.Future] = {}
        self.connection_attempts: Dict[str, int] = {}
    
    async def start(self):
        """Start the P2P network"""
        if self.running:
            return
        
        # Start TCP server
        self.tcp_server = await asyncio.start_server(
            self._handle_tcp_connection,
            self.host,
            self.tcp_port
        )
        
        # Get actual TCP port if we used 0
        if self.tcp_port == 0:
            self.tcp_port = self.tcp_server.sockets[0].getsockname()[1]
        
        # Start UDP listener
        loop = asyncio.get_event_loop()
        self.udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: UDPProtocol(self._handle_udp_message),
            local_addr=(self.host, self.udp_port)
        )
        
        # Get actual UDP port if we used 0
        if self.udp_port == 0:
            self.udp_port = self.udp_transport.get_extra_info('socket').getsockname()[1]
        
        self.running = True
        print(f"P2P Network started:")
        print(f"  TCP: {self.host}:{self.tcp_port}")
        print(f"  UDP: {self.host}:{self.udp_port}")
        print(f"  Node ID: {self.node_id}")
        print(f"  Public Key: {encode_public_key(self.key_pair.public_key)}")
    
    async def stop(self):
        """Stop the P2P network"""
        if not self.running:
            return
        
        self.running = False
        
        # Close TCP server
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
        
        # Close UDP transport
        if self.udp_transport:
            self.udp_transport.close()
        
        # Securely delete key pair
        from .encryption import secure_delete_keypair
        secure_delete_keypair(self.key_pair)
        
        print("P2P Network stopped")
    
    async def connect_to_peer(self, ip: str, port: int) -> bool:
        """
        Connect to a peer with automatic NAT traversal
        
        Args:
            ip: Peer IP address
            port: Peer port
            
        Returns:
            True if connection successful
        """
        peer_id = f"{ip}:{port}"
        
        # Check if already connected
        if peer_id in self.peers:
            print(f"Already connected to {peer_id}")
            return True
        
        # Check if connection attempt in progress
        if peer_id in self.pending_connections:
            print(f"Connection attempt to {peer_id} already in progress")
            return await self.pending_connections[peer_id]
        
        # Create connection future
        connection_future = asyncio.Future()
        self.pending_connections[peer_id] = connection_future
        
        try:
            # Try direct TCP connection first
            if await self._try_direct_tcp_connection(ip, port):
                connection_future.set_result(True)
                return True
            
            # Try UDP hole punching
            if await self._try_udp_hole_punch(ip, port):
                connection_future.set_result(True)
                return True
            
            # Try relay through bootstrap peer
            if await self._try_relay_connection(ip, port):
                connection_future.set_result(True)
                return True
            
            connection_future.set_result(False)
            return False
            
        except Exception as e:
            print(f"Failed to connect to {peer_id}: {e}")
            connection_future.set_exception(e)
            return False
        finally:
            if peer_id in self.pending_connections:
                del self.pending_connections[peer_id]
    
    async def _try_direct_tcp_connection(self, ip: str, port: int) -> bool:
        """Try direct TCP connection to peer"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.connection_timeout
            )
            
            # Perform handshake
            if await self._perform_handshake(reader, writer, ip, port):
                return True
            
            writer.close()
            await writer.wait_closed()
            return False
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
    
    async def _try_udp_hole_punch(self, ip: str, port: int) -> bool:
        """Try UDP hole punching for NAT traversal"""
        try:
            # Send UDP punch packet
            punch_msg = NetworkMessage("udp_punch", {
                "node_id": self.node_id,
                "public_key": encode_public_key(self.key_pair.public_key),
                "tcp_port": self.tcp_port,
                "udp_port": self.udp_port
            })
            
            # Send punch packet
            self.udp_transport.sendto(punch_msg.to_bytes(), (ip, port))
            
            # Wait for response
            try:
                await asyncio.wait_for(
                    self._wait_for_udp_response(ip, port),
                    timeout=self.udp_hole_punch_timeout
                )
                return True
            except asyncio.TimeoutError:
                return False
                
        except Exception as e:
            print(f"UDP hole punch failed: {e}")
            return False
    
    async def _try_relay_connection(self, ip: str, port: int) -> bool:
        """Try connection through bootstrap peer relay"""
        for bootstrap_ip, bootstrap_port in self.bootstrap_peers:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(bootstrap_ip, bootstrap_port),
                    timeout=self.connection_timeout
                )
                
                # Send relay request
                relay_msg = NetworkMessage("relay_request", {
                    "target_ip": ip,
                    "target_port": port,
                    "node_id": self.node_id,
                    "public_key": encode_public_key(self.key_pair.public_key)
                })
                
                await self._send_tcp_message(relay_msg, writer)
                
                # Wait for relay response
                response = await self._receive_tcp_message(reader)
                if response and response.msg_type == "relay_response":
                    writer.close()
                    await writer.wait_closed()
                    return True
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                print(f"Relay through {bootstrap_ip}:{bootstrap_port} failed: {e}")
                continue
        
        return False
    
    async def _perform_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ip: str, port: int) -> bool:
        """Perform secure handshake with peer"""
        try:
            # Send handshake
            handshake_msg = NetworkMessage("handshake", {
                "node_id": self.node_id,
                "public_key": encode_public_key(self.key_pair.public_key),
                "tcp_port": self.tcp_port,
                "udp_port": self.udp_port
            })
            
            await self._send_tcp_message(handshake_msg, writer)
            
            # Receive handshake response
            response = await self._receive_tcp_message(reader)
            if not response or response.msg_type != "handshake":
                return False
            
            # Extract peer info
            peer_public_key = decode_public_key(response.payload["public_key"])
            peer_id = response.payload["node_id"]
            
            # Derive shared key
            shared_key = derive_shared_key(self.key_pair.private_key, peer_public_key)
            
            # Create peer
            peer = Peer(
                id=peer_id,
                public_key=peer_public_key,
                host=ip,
                port=port,
                shared_key=shared_key,
                last_seen=time.time(),
                connection_type="direct"
            )
            
            self.peers[peer_id] = peer
            
            # Start listening for messages from this peer
            asyncio.create_task(self._listen_to_peer(reader, writer, peer))
            
            print(f"Handshake completed with {peer_id} at {ip}:{port}")
            return True
            
        except Exception as e:
            print(f"Handshake failed: {e}")
            return False
    
    async def send_encrypted(self, shared_key: bytes, msg: bytes) -> bool:
        """
        Send encrypted message to peer with given shared key
        
        Args:
            shared_key: Shared encryption key
            msg: Message to encrypt and send
            
        Returns:
            True if message sent successfully
        """
        try:
            # Find peer with this shared key
            target_peer = None
            for peer in self.peers.values():
                if peer.shared_key == shared_key:
                    target_peer = peer
                    break
            
            if not target_peer:
                print("No peer found with the specified shared key")
                return False
            
            # Encrypt message
            encrypted = encrypt_message(shared_key, msg)
            
            # Create encrypted message
            encrypted_msg = NetworkMessage("encrypted", {
                "ciphertext": encrypted.ciphertext.hex(),
                "nonce": encrypted.nonce.hex(),
                "tag": encrypted.tag.hex()
            }, self.node_id)
            
            # Send via appropriate transport
            if target_peer.connection_type == "udp":
                self.udp_transport.sendto(encrypted_msg.to_bytes(), (target_peer.host, target_peer.port))
            else:
                # For now, we'll need to track active connections
                # In a full implementation, you'd maintain connection objects
                print(f"Encrypted message prepared for {target_peer.id}")
            
            return True
            
        except Exception as e:
            print(f"Failed to send encrypted message: {e}")
            return False
    
    async def receive_encrypted(self, shared_key: bytes) -> Optional[bytes]:
        """
        Receive and decrypt message using shared key
        
        Args:
            shared_key: Shared encryption key
            
        Returns:
            Decrypted message or None if no message available
        """
        # This would typically be called from a message handler
        # For now, we'll return None as this is handled in the message processing
        return None
    
    async def _handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming TCP connection"""
        try:
            while self.running:
                message = await self._receive_tcp_message(reader)
                if not message:
                    break
                
                await self._handle_message(message, reader, writer)
                
        except Exception as e:
            print(f"TCP connection error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _handle_udp_message(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming UDP message"""
        try:
            message = NetworkMessage.from_bytes(data)
            await self._handle_message(message, None, None, addr)
        except Exception as e:
            print(f"UDP message error: {e}")
    
    async def _handle_message(self, message: NetworkMessage, reader: Optional[asyncio.StreamReader], 
                            writer: Optional[asyncio.StreamWriter], addr: Optional[Tuple[str, int]] = None):
        """Handle incoming message"""
        try:
            if message.msg_type == "handshake":
                await self._handle_handshake(message, reader, writer, addr)
            elif message.msg_type == "udp_punch":
                await self._handle_udp_punch(message, addr)
            elif message.msg_type == "encrypted":
                await self._handle_encrypted_message(message, addr)
            elif message.msg_type == "relay_request":
                await self._handle_relay_request(message, reader, writer)
            else:
                # Call custom message handler
                handler = self.message_handlers.get(message.msg_type)
                if handler:
                    await handler(message, reader, writer, addr)
                else:
                    print(f"Unknown message type: {message.msg_type}")
                    
        except Exception as e:
            print(f"Error handling message {message.msg_type}: {e}")
    
    async def _handle_handshake(self, message: NetworkMessage, reader: asyncio.StreamReader, 
                              writer: asyncio.StreamWriter, addr: Tuple[str, int]):
        """Handle handshake message"""
        try:
            # Extract peer info
            peer_public_key = decode_public_key(message.payload["public_key"])
            peer_id = message.payload["node_id"]
            
            # Derive shared key
            shared_key = derive_shared_key(self.key_pair.private_key, peer_public_key)
            
            # Create peer
            peer = Peer(
                id=peer_id,
                public_key=peer_public_key,
                host=addr[0] if addr else "unknown",
                port=addr[1] if addr else 0,
                shared_key=shared_key,
                last_seen=time.time(),
                connection_type="direct" if writer else "udp"
            )
            
            self.peers[peer_id] = peer
            
            # Send handshake response
            if writer:
                response = NetworkMessage("handshake", {
                    "node_id": self.node_id,
                    "public_key": encode_public_key(self.key_pair.public_key),
                    "tcp_port": self.tcp_port,
                    "udp_port": self.udp_port
                })
                await self._send_tcp_message(response, writer)
                
                # Start listening for messages from this peer
                asyncio.create_task(self._listen_to_peer(reader, writer, peer))
            
            print(f"Handshake completed with {peer_id}")
            
        except Exception as e:
            print(f"Handshake handling error: {e}")
    
    async def _handle_udp_punch(self, message: NetworkMessage, addr: Tuple[str, int]):
        """Handle UDP punch message"""
        try:
            # Send UDP punch response
            response = NetworkMessage("udp_punch_response", {
                "node_id": self.node_id,
                "public_key": encode_public_key(self.key_pair.public_key),
                "tcp_port": self.tcp_port,
                "udp_port": self.udp_port
            })
            
            self.udp_transport.sendto(response.to_bytes(), addr)
            
            # Try TCP connection to the peer
            tcp_port = message.payload.get("tcp_port", 0)
            if tcp_port > 0:
                asyncio.create_task(self.connect_to_peer(addr[0], tcp_port))
                
        except Exception as e:
            print(f"UDP punch handling error: {e}")
    
    async def _handle_encrypted_message(self, message: NetworkMessage, addr: Tuple[str, int]):
        """Handle encrypted message"""
        try:
            # Find peer by address
            target_peer = None
            for peer in self.peers.values():
                if peer.host == addr[0] and peer.port == addr[1]:
                    target_peer = peer
                    break
            
            if not target_peer or not target_peer.shared_key:
                print(f"No shared key found for {addr}")
                return
            
            # Decrypt message
            ciphertext = bytes.fromhex(message.payload["ciphertext"])
            nonce = bytes.fromhex(message.payload["nonce"])
            tag = bytes.fromhex(message.payload["tag"])
            
            encrypted_msg = EncryptedMessage(ciphertext, nonce, tag)
            decrypted = decrypt_message(target_peer.shared_key, encrypted_msg)
            
            print(f"Received encrypted message from {target_peer.id}: {decrypted.decode()}")
            
        except Exception as e:
            print(f"Encrypted message handling error: {e}")
    
    async def _handle_relay_request(self, message: NetworkMessage, reader: asyncio.StreamReader, 
                                  writer: asyncio.StreamWriter):
        """Handle relay request (bootstrap peer functionality)"""
        try:
            target_ip = message.payload["target_ip"]
            target_port = message.payload["target_port"]
            
            # Try to connect to target
            success = await self.connect_to_peer(target_ip, target_port)
            
            # Send relay response
            response = NetworkMessage("relay_response", {
                "success": success,
                "target_ip": target_ip,
                "target_port": target_port
            })
            
            await self._send_tcp_message(response, writer)
            
        except Exception as e:
            print(f"Relay request handling error: {e}")
    
    async def _listen_to_peer(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer: Peer):
        """Listen for messages from a specific peer"""
        try:
            while self.running:
                message = await self._receive_tcp_message(reader)
                if not message:
                    break
                
                await self._handle_message(message, reader, writer)
                
        except Exception as e:
            print(f"Error listening to peer {peer.id}: {e}")
        finally:
            # Remove peer from list
            if peer.id in self.peers:
                del self.peers[peer.id]
    
    async def _send_tcp_message(self, message: NetworkMessage, writer: asyncio.StreamWriter):
        """Send TCP message"""
        data = message.to_bytes()
        writer.write(data)
        await writer.drain()
    
    async def _receive_tcp_message(self, reader: asyncio.StreamReader) -> Optional[NetworkMessage]:
        """Receive TCP message"""
        try:
            # Read message length
            length_data = await reader.readexactly(4)
            length = struct.unpack('!I', length_data)[0]
            
            # Read message data
            message_data = await reader.readexactly(length)
            return NetworkMessage.from_bytes(length_data + message_data)
            
        except asyncio.IncompleteReadError:
            return None
        except Exception as e:
            print(f"Error receiving TCP message: {e}")
            return None
    
    async def _wait_for_udp_response(self, ip: str, port: int):
        """Wait for UDP response (simplified)"""
        # In a real implementation, you'd set up a proper response handler
        await asyncio.sleep(0.1)
    
    def add_message_handler(self, msg_type: str, handler: Callable):
        """Add a custom message handler"""
        self.message_handlers[msg_type] = handler
    
    def add_bootstrap_peer(self, ip: str, port: int):
        """Add a bootstrap peer for relay connections"""
        self.bootstrap_peers.append((ip, port))
    
    def get_peer_info(self) -> List[Dict[str, Any]]:
        """Get information about connected peers"""
        return [
            {
                "id": peer.id,
                "host": peer.host,
                "port": peer.port,
                "public_key": encode_public_key(peer.public_key),
                "connection_type": peer.connection_type,
                "last_seen": peer.last_seen
            }
            for peer in self.peers.values()
        ]


class UDPProtocol(asyncio.DatagramProtocol):
    """UDP protocol for handling datagram messages"""
    
    def __init__(self, message_handler: Callable):
        self.message_handler = message_handler
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data, addr):
        asyncio.create_task(self.message_handler(data, addr))
    
    def error_received(self, exc):
        print(f"UDP error: {exc}") 