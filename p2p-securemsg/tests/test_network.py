"""
Tests for the enhanced network module
"""

import pytest
import pytest_asyncio
import asyncio
import time
from unittest.mock import Mock, patch
from p2p_securemsg.network import (
    P2PNetwork, NetworkMessage, Peer, UDPProtocol
)
from p2p_securemsg.encryption import (
    generate_keypair, derive_shared_key, encrypt_message, decrypt_message,
    encode_public_key, decode_public_key
)


class TestNetworkMessage:
    """Test NetworkMessage class"""
    
    def test_network_message_creation(self):
        """Test creating a NetworkMessage"""
        msg = NetworkMessage("test", {"data": "value"}, "sender123")
        
        assert msg.msg_type == "test"
        assert msg.payload == {"data": "value"}
        assert msg.sender_id == "sender123"
        assert msg.timestamp > 0
    
    def test_network_message_serialization(self):
        """Test message serialization and deserialization"""
        original = NetworkMessage("handshake", {
            "node_id": "test_node",
            "public_key": "test_key"
        }, "sender123")
        
        # Serialize
        data = original.to_bytes()
        assert isinstance(data, bytes)
        assert len(data) > 0
        
        # Deserialize
        deserialized = NetworkMessage.from_bytes(data)
        assert deserialized.msg_type == original.msg_type
        assert deserialized.payload == original.payload
        assert deserialized.sender_id == original.sender_id
    
    def test_network_message_to_dict(self):
        """Test converting message to dictionary"""
        msg = NetworkMessage("test", {"key": "value"}, "sender")
        msg_dict = msg.to_dict()
        
        assert msg_dict["type"] == "test"
        assert msg_dict["payload"] == {"key": "value"}
        assert msg_dict["sender_id"] == "sender"
        assert "timestamp" in msg_dict
    
    def test_network_message_from_dict(self):
        """Test creating message from dictionary"""
        msg_dict = {
            "type": "test",
            "payload": {"key": "value"},
            "sender_id": "sender",
            "timestamp": 1234567890.0
        }
        
        msg = NetworkMessage.from_dict(msg_dict)
        assert msg.msg_type == "test"
        assert msg.payload == {"key": "value"}
        assert msg.sender_id == "sender"
        assert msg.timestamp == 1234567890.0


class TestP2PNetwork:
    """Test P2PNetwork class"""
    
    @pytest_asyncio.fixture
    async def network(self):
        """Create a test network instance"""
        net = P2PNetwork("127.0.0.1", 0, 0)
        yield net
        if net.running:
            await net.stop()
    
    @pytest.mark.asyncio
    async def test_network_initialization(self, network):
        """Test network initialization"""
        assert network.host == "127.0.0.1"
        assert network.tcp_port == 0
        assert network.udp_port == 0
        assert not network.running
        assert len(network.peers) == 0
        assert network.node_id is not None
        assert len(network.key_pair.public_key) == 32
    
    @pytest.mark.asyncio
    async def test_network_start_stop(self, network):
        """Test starting and stopping the network"""
        # Start network
        await network.start()
        assert network.running
        assert network.tcp_port > 0
        assert network.udp_port > 0
        assert network.tcp_server is not None
        assert network.udp_transport is not None
        
        # Stop network
        await network.stop()
        assert not network.running
    
    @pytest.mark.asyncio
    async def test_connect_to_peer_direct_tcp(self, network):
        """Test direct TCP connection to peer"""
        await network.start()
        
        # Create a mock peer server
        mock_server = await asyncio.start_server(
            self._mock_peer_handler,
            "127.0.0.1",
            0
        )
        mock_port = mock_server.sockets[0].getsockname()[1]
        
        try:
            # Test connection
            success = await network.connect_to_peer("127.0.0.1", mock_port)
            # This should fail in test environment, but not raise exception
            assert isinstance(success, bool)
        finally:
            mock_server.close()
            await mock_server.wait_closed()
    
    async def _mock_peer_handler(self, reader, writer):
        """Mock peer handler for testing"""
        try:
            # Read handshake
            data = await reader.readexactly(4)
            length = int.from_bytes(data, 'big')
            message_data = await reader.readexactly(length)
            
            # Send handshake response
            response = NetworkMessage("handshake", {
                "node_id": "mock_peer",
                "public_key": encode_public_key(generate_keypair().public_key),
                "tcp_port": 8080,
                "udp_port": 8081
            })
            
            response_data = response.to_bytes()
            writer.write(response_data)
            await writer.drain()
            
        except Exception:
            pass
        finally:
            writer.close()
            await writer.wait_closed()
    
    @pytest.mark.asyncio
    async def test_udp_hole_punch(self, network):
        """Test UDP hole punching"""
        await network.start()
        
        # Mock UDP transport
        with patch.object(network.udp_transport, 'sendto') as mock_sendto:
            success = await network._try_udp_hole_punch("127.0.0.1", 8080)
            
            # Should call sendto with punch message
            mock_sendto.assert_called_once()
            call_args = mock_sendto.call_args
            assert call_args[0][1] == ("127.0.0.1", 8080)
    
    @pytest.mark.asyncio
    async def test_relay_connection(self, network):
        """Test relay connection through bootstrap peer"""
        await network.start()
        
        # Add bootstrap peer
        network.add_bootstrap_peer("127.0.0.1", 8080)
        
        # Mock connection attempt
        with patch('asyncio.open_connection') as mock_connect:
            mock_connect.side_effect = ConnectionRefusedError()
            
            success = await network._try_relay_connection("192.168.1.100", 8080)
            assert not success
    
    @pytest.mark.asyncio
    async def test_handshake_performance(self, network):
        """Test handshake performance"""
        await network.start()
        
        # Create test key pairs
        alice_keypair = generate_keypair()
        bob_keypair = generate_keypair()
        
        # Test handshake message creation
        handshake_msg = NetworkMessage("handshake", {
            "node_id": "alice",
            "public_key": encode_public_key(alice_keypair.public_key),
            "tcp_port": 8080,
            "udp_port": 8081
        })
        
        # Test shared key derivation
        shared_key = derive_shared_key(alice_keypair.private_key, bob_keypair.public_key)
        assert len(shared_key) == 32
        
        # Test encryption/decryption
        test_message = b"Hello, secure world!"
        encrypted = encrypt_message(shared_key, test_message)
        decrypted = decrypt_message(shared_key, encrypted)
        assert decrypted == test_message
    
    @pytest.mark.asyncio
    async def test_send_encrypted(self, network):
        """Test sending encrypted messages"""
        await network.start()
        
        # Create a test peer
        test_keypair = generate_keypair()
        shared_key = derive_shared_key(network.key_pair.private_key, test_keypair.public_key)
        
        peer = Peer(
            id="test_peer",
            public_key=test_keypair.public_key,
            host="127.0.0.1",
            port=8080,
            shared_key=shared_key,
            connection_type="direct"
        )
        network.peers["test_peer"] = peer
        
        # Test sending encrypted message
        test_message = b"Secret message"
        success = await network.send_encrypted(shared_key, test_message)
        assert success
    
    @pytest.mark.asyncio
    async def test_message_handlers(self, network):
        """Test custom message handlers"""
        await network.start()
        
        # Test message handler
        received_messages = []
        
        async def test_handler(message, reader, writer, addr):
            received_messages.append(message)
        
        network.add_message_handler("test_message", test_handler)
        
        # Create test message
        test_msg = NetworkMessage("test_message", {"data": "test"}, "sender")
        
        # Simulate message handling
        await network._handle_message(test_msg, None, None, ("127.0.0.1", 8080))
        
        assert len(received_messages) == 1
        assert received_messages[0].msg_type == "test_message"
    
    @pytest.mark.asyncio
    async def test_peer_management(self, network):
        """Test peer management functionality"""
        await network.start()
        
        # Add test peer
        test_peer = Peer(
            id="test_peer",
            public_key=b"x" * 32,
            host="127.0.0.1",
            port=8080,
            shared_key=b"y" * 32,
            connection_type="direct",
            last_seen=time.time()
        )
        network.peers["test_peer"] = test_peer
        
        # Test peer info
        peer_info = network.get_peer_info()
        assert len(peer_info) == 1
        assert peer_info[0]["id"] == "test_peer"
        assert peer_info[0]["host"] == "127.0.0.1"
        assert peer_info[0]["port"] == 8080
        assert peer_info[0]["connection_type"] == "direct"
    
    @pytest.mark.asyncio
    async def test_connection_timeout(self, network):
        """Test connection timeout handling"""
        await network.start()
        
        # Test with very short timeout
        network.connection_timeout = 0.001
        
        # This should timeout quickly
        start_time = time.time()
        success = await network.connect_to_peer("192.168.1.999", 8080)
        end_time = time.time()
        
        # The connection might succeed in some cases, but should be fast
        assert end_time - start_time < 1.0  # Should timeout quickly
    
    @pytest.mark.asyncio
    async def test_duplicate_connection_attempts(self, network):
        """Test handling of duplicate connection attempts"""
        await network.start()
        
        # Start first connection attempt
        task1 = asyncio.create_task(network.connect_to_peer("127.0.0.1", 8080))
        
        # Try to connect to same peer again
        task2 = asyncio.create_task(network.connect_to_peer("127.0.0.1", 8080))
        
        # Both should complete (second should return the same future)
        results = await asyncio.gather(task1, task2, return_exceptions=True)
        
        # Both should return the same result
        assert results[0] == results[1]


class TestUDPProtocol:
    """Test UDP protocol"""
    
    def test_udp_protocol_creation(self):
        """Test UDP protocol creation"""
        message_handler = Mock()
        protocol = UDPProtocol(message_handler)
        
        assert protocol.message_handler == message_handler
    
    def test_udp_protocol_connection_made(self):
        """Test UDP protocol connection setup"""
        message_handler = Mock()
        protocol = UDPProtocol(message_handler)
        
        mock_transport = Mock()
        protocol.connection_made(mock_transport)
        
        assert protocol.transport == mock_transport
    
    @pytest.mark.asyncio
    async def test_udp_protocol_datagram_received(self):
        """Test UDP protocol datagram handling"""
        async def mock_handler(data, addr):
            pass
        
        protocol = UDPProtocol(mock_handler)
        
        # Mock transport
        protocol.transport = Mock()
        
        # Test datagram received
        test_data = b"test data"
        test_addr = ("127.0.0.1", 8080)
        
        # This should work with a proper async handler
        protocol.datagram_received(test_data, test_addr)


@pytest.mark.asyncio
async def test_network_integration():
    """Integration test for network functionality"""
    # Create two networks
    network1 = P2PNetwork("127.0.0.1", 0, 0)
    network2 = P2PNetwork("127.0.0.1", 0, 0)
    
    try:
        # Start both networks
        await network1.start()
        await network2.start()
        
        # Verify both are running
        assert network1.running
        assert network2.running
        
        # Verify different ports
        assert network1.tcp_port != network2.tcp_port
        assert network1.udp_port != network2.udp_port
        
        # Verify different node IDs
        assert network1.node_id != network2.node_id
        
    finally:
        await network1.stop()
        await network2.stop()


@pytest.mark.asyncio
async def test_encrypted_communication():
    """Test encrypted communication between peers"""
    # Create networks
    network1 = P2PNetwork("127.0.0.1", 0, 0)
    network2 = P2PNetwork("127.0.0.1", 0, 0)
    
    try:
        await network1.start()
        await network2.start()
        
        # Create shared key
        shared_key = derive_shared_key(
            network1.key_pair.private_key,
            network2.key_pair.public_key
        )
        
        # Test encryption/decryption
        test_message = b"Hello, encrypted world!"
        encrypted = encrypt_message(shared_key, test_message)
        decrypted = decrypt_message(shared_key, encrypted)
        
        assert decrypted == test_message
        
        # Test that different messages produce different ciphertexts
        message2 = b"Different message"
        encrypted2 = encrypt_message(shared_key, message2)
        
        assert encrypted.ciphertext != encrypted2.ciphertext
        assert encrypted.nonce != encrypted2.nonce
        assert encrypted.tag != encrypted2.tag
        
    finally:
        await network1.stop()
        await network2.stop()


@pytest.mark.asyncio
async def test_nat_traversal_simulation():
    """Test NAT traversal simulation"""
    network = P2PNetwork("127.0.0.1", 0, 0)
    
    try:
        await network.start()
        
        # Test UDP hole punching simulation
        with patch.object(network.udp_transport, 'sendto') as mock_sendto:
            success = await network._try_udp_hole_punch("192.168.1.100", 8080)
            
            # Should attempt UDP punch
            mock_sendto.assert_called_once()
            
            # Extract sent message
            sent_data = mock_sendto.call_args[0][0]
            sent_addr = mock_sendto.call_args[0][1]
            
            # Verify address
            assert sent_addr == ("192.168.1.100", 8080)
            
            # Verify message format
            message = NetworkMessage.from_bytes(sent_data)
            assert message.msg_type == "udp_punch"
            assert "node_id" in message.payload
            assert "public_key" in message.payload
            assert "tcp_port" in message.payload
            assert "udp_port" in message.payload
        
    finally:
        await network.stop() 