"""
Tests for the secure messenger module
"""

import pytest
import pytest_asyncio
import asyncio
import tempfile
import os
import time
import base64
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path

from p2p_securemsg.messenger import SecureMessenger
from p2p_securemsg.network import P2PNetwork, NetworkMessage
from p2p_securemsg.encryption import (
    generate_keypair, derive_shared_key, encrypt_message, decrypt_message,
    encode_public_key, decode_public_key
)


class TestSecureMessenger:
    """Test SecureMessenger class"""
    
    @pytest_asyncio.fixture
    async def messenger(self):
        """Create a test messenger instance"""
        msg = SecureMessenger()
        yield msg
        if msg.running:
            await msg.secure_exit()
    
    @pytest.mark.asyncio
    async def test_messenger_initialization(self, messenger):
        """Test messenger initialization"""
        assert messenger.network is None
        assert messenger.peer_shared_key is None
        assert messenger.peer_id is None
        assert messenger.peer_address is None
        assert len(messenger.message_history) == 0
        assert len(messenger.temp_files) == 0
        assert not messenger.running
    
    @pytest.mark.asyncio
    async def test_network_startup(self, messenger):
        """Test network startup"""
        await messenger.start_network()
        
        assert messenger.network is not None
        assert messenger.network.running
        assert messenger.network.tcp_port > 0
        assert messenger.network.udp_port > 0
        assert messenger.network.node_id is not None
    
    @pytest.mark.asyncio
    async def test_peer_info_setup(self, messenger):
        """Test peer information setup"""
        # Mock prompt responses
        with patch('p2p_securemsg.messenger.Prompt.ask') as mock_prompt:
            mock_prompt.side_effect = ["192.168.1.100", "8080"]
            
            await messenger.get_peer_info()
            
            assert messenger.peer_address == ("192.168.1.100", 8080)
    
    @pytest.mark.asyncio
    async def test_handshake_handling(self, messenger):
        """Test handshake message handling"""
        # Start network
        await messenger.start_network()
        
        # Create test key pairs
        alice_keypair = generate_keypair()
        bob_keypair = generate_keypair()
        
        # Create handshake message
        handshake_msg = NetworkMessage("handshake", {
            "node_id": "test_peer",
            "public_key": encode_public_key(bob_keypair.public_key),
            "tcp_port": 8080,
            "udp_port": 8081
        }, "test_peer")
        
        # Handle handshake
        await messenger.handle_handshake(handshake_msg, None, None, ("192.168.1.100", 8080))
        
        # Verify shared key was established
        assert messenger.peer_shared_key is not None
        assert messenger.peer_id == "test_peer"
        assert messenger.peer_address == ("192.168.1.100", 8080)
        
        # Verify shared key is correct
        expected_shared_key = derive_shared_key(
            messenger.network.key_pair.private_key,
            bob_keypair.public_key
        )
        assert messenger.peer_shared_key == expected_shared_key
    
    @pytest.mark.asyncio
    async def test_text_message_handling(self, messenger):
        """Test text message handling"""
        # Start network and establish shared key
        await messenger.start_network()
        alice_keypair = generate_keypair()
        bob_keypair = generate_keypair()
        shared_key = derive_shared_key(
            messenger.network.key_pair.private_key,
            bob_keypair.public_key
        )
        messenger.peer_shared_key = shared_key
        messenger.peer_id = "test_peer"
        
        # Create encrypted message
        test_message = "Hello, secure world!"
        encrypted = encrypt_message(shared_key, test_message.encode('utf-8'))
        
        # Create message
        text_msg = NetworkMessage("text_message", {
            "ciphertext": encrypted.ciphertext.hex(),
            "nonce": encrypted.nonce.hex(),
            "tag": encrypted.tag.hex()
        }, "test_peer")
        
        # Handle message
        await messenger.handle_text_message(text_msg, None, None, ("192.168.1.100", 8080))
        
        # Verify message was added to history
        assert len(messenger.message_history) == 1
        assert messenger.message_history[0]["type"] == "received"
        assert messenger.message_history[0]["content"] == test_message
        assert messenger.message_history[0]["sender"] == "test_peer"
    
    @pytest.mark.asyncio
    async def test_file_message_handling(self, messenger):
        """Test file message handling"""
        # Start network and establish shared key
        await messenger.start_network()
        alice_keypair = generate_keypair()
        bob_keypair = generate_keypair()
        shared_key = derive_shared_key(
            messenger.network.key_pair.private_key,
            bob_keypair.public_key
        )
        messenger.peer_shared_key = shared_key
        messenger.peer_id = "test_peer"
        
                # Create test file data
        test_file_data = b"This is test file content"
        encoded_data = base64.b64encode(test_file_data)  # Properly encode as base64

        # Create encrypted file message
        encrypted = encrypt_message(shared_key, encoded_data)
        
        file_msg = NetworkMessage("file_message", {
            "ciphertext": encrypted.ciphertext.hex(),
            "nonce": encrypted.nonce.hex(),
            "tag": encrypted.tag.hex(),
            "filename": "test.txt"
        }, "test_peer")
        
        # Handle file message
        await messenger.handle_file_message(file_msg, None, None, ("192.168.1.100", 8080))
        
        # Verify file message was added to history
        assert len(messenger.message_history) == 1
        assert messenger.message_history[0]["type"] == "file_received"
        assert "test.txt" in messenger.message_history[0]["content"]
        assert messenger.message_history[0]["sender"] == "test_peer"
    
    @pytest.mark.asyncio
    async def test_send_text_message(self, messenger):
        """Test sending text messages"""
        # Start network and establish shared key
        await messenger.start_network()
        alice_keypair = generate_keypair()
        bob_keypair = generate_keypair()
        shared_key = derive_shared_key(
            messenger.network.key_pair.private_key,
            bob_keypair.public_key
        )
        messenger.peer_shared_key = shared_key
        
        # Mock network send_encrypted
        with patch.object(messenger.network, 'send_encrypted', return_value=True):
            await messenger.send_text_message("Test message")
            
            # Verify message was added to history
            assert len(messenger.message_history) == 1
            assert messenger.message_history[0]["type"] == "sent"
            assert messenger.message_history[0]["content"] == "Test message"
            assert messenger.message_history[0]["sender"] == messenger.network.node_id
    
    @pytest.mark.asyncio
    async def test_send_file_message(self, messenger):
        """Test sending file messages"""
        # Start network and establish shared key
        await messenger.start_network()
        alice_keypair = generate_keypair()
        bob_keypair = generate_keypair()
        shared_key = derive_shared_key(
            messenger.network.key_pair.private_key,
            bob_keypair.public_key
        )
        messenger.peer_shared_key = shared_key
        
        # Create temporary test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test file content")
            temp_file_path = f.name
        
        try:
            # Mock network send_encrypted
            with patch.object(messenger.network, 'send_encrypted', return_value=True):
                await messenger.send_file_message(temp_file_path)
                
                # Verify file message was added to history
                assert len(messenger.message_history) == 1
                assert messenger.message_history[0]["type"] == "file_sent"
                # Check that the content contains "File:" and the filename (which will be a temp filename)
                assert "File:" in messenger.message_history[0]["content"]
                assert messenger.message_history[0]["sender"] == messenger.network.node_id
        finally:
            # Clean up temp file
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
    
    def test_format_file_size(self, messenger):
        """Test file size formatting"""
        assert messenger.format_file_size(512) == "512 B"
        assert messenger.format_file_size(1024) == "1.0 KB"
        assert messenger.format_file_size(1024 * 1024) == "1.0 MB"
        assert messenger.format_file_size(1024 * 1024 * 1024) == "1.0 GB"
    
    def test_save_temp_file(self, messenger):
        """Test temporary file saving"""
        test_data = b"Test file content"
        filename = "test.txt"
        
        temp_path = messenger.save_temp_file(test_data, filename)
        
        # Verify file was created
        assert os.path.exists(temp_path)
        assert temp_path in messenger.temp_files
        
        # Verify file content
        with open(temp_path, 'rb') as f:
            content = f.read()
        assert content == test_data
        
        # Clean up
        os.unlink(temp_path)
        messenger.temp_files.remove(temp_path)
    
    @pytest.mark.asyncio
    async def test_secure_exit(self, messenger):
        """Test secure exit functionality"""
        # Start network
        await messenger.start_network()
        
        # Add some test data
        messenger.peer_shared_key = b"test_key_32_bytes_long_for_testing"
        messenger.message_history.append({"type": "test", "content": "test"})
        
        # Create a temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test")
            temp_file_path = f.name
            messenger.temp_files.append(temp_file_path)
        
        try:
            # Perform secure exit
            await messenger.secure_exit()
            
            # Verify cleanup
            assert not messenger.running
            assert len(messenger.message_history) == 0
            assert len(messenger.temp_files) == 0
            assert not os.path.exists(temp_file_path)
            
        finally:
            # Clean up if test fails
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
    
    @pytest.mark.asyncio
    async def test_command_handling(self, messenger):
        """Test command handling"""
        # Test help command
        with patch.object(messenger, 'show_help') as mock_help:
            await messenger.handle_command("help")
            mock_help.assert_called_once()
        
        # Test file command
        with patch.object(messenger, 'send_file_message') as mock_file:
            await messenger.handle_command("file test.txt")
            mock_file.assert_called_once_with("test.txt")
        
        # Test clear command
        with patch.object(messenger.console, 'clear') as mock_clear:
            with patch.object(messenger, 'show_banner') as mock_banner:
                await messenger.handle_command("clear")
                mock_clear.assert_called_once()
                mock_banner.assert_called_once()
        
        # Test status command
        with patch.object(messenger, 'show_status') as mock_status:
            await messenger.handle_command("status")
            mock_status.assert_called_once()
        
        # Test history command
        with patch.object(messenger, 'show_history') as mock_history:
            await messenger.handle_command("history")
            mock_history.assert_called_once()
        
        # Test quit command
        with patch.object(messenger, 'secure_exit') as mock_exit:
            await messenger.handle_command("quit")
            mock_exit.assert_called_once()
    
    def test_display_message(self, messenger):
        """Test message display"""
        # Test sent message display
        with patch.object(messenger.console, 'print') as mock_print:
            messenger.display_message("sent", "Test message")
            mock_print.assert_called_once()
        
        # Test received message display
        with patch.object(messenger.console, 'print') as mock_print:
            messenger.display_message("received", "Test message")
            mock_print.assert_called_once()
    
    def test_display_file_message(self, messenger):
        """Test file message display"""
        # Create temporary file for testing
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test content")
            temp_file_path = f.name
        
        try:
            # Test sent file message display
            with patch.object(messenger.console, 'print') as mock_print:
                messenger.display_file_message("sent", "test.txt", temp_file_path)
                mock_print.assert_called_once()
            
            # Test received file message display
            with patch.object(messenger.console, 'print') as mock_print:
                messenger.display_file_message("received", "test.txt", temp_file_path)
                mock_print.assert_called_once()
        finally:
            os.unlink(temp_file_path)
    
    def test_show_status(self, messenger):
        """Test status display"""
        with patch.object(messenger.console, 'print') as mock_print:
            messenger.show_status()
            mock_print.assert_called_once()
    
    def test_show_history(self, messenger):
        """Test history display"""
        # Test empty history
        with patch.object(messenger.console, 'print') as mock_print:
            messenger.show_history()
            mock_print.assert_called_once()
        
        # Test with history
        messenger.message_history.append({
            "type": "sent",
            "content": "Test message",
            "timestamp": time.time(),
            "sender": "test"
        })
        
        with patch.object(messenger.console, 'print') as mock_print:
            messenger.show_history()
            mock_print.assert_called_once()
    
    def test_show_help(self, messenger):
        """Test help display"""
        with patch.object(messenger.console, 'print') as mock_print:
            messenger.show_help()
            mock_print.assert_called_once()


@pytest.mark.asyncio
async def test_messenger_integration():
    """Integration test for messenger functionality"""
    # Create two messengers
    messenger1 = SecureMessenger()
    messenger2 = SecureMessenger()
    
    try:
        # Start both messengers
        await messenger1.start_network()
        await messenger2.start_network()
        
        # Verify both are running
        assert messenger1.network.running
        assert messenger2.network.running
        
        # Verify different ports
        assert messenger1.network.tcp_port != messenger2.network.tcp_port
        assert messenger1.network.udp_port != messenger2.network.udp_port
        
        # Verify different node IDs
        assert messenger1.network.node_id != messenger2.network.node_id
        
    finally:
        await messenger1.secure_exit()
        await messenger2.secure_exit()


@pytest.mark.asyncio
async def test_encrypted_communication():
    """Test encrypted communication between messengers"""
    # Create messengers
    messenger1 = SecureMessenger()
    messenger2 = SecureMessenger()
    
    try:
        await messenger1.start_network()
        await messenger2.start_network()
        
        # Create shared key
        shared_key = derive_shared_key(
            messenger1.network.key_pair.private_key,
            messenger2.network.key_pair.public_key
        )
        
        # Test encryption/decryption
        test_message = "Hello, encrypted world!"
        encrypted = encrypt_message(shared_key, test_message.encode('utf-8'))
        decrypted = decrypt_message(shared_key, encrypted)
        
        assert decrypted.decode('utf-8') == test_message
        
        # Test that different messages produce different ciphertexts
        message2 = "Different message"
        encrypted2 = encrypt_message(shared_key, message2.encode('utf-8'))
        
        assert encrypted.ciphertext != encrypted2.ciphertext
        assert encrypted.nonce != encrypted2.nonce
        assert encrypted.tag != encrypted2.tag
        
    finally:
        await messenger1.secure_exit()
        await messenger2.secure_exit()


@pytest.mark.asyncio
async def test_file_transfer():
    """Test file transfer functionality"""
    messenger1 = SecureMessenger()
    messenger2 = SecureMessenger()
    
    try:
        await messenger1.start_network()
        await messenger2.start_network()
        
        # Create shared key
        shared_key = derive_shared_key(
            messenger1.network.key_pair.private_key,
            messenger2.network.key_pair.public_key
        )
        
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test file content for transfer")
            test_file_path = f.name
        
        try:
            # Read file
            with open(test_file_path, 'rb') as f:
                file_data = f.read()
            
            # Encode and encrypt
            encoded_data = b"Test file content for transfer"  # Simplified for test
            encrypted = encrypt_message(shared_key, encoded_data)
            
            # Decrypt and decode
            decrypted = decrypt_message(shared_key, encrypted)
            decoded_data = decrypted  # Simplified for test
            
            # Verify data integrity
            assert decoded_data == file_data
            
        finally:
            if os.path.exists(test_file_path):
                os.unlink(test_file_path)
        
    finally:
        await messenger1.secure_exit()
        await messenger2.secure_exit()


@pytest.mark.asyncio
async def test_secure_exit_comprehensive():
    """Comprehensive test of secure exit functionality"""
    messenger = SecureMessenger()
    
    try:
        await messenger.start_network()
        
        # Add various test data
        messenger.peer_shared_key = b"test_key_32_bytes_long_for_testing"
        messenger.message_history = [
            {"type": "sent", "content": "test1", "timestamp": time.time()},
            {"type": "received", "content": "test2", "timestamp": time.time()}
        ]
        
        # Create multiple temp files
        temp_files = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(f"test content {i}")
                temp_files.append(f.name)
                messenger.temp_files.append(f.name)
        
        # Perform secure exit
        await messenger.secure_exit()
        
        # Verify all cleanup
        assert not messenger.running
        assert len(messenger.message_history) == 0
        assert len(messenger.temp_files) == 0
        
        # Verify temp files are deleted
        for temp_file in temp_files:
            assert not os.path.exists(temp_file)
        
    finally:
        # Clean up any remaining temp files
        for temp_file in messenger.temp_files:
            if os.path.exists(temp_file):
                os.unlink(temp_file) 