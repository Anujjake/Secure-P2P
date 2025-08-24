"""
Secure Messenger module for P2P Secure Messaging
Provides interactive CLI with encrypted messaging and file transfer capabilities
"""

import asyncio
import os
import base64
import tempfile
import shutil
import time
from typing import Optional, Dict, List
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.table import Table
from rich.align import Align
from rich import box
from rich.live import Live
from rich.layout import Layout
from rich.status import Status
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax

from .network import P2PNetwork, NetworkMessage
from .encryption import (
    generate_keypair, derive_shared_key, encrypt_message, decrypt_message,
    encode_public_key, decode_public_key, secure_delete_keypair
)


class SecureMessenger:
    """Interactive secure messenger with CLI interface"""
    
    def __init__(self):
        self.console = Console()
        self.network: Optional[P2PNetwork] = None
        self.peer_shared_key: Optional[bytes] = None
        self.peer_id: Optional[str] = None
        self.peer_address: Optional[tuple] = None
        self.message_history: List[Dict] = []
        self.temp_files: List[str] = []
        self.running = False
        
        # Set up message handlers
        self.setup_message_handlers()
    
    def setup_message_handlers(self):
        """Set up message handlers for the network"""
        if not self.network:
            return
        
        self.network.add_message_handler("text_message", self.handle_text_message)
        self.network.add_message_handler("file_message", self.handle_file_message)
        self.network.add_message_handler("handshake", self.handle_handshake)
    
    async def handle_handshake(self, message: NetworkMessage, reader, writer, addr=None):
        """Handle handshake messages"""
        try:
            if "public_key" in message.payload:
                peer_public_key = decode_public_key(message.payload["public_key"])
                peer_id = message.payload["node_id"]
                
                # Derive shared key
                self.peer_shared_key = derive_shared_key(
                    self.network.key_pair.private_key, 
                    peer_public_key
                )
                self.peer_id = peer_id
                self.peer_address = addr
                
                self.console.print(f"[green]✓ Secure connection established with {peer_id}[/green]")
                
        except Exception as e:
            self.console.print(f"[red]Error during handshake: {e}[/red]")
    
    async def handle_text_message(self, message: NetworkMessage, reader, writer, addr=None):
        """Handle incoming text messages"""
        try:
            if not self.peer_shared_key:
                self.console.print("[red]No shared key established[/red]")
                return
            
            # Decrypt message
            ciphertext = bytes.fromhex(message.payload["ciphertext"])
            nonce = bytes.fromhex(message.payload["nonce"])
            tag = bytes.fromhex(message.payload["tag"])
            
            from .encryption import EncryptedMessage
            encrypted_msg = EncryptedMessage(ciphertext, nonce, tag)
            decrypted = decrypt_message(self.peer_shared_key, encrypted_msg)
            
            # Add to history
            self.message_history.append({
                "type": "received",
                "content": decrypted.decode('utf-8', errors='ignore'),
                "timestamp": time.time(),
                "sender": self.peer_id or "Unknown"
            })
            
            # Display message
            self.display_message("received", decrypted.decode('utf-8', errors='ignore'))
            
        except Exception as e:
            self.console.print(f"[red]Error decrypting message: {e}[/red]")
    
    async def handle_file_message(self, message: NetworkMessage, reader, writer, addr=None):
        """Handle incoming file messages"""
        try:
            if not self.peer_shared_key:
                self.console.print("[red]No shared key established[/red]")
                return
            
            # Decrypt file data
            ciphertext = bytes.fromhex(message.payload["ciphertext"])
            nonce = bytes.fromhex(message.payload["nonce"])
            tag = bytes.fromhex(message.payload["tag"])
            
            from .encryption import EncryptedMessage
            encrypted_msg = EncryptedMessage(ciphertext, nonce, tag)
            decrypted = decrypt_message(self.peer_shared_key, encrypted_msg)
            
            # Decode base64
            file_data = base64.b64decode(decrypted)
            filename = message.payload.get("filename", "received_file")
            
            # Save to temp file
            temp_path = self.save_temp_file(file_data, filename)
            
            # Add to history
            self.message_history.append({
                "type": "file_received",
                "content": f"File: {filename}",
                "timestamp": time.time(),
                "sender": self.peer_id or "Unknown",
                "file_path": temp_path
            })
            
            # Display file message
            self.display_file_message("received", filename, temp_path)
            
        except Exception as e:
            self.console.print(f"[red]Error handling file message: {e}[/red]")
    
    def display_message(self, direction: str, content: str):
        """Display a message in the chat interface"""
        timestamp = time.strftime("%H:%M:%S")
        
        if direction == "sent":
            panel = Panel(
                f"[cyan]{content}[/cyan]",
                title=f"[green]You ({timestamp})[/green]",
                border_style="green",
                box=box.ROUNDED
            )
        else:
            panel = Panel(
                f"[white]{content}[/white]",
                title=f"[blue]{self.peer_id or 'Peer'} ({timestamp})[/blue]",
                border_style="blue",
                box=box.ROUNDED
            )
        
        self.console.print(panel)
    
    def display_file_message(self, direction: str, filename: str, file_path: str):
        """Display a file message in the chat interface"""
        timestamp = time.strftime("%H:%M:%S")
        file_size = os.path.getsize(file_path)
        
        if direction == "sent":
            panel = Panel(
                f"[cyan]📎 {filename} ({self.format_file_size(file_size)})[/cyan]",
                title=f"[green]You ({timestamp})[/green]",
                border_style="green",
                box=box.ROUNDED
            )
        else:
            panel = Panel(
                f"[white]📎 {filename} ({self.format_file_size(file_size)}) - Saved to: {file_path}[/white]",
                title=f"[blue]{self.peer_id or 'Peer'} ({timestamp})[/blue]",
                border_style="blue",
                box=box.ROUNDED
            )
        
        self.console.print(panel)
    
    def format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    
    def save_temp_file(self, file_data: bytes, filename: str) -> str:
        """Save file data to temporary file"""
        # Create temp directory if it doesn't exist
        temp_dir = Path(tempfile.gettempdir()) / "p2p_securemsg"
        temp_dir.mkdir(exist_ok=True)
        
        # Generate unique filename
        base_name = Path(filename).stem
        extension = Path(filename).suffix
        counter = 1
        
        while True:
            if counter == 1:
                temp_filename = f"{base_name}{extension}"
            else:
                temp_filename = f"{base_name}_{counter}{extension}"
            
            temp_path = temp_dir / temp_filename
            if not temp_path.exists():
                break
            counter += 1
        
        # Write file
        with open(temp_path, 'wb') as f:
            f.write(file_data)
        
        self.temp_files.append(str(temp_path))
        return str(temp_path)
    
    async def start(self):
        """Start the secure messenger"""
        self.console.clear()
        self.show_banner()
        
        # Start network
        await self.start_network()
        
        # Get peer information
        await self.get_peer_info()
        
        # Establish secure connection
        await self.establish_connection()
        
        # Start interactive chat
        await self.run_chat()
    
    def show_banner(self):
        """Display the messenger banner"""
        banner = Text("🔐 Secure P2P Messenger", style="bold blue")
        subtitle = Text("End-to-end encrypted messaging with file transfer", style="italic")
        
        panel = Panel(
            Align.center(banner + "\n" + subtitle),
            border_style="blue",
            box=box.DOUBLE
        )
        self.console.print(panel)
    
    async def start_network(self):
        """Start the P2P network"""
        with Status("[bold blue]Starting secure network...", console=self.console):
            self.network = P2PNetwork("127.0.0.1", 0, 0)
            await self.network.start()
            self.setup_message_handlers()
        
        self.console.print(f"[green]✓ Network started on TCP {self.network.tcp_port}, UDP {self.network.udp_port}[/green]")
        self.console.print(f"[blue]Your Node ID: {self.network.node_id}[/blue]")
        self.console.print(f"[blue]Your Public Key: {encode_public_key(self.network.key_pair.public_key)[:32]}...[/blue]")
    
    async def get_peer_info(self):
        """Get peer connection information from user"""
        self.console.print("\n[bold yellow]Peer Connection Setup[/bold yellow]")
        
        # Get peer IP and port
        peer_ip = Prompt.ask("Enter peer IP address", default="127.0.0.1")
        peer_port = int(Prompt.ask("Enter peer port", default="8080"))
        
        self.peer_address = (peer_ip, peer_port)
        
        self.console.print(f"[blue]Attempting to connect to {peer_ip}:{peer_port}...[/blue]")
    
    async def establish_connection(self):
        """Establish secure connection with peer"""
        with Status("[bold blue]Establishing secure connection...", console=self.console):
            success = await self.network.connect_to_peer(self.peer_address[0], self.peer_address[1])
            
            if not success:
                self.console.print("[red]✗ Failed to establish connection[/red]")
                self.console.print("[yellow]Make sure the peer is running and accessible[/yellow]")
                return False
            
            # Wait for handshake to complete
            await asyncio.sleep(2)
            
            if not self.peer_shared_key:
                self.console.print("[red]✗ Failed to establish shared key[/red]")
                return False
        
        self.console.print("[green]✓ Secure connection established![/green]")
        return True
    
    async def run_chat(self):
        """Run the interactive chat interface"""
        self.running = True
        self.console.print("\n[bold green]Chat started! Type 'help' for commands.[/bold green]")
        self.console.print("[dim]Press Ctrl+C to exit securely[/dim]\n")
        
        while self.running:
            try:
                # Get user input
                user_input = Prompt.ask(f"[bold cyan]{self.network.node_id}[/bold cyan]")
                
                if not user_input.strip():
                    continue
                
                # Parse command
                if user_input.startswith('/'):
                    await self.handle_command(user_input[1:])
                else:
                    await self.send_text_message(user_input)
                    
            except KeyboardInterrupt:
                await self.secure_exit()
                break
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
    
    async def handle_command(self, command: str):
        """Handle chat commands"""
        parts = command.split()
        cmd = parts[0].lower()
        
        if cmd == "help":
            self.show_help()
        elif cmd == "file":
            if len(parts) < 2:
                self.console.print("[red]Usage: /file <filepath>[/red]")
            else:
                filepath = " ".join(parts[1:])
                await self.send_file_message(filepath)
        elif cmd == "clear":
            self.console.clear()
            self.show_banner()
        elif cmd == "status":
            self.show_status()
        elif cmd == "history":
            self.show_history()
        elif cmd == "quit":
            await self.secure_exit()
        else:
            self.console.print(f"[red]Unknown command: {cmd}[/red]")
            self.console.print("Type /help for available commands")
    
    def show_help(self):
        """Show help information"""
        help_text = """
[bold]Available Commands:[/bold]

[green]/help[/green] - Show this help
[green]/file <filepath>[/green] - Send a file
[green]/clear[/green] - Clear the screen
[green]/status[/green] - Show connection status
[green]/history[/green] - Show message history
[green]/quit[/green] - Exit securely

[bold]Examples:[/bold]
  /file /path/to/document.pdf
  /file C:\\Users\\User\\Pictures\\photo.jpg
        """
        
        panel = Panel(help_text, title="Help", border_style="green")
        self.console.print(panel)
    
    def show_status(self):
        """Show connection status"""
        status_table = Table(title="Connection Status", border_style="blue")
        status_table.add_column("Property", style="cyan")
        status_table.add_column("Value", style="white")
        
        network_status = "Running" if self.network and self.network.running else "Stopped"
        connected_peers = str(len(self.network.peers)) if self.network else "0"
        
        status_table.add_row("Network Status", network_status)
        status_table.add_row("Connected Peers", connected_peers)
        status_table.add_row("Secure Connection", "✓ Established" if self.peer_shared_key else "✗ Not established")
        status_table.add_row("Peer ID", self.peer_id or "Unknown")
        status_table.add_row("Peer Address", f"{self.peer_address[0]}:{self.peer_address[1]}" if self.peer_address else "Unknown")
        status_table.add_row("Messages Sent", str(len([m for m in self.message_history if m["type"] == "sent"])))
        status_table.add_row("Messages Received", str(len([m for m in self.message_history if m["type"] == "received"])))
        
        self.console.print(status_table)
    
    def show_history(self):
        """Show message history"""
        if not self.message_history:
            self.console.print("[yellow]No messages in history[/yellow]")
            return
        
        history_table = Table(title="Message History", border_style="green")
        history_table.add_column("Time", style="cyan")
        history_table.add_column("Type", style="yellow")
        history_table.add_column("Content", style="white")
        
        for msg in self.message_history[-20:]:  # Show last 20 messages
            timestamp = time.strftime("%H:%M:%S", time.localtime(msg["timestamp"]))
            msg_type = "📤" if msg["type"] == "sent" else "📥"
            content = msg["content"][:50] + "..." if len(msg["content"]) > 50 else msg["content"]
            
            history_table.add_row(timestamp, msg_type, content)
        
        self.console.print(history_table)
    
    async def send_text_message(self, text: str):
        """Send a text message"""
        if not self.peer_shared_key:
            self.console.print("[red]No secure connection established[/red]")
            return
        
        try:
            # Encrypt message
            encrypted = encrypt_message(self.peer_shared_key, text.encode('utf-8'))
            
            # Create message
            message = NetworkMessage("text_message", {
                "ciphertext": encrypted.ciphertext.hex(),
                "nonce": encrypted.nonce.hex(),
                "tag": encrypted.tag.hex()
            }, self.network.node_id)
            
            # Send message
            success = await self.network.send_encrypted(self.peer_shared_key, text.encode('utf-8'))
            
            if success:
                # Add to history
                self.message_history.append({
                    "type": "sent",
                    "content": text,
                    "timestamp": time.time(),
                    "sender": self.network.node_id
                })
                
                # Display message
                self.display_message("sent", text)
            else:
                self.console.print("[red]Failed to send message[/red]")
                
        except Exception as e:
            self.console.print(f"[red]Error sending message: {e}[/red]")
    
    async def send_file_message(self, filepath: str):
        """Send a file message"""
        if not self.peer_shared_key:
            self.console.print("[red]No secure connection established[/red]")
            return
        
        if not os.path.exists(filepath):
            self.console.print(f"[red]File not found: {filepath}[/red]")
            return
        
        try:
            with Status(f"[bold blue]Reading file {os.path.basename(filepath)}...", console=self.console):
                # Read file
                with open(filepath, 'rb') as f:
                    file_data = f.read()
                
                # Encode as base64
                encoded_data = base64.b64encode(file_data)
                
                # Encrypt file data
                encrypted = encrypt_message(self.peer_shared_key, encoded_data)
                
                # Create message
                message = NetworkMessage("file_message", {
                    "ciphertext": encrypted.ciphertext.hex(),
                    "nonce": encrypted.nonce.hex(),
                    "tag": encrypted.tag.hex(),
                    "filename": os.path.basename(filepath)
                }, self.network.node_id)
            
            # Send message
            success = await self.network.send_encrypted(self.peer_shared_key, encoded_data)
            
            if success:
                # Add to history
                self.message_history.append({
                    "type": "file_sent",
                    "content": f"File: {os.path.basename(filepath)}",
                    "timestamp": time.time(),
                    "sender": self.network.node_id,
                    "file_path": filepath
                })
                
                # Display file message
                self.display_file_message("sent", os.path.basename(filepath), filepath)
            else:
                self.console.print("[red]Failed to send file[/red]")
                
        except Exception as e:
            self.console.print(f"[red]Error sending file: {e}[/red]")
    
    async def secure_exit(self):
        """Securely exit the messenger"""
        self.console.print("\n[yellow]Securing exit...[/yellow]")
        
        # Stop network
        if self.network:
            await self.network.stop()
        
        # Securely delete key pair
        if hasattr(self.network, 'key_pair'):
            secure_delete_keypair(self.network.key_pair)
        
        # Clear message history
        self.message_history.clear()
        
        # Delete temp files
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception:
                pass
        
        # Clear temp files list
        self.temp_files.clear()
        
        # Clear screen
        self.console.clear()
        
        # Overwrite sensitive data in memory
        if self.peer_shared_key:
            # Overwrite with zeros
            for i in range(len(self.peer_shared_key)):
                self.peer_shared_key = self.peer_shared_key[:i] + b'\x00' + self.peer_shared_key[i+1:]
        
        self.console.print("[green]✓ Secure exit completed[/green]")
        self.console.print("[blue]All data has been securely wiped from memory[/blue]")
        self.running = False


async def main():
    """Main entry point for the secure messenger"""
    messenger = SecureMessenger()
    
    try:
        await messenger.start()
    except KeyboardInterrupt:
        await messenger.secure_exit()
    except Exception as e:
        messenger.console.print(f"[red]Fatal error: {e}[/red]")
        await messenger.secure_exit()


if __name__ == "__main__":
    asyncio.run(main()) 