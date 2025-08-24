"""
CLI module for P2P Secure Messaging
Provides a rich command-line interface for the P2P messaging system
"""

import asyncio
import argparse
import sys
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.align import Align
from rich import box
from .network import P2PNetwork, NetworkMessage
from .encryption import encode_public_key, decode_public_key


class SecureMessagingCLI:
    """Rich CLI for P2P Secure Messaging"""
    
    def __init__(self):
        self.console = Console()
        self.network: Optional[P2PNetwork] = None
        self.running = False
        
        # Set up message handlers
        self.setup_message_handlers()
    
    def setup_message_handlers(self):
        """Set up default message handlers"""
        if not self.network:
            return
        
        self.network.add_message_handler("handshake", self.handle_handshake)
        self.network.add_message_handler("message", self.handle_message)
        self.network.add_message_handler("encrypted", self.handle_encrypted_message)
    
    async def handle_handshake(self, message: NetworkMessage, reader, writer, addr=None):
        """Handle handshake messages"""
        self.console.print(f"[green]Handshake received from {message.sender_id}[/green]")
        if "public_key" in message.payload:
            peer_public_key = decode_public_key(message.payload["public_key"])
            self.console.print(f"[blue]Peer public key: {message.payload['public_key'][:32]}...[/blue]")
    
    async def handle_message(self, message: NetworkMessage, reader, writer, addr=None):
        """Handle plain text messages"""
        self.console.print(f"[yellow]Message from {message.sender_id}:[/yellow] {message.payload}")
    
    async def handle_encrypted_message(self, message: NetworkMessage, reader, writer, addr=None):
        """Handle encrypted messages"""
        self.console.print(f"[red]Encrypted message from {message.sender_id}[/red]")
        # In a real implementation, you'd decrypt this message
    
    def show_banner(self):
        """Display the application banner"""
        banner = Text("P2P Secure Messaging", style="bold blue")
        subtitle = Text("End-to-end encrypted peer-to-peer communication", style="italic")
        
        panel = Panel(
            Align.center(banner + "\n" + subtitle),
            border_style="blue",
            box=box.DOUBLE
        )
        self.console.print(panel)
    
    def show_help(self):
        """Display help information"""
        help_text = """
[bold]Available Commands:[/bold]

[green]start[/green] - Start the P2P network (TCP + UDP)
[green]connect <ip> <port>[/green] - Connect to a peer with NAT traversal
[green]send <peer_id> <message>[/green] - Send encrypted message to a peer
[green]peers[/green] - List connected peers
[green]info[/green] - Show network information
[green]help[/green] - Show this help
[green]quit[/green] - Exit the application

[bold]Examples:[/bold]
  connect 192.168.1.100 8080
  send peer123 Hello, this is a secure message!
        """
        
        panel = Panel(help_text, title="Help", border_style="green")
        self.console.print(panel)
    
    def show_node_info(self):
        """Display node information"""
        if not self.network:
            self.console.print("[red]Network not started[/red]")
            return
        
        info_table = Table(title="Network Information", border_style="blue")
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="white")
        
        info_table.add_row("Node ID", self.network.node_id)
        info_table.add_row("Host", self.network.host)
        info_table.add_row("TCP Port", str(self.network.tcp_port))
        info_table.add_row("UDP Port", str(self.network.udp_port))
        info_table.add_row("Status", "Running" if self.network.running else "Stopped")
        info_table.add_row("Connected Peers", str(len(self.network.peers)))
        info_table.add_row("Public Key", encode_public_key(self.network.key_pair.public_key)[:32] + "...")
        
        self.console.print(info_table)
    
    def show_peers(self):
        """Display connected peers"""
        if not self.network:
            self.console.print("[red]Network not started[/red]")
            return
        
        if not self.network.peers:
            self.console.print("[yellow]No peers connected[/yellow]")
            return
        
        peers_table = Table(title="Connected Peers", border_style="green")
        peers_table.add_column("Peer ID", style="cyan")
        peers_table.add_column("Host", style="white")
        peers_table.add_column("Port", style="white")
        peers_table.add_column("Connection Type", style="yellow")
        peers_table.add_column("Last Seen", style="blue")
        
        for peer in self.network.peers.values():
            peers_table.add_row(
                peer.id,
                peer.host,
                str(peer.port),
                peer.connection_type,
                str(int(peer.last_seen))
            )
        
        self.console.print(peers_table)
    
    async def start_network(self, host: str = "0.0.0.0", tcp_port: int = 0, udp_port: int = 0):
        """Start the P2P network"""
        try:
            self.network = P2PNetwork(host, tcp_port, udp_port)
            await self.network.start()
            self.setup_message_handlers()
            self.console.print("[green]Network started successfully![/green]")
        except Exception as e:
            self.console.print(f"[red]Failed to start network: {e}[/red]")
    
    async def connect_to_peer(self, ip: str, port: int):
        """Connect to a peer"""
        if not self.network:
            self.console.print("[red]Network not started. Use 'start' first.[/red]")
            return
        
        try:
            success = await self.network.connect_to_peer(ip, port)
            if success:
                self.console.print(f"[green]Successfully connected to {ip}:{port}[/green]")
            else:
                self.console.print(f"[red]Failed to connect to {ip}:{port}[/red]")
        except Exception as e:
            self.console.print(f"[red]Error connecting to peer: {e}[/red]")
    
    async def send_encrypted_message(self, peer_id: str, message_text: str):
        """Send an encrypted message to a peer"""
        if not self.network:
            self.console.print("[red]Network not started. Use 'start' first.[/red]")
            return
        
        # Find peer by ID
        target_peer = None
        for peer in self.network.peers.values():
            if peer.id == peer_id:
                target_peer = peer
                break
        
        if not target_peer or not target_peer.shared_key:
            self.console.print(f"[red]No shared key found for peer {peer_id}[/red]")
            return
        
        try:
            success = await self.network.send_encrypted(target_peer.shared_key, message_text.encode())
            if success:
                self.console.print(f"[green]Encrypted message sent to {peer_id}[/green]")
            else:
                self.console.print(f"[red]Failed to send encrypted message to {peer_id}[/red]")
        except Exception as e:
            self.console.print(f"[red]Error sending encrypted message: {e}[/red]")
    
    async def run_interactive(self):
        """Run the interactive CLI"""
        self.show_banner()
        self.show_help()
        
        while True:
            try:
                command = Prompt.ask("\n[bold cyan]p2p-securemsg>[/bold cyan]")
                command = command.strip()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                
                if cmd == "quit" or cmd == "exit":
                    if self.network:
                        await self.network.stop()
                    self.console.print("[yellow]Goodbye![/yellow]")
                    break
                
                elif cmd == "help":
                    self.show_help()
                
                elif cmd == "start":
                    host = Prompt.ask("Host", default="0.0.0.0")
                    tcp_port = int(Prompt.ask("TCP Port", default="0"))
                    udp_port = int(Prompt.ask("UDP Port", default="0"))
                    await self.start_network(host, tcp_port, udp_port)
                
                elif cmd == "connect":
                    if len(parts) < 3:
                        self.console.print("[red]Usage: connect <ip> <port>[/red]")
                        continue
                    
                    ip = parts[1]
                    port = int(parts[2])
                    await self.connect_to_peer(ip, port)
                
                elif cmd == "send":
                    if len(parts) < 3:
                        self.console.print("[red]Usage: send <peer_id> <message>[/red]")
                        continue
                    
                    peer_id = parts[1]
                    message = " ".join(parts[2:])
                    await self.send_encrypted_message(peer_id, message)
                
                elif cmd == "peers":
                    self.show_peers()
                
                elif cmd == "info":
                    self.show_node_info()
                
                else:
                    self.console.print(f"[red]Unknown command: {cmd}[/red]")
                    self.console.print("Type 'help' for available commands")
            
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Use 'quit' to exit[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")


def main():
    """Main entry point for the CLI"""
    parser = argparse.ArgumentParser(description="P2P Secure Messaging CLI")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--tcp-port", type=int, default=0, help="TCP port to bind to")
    parser.add_argument("--udp-port", type=int, default=0, help="UDP port to bind to")
    parser.add_argument("--auto-start", action="store_true", help="Auto-start the network")
    
    args = parser.parse_args()
    
    cli = SecureMessagingCLI()
    
    async def run():
        if args.auto_start:
            await cli.start_network(args.host, args.tcp_port, args.udp_port)
        
        await cli.run_interactive()
    
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 