"""
WireGuard Configuration Generator

Generates WireGuard configuration files from a YAML definition.
"""

import ipaddress
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class Node:
    """Represents a WireGuard node (server or client)."""
    name: str
    ip: str
    private_key: str = ""
    public_key: str = ""
    endpoint: Optional[str] = None  # Only for server
    is_server: bool = False
    connect_to: list[str] = field(default_factory=list)


class KeyGenerator:
    """Generates WireGuard key pairs."""

    @staticmethod
    def generate_keypair() -> tuple[str, str]:
        """Generate a WireGuard private/public key pair."""
        # Generate private key
        private_key = subprocess.run(
            ["wg", "genkey"],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()

        # Derive public key
        public_key = subprocess.run(
            ["wg", "pubkey"],
            input=private_key,
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()

        return private_key, public_key


class IPAllocator:
    """Handles automatic IP address allocation."""

    def __init__(self, subnet: str):
        self.network = ipaddress.ip_network(subnet, strict=False)
        self.hosts = list(self.network.hosts())
        self.next_index = 0
        self.allocated: dict[str, str] = {}

    def allocate(self, node_name: str, requested_ip: Optional[str] = None) -> str:
        """Allocate an IP address for a node."""
        if requested_ip and requested_ip.lower() != "auto":
            # Manual IP assignment
            ip = ipaddress.ip_address(requested_ip)
            if ip not in self.hosts:
                raise ValueError(f"IP {requested_ip} is not in subnet {self.network}")
            self.allocated[node_name] = str(ip)
            return str(ip)

        # Auto allocation - find next available IP
        while self.next_index < len(self.hosts):
            candidate = str(self.hosts[self.next_index])
            self.next_index += 1
            if candidate not in self.allocated.values():
                self.allocated[node_name] = candidate
                return candidate

        raise RuntimeError("No more IP addresses available in subnet")

    def get_prefix_length(self) -> int:
        """Get the prefix length of the subnet."""
        return self.network.prefixlen


class ConfigGenerator:
    """Main configuration generator."""

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config: dict = {}
        self.nodes: dict[str, Node] = {}
        self.server: Optional[Node] = None
        self.ip_allocator: Optional[IPAllocator] = None
        self.keepalive: int = 25

    def load_config(self) -> None:
        """Load and parse YAML configuration."""
        with open(self.config_path) as f:
            self.config = yaml.safe_load(f)

        # Initialize IP allocator
        subnet = self.config["network"]["subnet"]
        self.ip_allocator = IPAllocator(subnet)
        self.keepalive = self.config["network"].get("keepalive", 25)

    def process_nodes(self) -> None:
        """Process all nodes: generate keys and allocate IPs."""
        # Process server first
        server_config = self.config["server"]
        server_ip = self.ip_allocator.allocate(
            server_config["name"],
            server_config.get("ip")
        )
        private_key, public_key = KeyGenerator.generate_keypair()

        self.server = Node(
            name=server_config["name"],
            ip=server_ip,
            private_key=private_key,
            public_key=public_key,
            endpoint=server_config["endpoint"],
            is_server=True,
            connect_to=["all"]  # Server connects to all
        )
        self.nodes[self.server.name] = self.server

        # Process clients
        for client_config in self.config.get("clients", []):
            client_ip = self.ip_allocator.allocate(
                client_config["name"],
                client_config.get("ip")
            )
            private_key, public_key = KeyGenerator.generate_keypair()

            connect_to = client_config.get("connect_to", "all")
            if isinstance(connect_to, str):
                connect_to = [connect_to]

            client = Node(
                name=client_config["name"],
                ip=client_ip,
                private_key=private_key,
                public_key=public_key,
                connect_to=connect_to
            )
            self.nodes[client.name] = client

    def _resolve_allowed_ips(self, node: Node) -> dict[str, list[str]]:
        """
        Resolve which IPs each peer should have in AllowedIPs.
        Returns a dict: {peer_name: [allowed_ips]}
        """
        result = {}

        if node.is_server:
            # Server allows all clients
            for name, peer in self.nodes.items():
                if not peer.is_server:
                    result[name] = [f"{peer.ip}/32"]
        else:
            # Client always connects to server
            # AllowedIPs for server peer depends on connect_to
            if "all" in node.connect_to:
                # Allow all VPN traffic through server
                all_ips = [f"{n.ip}/32" for n in self.nodes.values()]
                result[self.server.name] = all_ips
            else:
                # Only allow specific nodes + server itself
                allowed = [f"{self.server.ip}/32"]  # Always include server
                for target_name in node.connect_to:
                    if target_name in self.nodes:
                        allowed.append(f"{self.nodes[target_name].ip}/32")

                # Also check reverse connections (bidirectional)
                for other_name, other_node in self.nodes.items():
                    if other_node.is_server:
                        continue
                    if node.name in other_node.connect_to:
                        ip = f"{other_node.ip}/32"
                        if ip not in allowed:
                            allowed.append(ip)

                result[self.server.name] = allowed

        return result

    def _generate_server_conf(self) -> str:
        """Generate server configuration file content."""
        lines = [
            f"# {self.server.name} - WireGuard Server Configuration",
            f"# Generated by wg-config-wizard",
            "",
            "[Interface]",
            f"PrivateKey = {self.server.private_key}",
            f"Address = {self.server.ip}/{self.ip_allocator.get_prefix_length()}",
            f"ListenPort = {self.server.endpoint.split(':')[-1]}",
            "",
        ]

        # Add all clients as peers
        allowed_ips = self._resolve_allowed_ips(self.server)
        for client_name, client in self.nodes.items():
            if client.is_server:
                continue

            lines.extend([
                f"# Peer: {client_name}",
                "[Peer]",
                f"PublicKey = {client.public_key}",
                f"AllowedIPs = {', '.join(allowed_ips.get(client_name, []))}",
                "",
            ])

        return "\n".join(lines)

    def _generate_client_conf(self, client: Node) -> str:
        """Generate client configuration file content."""
        lines = [
            f"# {client.name} - WireGuard Client Configuration",
            f"# Generated by wg-config-wizard",
            "",
            "[Interface]",
            f"PrivateKey = {client.private_key}",
            f"Address = {client.ip}/{self.ip_allocator.get_prefix_length()}",
            "",
        ]

        # Add server as peer
        allowed_ips = self._resolve_allowed_ips(client)
        server_allowed = allowed_ips.get(self.server.name, [])

        lines.extend([
            f"# Peer: {self.server.name} (server)",
            "[Peer]",
            f"PublicKey = {self.server.public_key}",
            f"Endpoint = {self.server.endpoint}",
            f"AllowedIPs = {', '.join(server_allowed)}",
            f"PersistentKeepalive = {self.keepalive}",
            "",
        ])

        return "\n".join(lines)

    def generate(self, output_dir: str = "output") -> None:
        """Generate all configuration files."""
        self.load_config()
        self.process_nodes()

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Generate server config
        server_conf = self._generate_server_conf()
        server_file = output_path / f"{self.server.name}.conf"
        server_file.write_text(server_conf)
        print(f"Generated: {server_file}")

        # Generate client configs
        for name, node in self.nodes.items():
            if node.is_server:
                continue

            client_conf = self._generate_client_conf(node)
            client_file = output_path / f"{name}.conf"
            client_file.write_text(client_conf)
            print(f"Generated: {client_file}")

        print(f"\nAll configurations saved to: {output_path.absolute()}")
