"""
GuardX Scope Management Module
Defines and enforces scan boundaries (targets allowed).
"""

import ipaddress
import socket
from typing import List
from urllib.parse import urlparse


class ScanScope:
    """Define and enforce scan boundaries.

    Supports IP addresses, CIDR notation, and domains with wildcards.
    """

    def __init__(self, targets: List[str]):
        """Initialize scope with target list.

        Args:
            targets: List of IPs, CIDR notation, or domains.
                    Examples: "192.168.1.1", "10.0.0.0/24", "example.com", "*.example.com"
        """
        self.targets = targets
        self.ipv4_networks = []
        self.ipv6_networks = []
        self.domains = []
        self.wildcard_domains = []

        self._parse_targets()

    def _parse_targets(self) -> None:
        """Parse target list into IP networks and domains."""
        for target in self.targets:
            target = target.strip().lower()

            # Try to parse as IP network (CIDR)
            try:
                network = ipaddress.ip_network(target, strict=False)
                if isinstance(network, ipaddress.IPv4Network):
                    self.ipv4_networks.append(network)
                else:
                    self.ipv6_networks.append(network)
                continue
            except ValueError:
                pass

            # Check if it's a wildcard domain
            if target.startswith('*.'):
                self.wildcard_domains.append(target[2:])  # Remove *. prefix
            else:
                self.domains.append(target)

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is within scope.

        Args:
            target: IP address, domain, or URL to check

        Returns:
            True if target is in scope
        """
        target = target.strip().lower()

        # Parse URL if necessary
        if target.startswith('http://') or target.startswith('https://'):
            try:
                parsed = urlparse(target)
                target = parsed.netloc or parsed.path
            except Exception:
                return False

        # Remove port if present
        if ':' in target and not target.startswith('['):
            target = target.split(':')[0]

        # Try as IP address
        try:
            ip = ipaddress.ip_address(target)
            for network in self.ipv4_networks if isinstance(ip, ipaddress.IPv4Address) else self.ipv6_networks:
                if ip in network:
                    return True
            return False
        except ValueError:
            pass

        # Try as domain
        if self._check_domain(target):
            return True

        # Try to resolve domain to IP and check
        try:
            resolved_ips = socket.getaddrinfo(target, None)
            for _, _, _, _, sockaddr in resolved_ips:
                ip_str = sockaddr[0]
                ip = ipaddress.ip_address(ip_str)
                for network in self.ipv4_networks if isinstance(ip, ipaddress.IPv4Address) else self.ipv6_networks:
                    if ip in network:
                        return True
        except (socket.gaierror, ValueError, OSError):
            pass

        return False

    def _check_domain(self, domain: str) -> bool:
        """Check if domain matches scope domains.

        Args:
            domain: Domain to check

        Returns:
            True if domain is in scope
        """
        # Exact match
        if domain in self.domains:
            return True

        # Wildcard match
        for wildcard_base in self.wildcard_domains:
            if domain == wildcard_base or domain.endswith('.' + wildcard_base):
                return True

        return False

    def add_target(self, target: str) -> None:
        """Add a new target to scope.

        Args:
            target: IP, CIDR, or domain to add
        """
        target = target.strip().lower()
        if target not in self.targets:
            self.targets.append(target)
            self._parse_targets()

    def remove_target(self, target: str) -> None:
        """Remove a target from scope.

        Args:
            target: Target to remove
        """
        target = target.strip().lower()
        self.targets = [t for t in self.targets if t.lower() != target]
        self._parse_targets()

    def get_targets(self) -> List[str]:
        """Get list of targets in scope.

        Returns:
            List of target specifications
        """
        return self.targets.copy()

    def validate_url(self, url: str) -> bool:
        """Extract host from URL and check if it's in scope.

        Args:
            url: Full URL to validate

        Returns:
            True if URL's host is in scope
        """
        try:
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path

            # Remove port
            if ':' in host:
                host = host.split(':')[0]

            return self.is_in_scope(host)
        except Exception:
            return False

    def get_summary(self) -> dict:
        """Get summary of scope configuration.

        Returns:
            Dictionary with scope statistics
        """
        return {
            'total_targets': len(self.targets),
            'ipv4_networks': len(self.ipv4_networks),
            'ipv6_networks': len(self.ipv6_networks),
            'explicit_domains': len(self.domains),
            'wildcard_domains': len(self.wildcard_domains),
            'targets': self.targets
        }


def create_scope(targets: List[str]) -> ScanScope:
    """Create a new scan scope.

    Args:
        targets: List of targets (IPs, CIDR, domains)

    Returns:
        ScanScope instance
    """
    return ScanScope(targets)
