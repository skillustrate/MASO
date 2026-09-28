"""
Allowlist-based Egress Proxy & Anti-SSRF Enforcement for MASO (v1.1.0).
Implements REVISED §6: default-deny, domain allowlist, self-resolving proxy-pinned IP,
and strict anti-DNS-rebinding protection.
"""

import asyncio
import ipaddress
import re
import socket
from typing import Any, Callable, List, Optional, Set, Tuple, Union


class SSRFSecurityViolation(Exception):
    """Base exception for all egress security violations."""
    pass


class DeniedIpError(SSRFSecurityViolation):
    """Raised when domain resolves to a private, loopback, link-local, or cloud metadata IP."""
    pass


class RawIpForbiddenError(SSRFSecurityViolation):
    """Raised when client supplies a raw IP literal instead of an allowlisted domain."""
    pass


class DomainNotAllowlistedError(SSRFSecurityViolation):
    """Raised when requested domain is not present in the skill's egress allowlist."""
    pass


class PortForbiddenError(SSRFSecurityViolation):
    """Raised when client attempts to connect to a port other than 443."""
    pass


# Strict set of denied IP subnets (IPv4 and IPv6) per REVISED §6.1
DENIED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-grade NAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),        # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmark Testing (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    ipaddress.ip_network("::/128"),              # Unspecified
    ipaddress.ip_network("::1/128"),             # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),            # IPv6 Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),           # IPv6 Link-local
    ipaddress.ip_network("ff00::/8"),            # IPv6 Multicast
]


def is_raw_ip(host: str) -> bool:
    """
    Detect whether the host string is an IP literal (IPv4, IPv6, decimal, or hex integer).
    Rejects bypass attempts using raw numeric encodings (e.g. 2130706433 or 0x7f000001).
    """
    clean_host = host.strip().strip("[]")
    
    # 1. Standard IP format
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    # 2. Decimal integer IP literal (e.g., 2130706433 for 127.0.0.1, 2852039166 for 169.254.169.254)
    if clean_host.isdigit():
        try:
            val = int(clean_host)
            if 0 <= val <= 0xFFFFFFFF:
                return True
        except ValueError:
            pass

    # 3. Hexadecimal IP literal (e.g., 0x7f000001)
    if clean_host.lower().startswith("0x"):
        try:
            val = int(clean_host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return True
        except ValueError:
            pass

    # 4. Octal IP notation (e.g., 0177.0.0.1)
    parts = clean_host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True

    return False


def is_ip_denied(ip_obj: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, str]:
    """
    Verify whether an IP address belongs to denied private, loopback, or metadata ranges.
    Handles IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1).
    """
    if isinstance(ip_obj, str):
        try:
            ip_obj = ipaddress.ip_address(ip_obj.strip().strip("[]"))
        except ValueError as e:
            return True, f"Invalid IP address format: {str(e)}"

    # Unwrap IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    if ip_obj.is_loopback:
        return True, f"Loopback address ({ip_obj}) is forbidden"
    if ip_obj.is_link_local:
        return True, f"Link-local / cloud metadata address ({ip_obj}) is forbidden"
    if ip_obj.is_private:
        return True, f"Private address ({ip_obj}) is forbidden"
    if ip_obj.is_multicast:
        return True, f"Multicast address ({ip_obj}) is forbidden"
    if ip_obj.is_reserved:
        return True, f"Reserved address ({ip_obj}) is forbidden"
    if ip_obj.is_unspecified:
        return True, f"Unspecified address ({ip_obj}) is forbidden"

    for net in DENIED_NETWORKS:
        if ip_obj in net:
            return True, f"Address {ip_obj} falls within denied subnet {net}"

    return False, ""


def is_domain_allowlisted(domain: str, allowlist: List[str]) -> bool:
    """
    Check if domain is explicitly allowlisted. Supports exact matching and *.wildcards.
    """
    clean_domain = domain.lower().strip().rstrip(".")
    for allowed in allowlist:
        clean_allowed = allowed.lower().strip().rstrip(".")
        if clean_allowed.startswith("*."):
            suffix = clean_allowed[1:]  # e.g. .example.com
            if clean_domain.endswith(suffix) and clean_domain != suffix[1:]:
                return True
        elif clean_domain == clean_allowed:
            return True
    return False


def resolve_and_pin_domain(
    domain: str,
    allowlist: List[str],
    port: int = 443,
    custom_resolver: Optional[Callable[[str, int], List[Tuple[Any, ...]]]] = None
) -> str:
    """
    Performs DNS resolution itself, pins the resulting IP, and rejects any SSRF/rebinding attempts.
    
    Returns:
        Pinned IP address string.
    """
    # 1. Enforce strict port 443 HTTPS only
    if port != 443:
        raise PortForbiddenError(f"Port {port} is forbidden. Only port 443 (HTTPS) is permitted per REVISED §6.1.")

    # 2. Reject raw IP literals
    if is_raw_ip(domain):
        raise RawIpForbiddenError(
            f"Direct IP access ({domain}) is forbidden per REVISED §6.1. Only allowlisted domain names are permitted."
        )

    # 3. Enforce domain allowlist
    if not is_domain_allowlisted(domain, allowlist):
        raise DomainNotAllowlistedError(
            f"Domain '{domain}' is not in the egress allowlist: {allowlist}"
        )

    # 4. Proxy DNS resolution (Anti-rebinding)
    try:
        if custom_resolver:
            addr_info = custom_resolver(domain, port)
        else:
            addr_info = socket.getaddrinfo(domain, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFSecurityViolation(f"DNS resolution failed for domain '{domain}': {str(e)}")

    if not addr_info:
        raise SSRFSecurityViolation(f"No DNS records resolved for domain '{domain}'")

    # 5. Validate every resolved address against denied IP ranges
    pinned_ip = None
    for item in addr_info:
        sockaddr = item[4]
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise DeniedIpError(f"Resolved address '{ip_str}' is invalid")

        denied, reason = is_ip_denied(ip_obj)
        if denied:
            raise DeniedIpError(
                f"DNS rebinding / SSRF attempt detected: domain '{domain}' resolved to denied IP {ip_str} ({reason})"
            )

        if pinned_ip is None:
            pinned_ip = ip_str

    if not pinned_ip:
        raise SSRFSecurityViolation(f"Could not pin a valid public IP for domain '{domain}'")

    return pinned_ip


class EgressProxyServer:
    """
    Minimal asynchronous HTTPS CONNECT forward proxy with strict allowlisting and IP pinning.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0, allowlist: Optional[List[str]] = None):
        self.host = host
        self.port = port
        self.allowlist = list(allowlist or [])
        self.server: Optional[asyncio.Server] = None
        self._listening_port: int = port

    @property
    def listening_port(self) -> int:
        return self._listening_port

    @property
    def proxy_url(self) -> str:
        return f"http://{self.host}:{self._listening_port}"

    async def start(self) -> None:
        """Start proxy server."""
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self._listening_port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        """Stop proxy server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming client HTTP request (CONNECT only)."""
        try:
            line = await reader.readline()
            if not line:
                writer.close()
                await writer.wait_closed()
                return

            request_line = line.decode("utf-8", errors="replace").strip()
            parts = request_line.split()

            if len(parts) < 3 or parts[0].upper() != "CONNECT":
                # Reject plain HTTP or malformed methods
                response = (
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: text/plain\r\n"
                    "Connection: close\r\n\r\n"
                    "[MASO EGRESS PROXY] Plain HTTP and non-CONNECT methods are forbidden. Only HTTPS on port 443 is permitted.\n"
                )
                writer.write(response.encode("utf-8"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # Read remaining headers
            while True:
                header_line = await reader.readline()
                if not header_line or header_line == b"\r\n" or header_line == b"\n":
                    break

            target = parts[1]
            if ":" in target:
                host_str, port_str = target.rsplit(":", 1)
                try:
                    target_port = int(port_str)
                except ValueError:
                    target_port = -1
            else:
                host_str = target
                target_port = 443

            # Enforce validation and IP pinning
            try:
                pinned_ip = resolve_and_pin_domain(host_str, self.allowlist, target_port)
            except SSRFSecurityViolation as e:
                err_msg = f"[MASO EGRESS PROXY FORBIDDEN] {type(e).__name__}: {str(e)}"
                response = (
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: text/plain\r\n"
                    "Connection: close\r\n\r\n"
                    f"{err_msg}\n"
                )
                writer.write(response.encode("utf-8"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # Establish upstream connection to the PINNED IP
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(pinned_ip, target_port),
                    timeout=10.0
                )
            except Exception as e:
                response = (
                    "HTTP/1.1 502 Bad Gateway\r\n"
                    "Content-Type: text/plain\r\n"
                    "Connection: close\r\n\r\n"
                    f"[MASO EGRESS PROXY ERROR] Failed to connect to pinned IP {pinned_ip}: {str(e)}\n"
                )
                writer.write(response.encode("utf-8"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # Send 200 Connection Established
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            # Bidirectional pipe
            async def forward(src_r: asyncio.StreamReader, dst_w: asyncio.StreamWriter):
                try:
                    while True:
                        data = await src_r.read(8192)
                        if not data:
                            break
                        dst_w.write(data)
                        await dst_w.drain()
                except Exception:
                    pass
                finally:
                    try:
                        dst_w.close()
                    except Exception:
                        pass

            await asyncio.gather(
                forward(reader, upstream_writer),
                forward(upstream_reader, writer),
                return_exceptions=True
            )

        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
