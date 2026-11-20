"""Destination validation (security).

Section 7 of the project brief: the proxy must not become an open relay and
must not let clients reach internal services (this attack class is called
SSRF - server-side request forgery).

Validation happens in two steps on purpose:

  1. check_policy(): cheap checks on the NAME and PORT, no network needed
     (blocked domains, allowed ports).
  2. resolve():      DNS lookup, then check the IP ADDRESSES we got back.
                     Checking the name alone is not enough: anyone can
                     register a public domain that resolves to 127.0.0.1.

resolve() returns the validated addresses and the caller connects to exactly
those. It must NOT resolve the name a second time, otherwise an attacker
could answer with a public IP the first time and a private one the second
("DNS rebinding").
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List, Tuple

from .config import Config
from .errors import BadGateway, BadRequest, Forbidden

# (address family, socket address) exactly as returned by getaddrinfo().
Address = Tuple[int, tuple]


def is_public_ip(text: str) -> bool:
    """True only for addresses on the public Internet."""
    ip = ipaddress.ip_address(text.split("%")[0])  # drop IPv6 zone id
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is really 127.0.0.1
    # is_global is False for loopback, private (10/8, 192.168/16...),
    # link-local (169.254/16, includes cloud metadata services), etc.
    return ip.is_global and not ip.is_multicast


class DestinationValidator:
    def __init__(self, config: Config) -> None:
        self.config = config

    def check_policy(self, host: str, port: int, is_connect: bool) -> None:
        hostname = host.lower().rstrip(".")
        # STAGE 7 - domain filtering (matches the domain and its subdomains).
        for blocked in self.config.blocked_domains:
            blocked = blocked.lower().strip(".")
            if hostname == blocked or hostname.endswith("." + blocked):
                raise Forbidden(f"Domain {host} is blocked by proxy policy")

        if self.config.insecure_testing:
            return
        allowed = (
            self.config.allowed_connect_ports
            if is_connect
            else self.config.allowed_http_ports
        )
        if port not in allowed:
            raise Forbidden(f"Port {port} is not allowed by proxy policy")

    def resolve(self, host: str, port: int) -> List[Address]:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise BadGateway(f"Could not resolve '{host}': {exc}")
        except UnicodeError:
            raise BadRequest("Invalid host name")

        addresses: List[Address] = []
        for family, _type, _proto, _canon, sockaddr in infos:
            if self.config.insecure_testing or is_public_ip(sockaddr[0]):
                if (family, sockaddr) not in addresses:
                    addresses.append((family, sockaddr))
        if not addresses:
            raise Forbidden("Destination resolves only to non-public addresses")
        return addresses
