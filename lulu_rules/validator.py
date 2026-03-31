"""Validates IP addresses and domain names before they are passed to lulu-cli."""

import ipaddress
import re

_DOMAIN_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$'
)


def is_valid_ipv4(addr: str) -> bool:
    """Return True if addr is a valid, routable IPv4 address."""
    try:
        obj = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if not isinstance(obj, ipaddress.IPv4Address):
        return False
    return not (
        obj.is_private
        or obj.is_loopback
        or obj.is_link_local
        or obj.is_multicast
        or obj.is_reserved
        or obj.is_unspecified
    )


def is_valid_domain(domain: str) -> bool:
    """Return True if domain looks like a valid FQDN (no DNS lookup performed)."""
    if not domain or len(domain) > 253:
        return False
    # Reject anything that looks like a URL fragment
    if '/' in domain or ':' in domain:
        return False
    return bool(_DOMAIN_RE.match(domain))


def classify_indicator(value: str) -> str | None:
    """Return 'ip', 'domain', or None if the value is not a valid indicator."""
    value = value.strip()
    if not value:
        return None
    if is_valid_ipv4(value):
        return 'ip'
    if is_valid_domain(value):
        return 'domain'
    return None
