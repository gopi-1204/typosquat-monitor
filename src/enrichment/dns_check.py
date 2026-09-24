"""
dns_check.py
Checks whether a domain is actively live and resolves its IPv4 address.
Uses OS-level resolver via standard socket, resilient against networks
that block raw port 53 UDP traffic.
"""

import socket


def resolve_domain_ip(domain, timeout=3):
    """
    Attempts to resolve domain to an IPv4 address.
    Returns:
        tuple: (is_live: bool, ip_address: str or None)
    """
    domain = domain.lower().lstrip("*.")
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        ip = socket.gethostbyname(domain)
        return True, ip
    except (socket.gaierror, socket.timeout, Exception):
        return False, None
    finally:
        socket.setdefaulttimeout(original_timeout)


def is_domain_live(domain, timeout=3):
    """
    Backwards-compatible boolean liveness checker.
    """
    is_live, _ = resolve_domain_ip(domain, timeout=timeout)
    return is_live


if __name__ == "__main__":
    test_domains = [
        "google.com",
        "flipkart.com",
        "this-domain-should-not-exist-xyz123.com",
    ]

    for domain in test_domains:
        live, ip = resolve_domain_ip(domain)
        status = f"LIVE ({ip})" if live else "not live"
        print(f"{domain:45s} -> {status}")
