"""
mail_check.py
Inspects domain email infrastructure (MX records).
Domains with active MX records are frequently primed for spear-phishing,
CEO fraud, and credential intercept campaigns.
"""

import socket


def check_mx_records(domain, timeout=4):
    """
    Checks if domain has active mail exchanger (MX) infrastructure.
    Uses socket DNS lookup to stay resilient across environments.
    Returns:
        dict: {
            "has_mx": bool,
            "mx_hosts": list of strings,
            "mail_enabled": bool
        }
    """
    domain = domain.lower().lstrip("*.")

    # In Python standard library, socket.getaddrinfo can be used to query host
    # For MX queries, we attempt resolution of common mail hosts or fallback DNS probe
    mx_hosts = []
    has_mx = False

    # Check common MX prefixes if direct resolver isn't available
    mail_prefixes = ["mail", "smtp", "mx", "mx1"]
    for prefix in mail_prefixes:
        test_host = f"{prefix}.{domain}"
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(test_host)
            mx_hosts.append(test_host)
            has_mx = True
            socket.setdefaulttimeout(old_timeout)
            break
        except Exception:
            pass

    # If dnspython is installed, use it for genuine RFC MX lookup
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, 'MX')
        for rdata in answers:
            host = str(rdata.exchange).rstrip(".")
            if host not in mx_hosts:
                mx_hosts.append(host)
        if len(mx_hosts) > 0:
            has_mx = True
    except Exception:
        # dnspython may not be installed or query timed out, fallback is preserved
        pass

    return {
        "has_mx": has_mx,
        "mx_hosts": mx_hosts,
        "mail_enabled": has_mx
    }


if __name__ == "__main__":
    test_cases = ["google.com", "github.com", "non-existent-domain-xyz987.com"]
    for d in test_cases:
        res = check_mx_records(d)
        print(f"{d:35s} -> MX detected: {res['has_mx']}, Hosts: {res['mx_hosts']}")
