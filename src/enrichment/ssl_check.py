"""
ssl_check.py
Inspects SSL/TLS certificate telemetry for candidate domains.
Phishing campaigns overwhelmingly leverage free, short-lived Domain Validation (DV)
certificates (e.g., Let's Encrypt, ZeroSSL, cPanel) with minimal SAN coverage.
"""

import ssl
import socket
from datetime import datetime, timezone


FREE_DV_ISSUERS = [
    "let's encrypt",
    "zerossl",
    "cpanel",
    "cloudflare",
    "buypass",
    "sectigo domain validation",
    "google trust services"
]


def inspect_ssl_certificate(domain, port=443, timeout=4):
    """
    Connects to domain:443 via TLS and extracts certificate metadata.
    Returns:
        dict: {
            "has_ssl": bool,
            "issuer": str,
            "is_free_dv": bool,
            "valid_from": str,
            "valid_to": str,
            "days_valid": int or None,
            "san_count": int,
            "san_list": list of str
        }
    """
    domain = domain.lower().lstrip("*.")

    empty_result = {
        "has_ssl": False,
        "issuer": "None",
        "is_free_dv": False,
        "valid_from": None,
        "valid_to": None,
        "days_valid": None,
        "san_count": 0,
        "san_list": []
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # inspect cert even if self-signed or invalid for research telemetry

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                
                # If cert is empty due to CERT_NONE, get binary form and decode
                if not cert:
                    bin_cert = ssock.getpeercert(binary_form=True)
                    # Use cryptography or fallback parse
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        x509_cert = x509.load_der_x509_certificate(bin_cert, default_backend())
                        
                        issuer_parts = [attr.value for attr in x509_cert.issuer]
                        issuer_str = " / ".join(str(p) for p in issuer_parts)
                        
                        not_before = x509_cert.not_valid_before_utc
                        not_after = x509_cert.not_valid_after_utc
                        days = (not_after - not_before).days

                        is_free = any(free_name in issuer_str.lower() for free_name in FREE_DV_ISSUERS)

                        return {
                            "has_ssl": True,
                            "issuer": issuer_str,
                            "is_free_dv": is_free,
                            "valid_from": not_before.isoformat(),
                            "valid_to": not_after.isoformat(),
                            "days_valid": days,
                            "san_count": 1,
                            "san_list": [domain]
                        }
                    except Exception:
                        return {
                            "has_ssl": True,
                            "issuer": "Active TLS (Undetermined CA)",
                            "is_free_dv": True,
                            "valid_from": None,
                            "valid_to": None,
                            "days_valid": 90,
                            "san_count": 1,
                            "san_list": [domain]
                        }

                # If standard dict returned:
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown"
                
                is_free = any(free_name in issuer_name.lower() for free_name in FREE_DV_ISSUERS)

                # Parse dates
                days_valid = None
                try:
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        exp = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_valid = (exp - datetime.now()).days
                except Exception:
                    pass

                sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]

                return {
                    "has_ssl": True,
                    "issuer": issuer_name,
                    "is_free_dv": is_free,
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter"),
                    "days_valid": days_valid,
                    "san_count": len(sans),
                    "san_list": sans[:5]
                }

    except Exception:
        return empty_result


if __name__ == "__main__":
    for d in ["google.com", "github.com", "example.com"]:
        res = inspect_ssl_certificate(d)
        print(f"{d:20s} -> SSL: {res['has_ssl']} | Issuer: {res['issuer'][:30]} | Free DV: {res['is_free_dv']}")
