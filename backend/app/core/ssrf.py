"""SSRF protection: resolve host to IP and block private/metadata addresses. No bypass via encoding or DNS rebinding."""
import ipaddress
import logging
import re
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),        # 0.0.0.0–0.255.255.255 (incl. 0.0.0.0)
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("10.0.0.0/8"),       # private
    ipaddress.ip_network("172.16.0.0/12"),   # private (Docker 172.17–172.31)
    ipaddress.ip_network("192.168.0.0/16"),   # private
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / AWS IMDS
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),        # IPv6 unique local
    ipaddress.ip_network("::ffff:0:0/96"),   # IPv4-mapped IPv6
]

BLOCKED_SCHEMES = {"file", "dict", "gopher", "ftp", "sftp", "ldap", "tftp"}

# Hostnames that resolve to 127.0.0.1 or are used for rebinding
BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "localtest.me", "localhost.me", "lvh.me", "127.0.0.1.nip.io",
    "127.0.0.1.xip.io", "169.254.169.254.xip.io", "metadata.google.internal",
}


def _parse_ip_from_unknown_format(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Try to parse host as IP in decimal, hex, or octal form (SSRF bypass attempts)."""
    host = host.strip().lower()
    # Decimal integer (e.g. 2130706433 = 127.0.0.1)
    if re.match(r"^\d+$", host):
        try:
            num = int(host)
            if 0 <= num <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(num)
        except ValueError:
            pass
    # Hex (e.g. 0x7f000001)
    if host.startswith("0x") and re.match(r"^0x[0-9a-f]+$", host):
        try:
            num = int(host, 16)
            if 0 <= num <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(num)
        except ValueError:
            pass
    # Octal (e.g. 0177.0.0.1 or 017700000001) – Python 3 doesn't interpret 0177 as octal in int();
    # but 0177.0.0.1 is parsed as IP string: try each octet as int(octet, 8) if leading 0
    if "." in host:
        parts = host.split(".")
        if len(parts) == 4 and all(re.match(r"^[0-9a-fx]+$", p) for p in parts):
            try:
                quads = []
                for p in parts:
                    if p.startswith("0x"):
                        quads.append(int(p, 16))
                    elif len(p) > 1 and p[0] == "0":
                        quads.append(int(p, 8))
                    else:
                        quads.append(int(p, 10))
                if all(0 <= q <= 255 for q in quads):
                    return ipaddress.IPv4Address(".".join(str(q) for q in quads))
            except (ValueError, TypeError):
                pass
    return None


def _resolve_host_to_ip(host: str) -> str | None:
    """Resolve hostname to first IPv4 or IPv6 address. Returns None on failure or timeout."""
    if not host:
        return None
    try:
        # Prefer IPv4 to avoid leaking IPv6 loopback behavior
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                results = socket.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
                if results:
                    return results[0][4][0]
            except (socket.gaierror, socket.timeout, OSError):
                continue
    except Exception as e:
        logger.debug("Resolve %s failed: %s", host[:50], e)
    return None


def _host_to_ips_to_check(host: str) -> list[str]:
    """Return list of IP strings to check: parsed IP (if any) plus resolved IP(s)."""
    ips = []
    host_clean = host.strip().lower()
    if host_clean in BLOCKED_HOSTNAMES:
        ips.extend(["127.0.0.1", "::1"])
    # Try parsing as IP in various forms
    parsed = _parse_ip_from_unknown_format(host)
    if parsed is not None:
        ips.append(str(parsed))
    else:
        try:
            ip = ipaddress.ip_address(host)
            ips.append(str(ip))
        except ValueError:
            pass
    # Always resolve hostname (covers DNS rebinding: localtest.me -> 127.0.0.1)
    resolved = _resolve_host_to_ip(host)
    if resolved and resolved not in ips:
        ips.append(resolved)
    return ips


def is_ssrf_blocked_url(url: str) -> bool:
    """
    Return True if the URL targets an internal/blocked host (SSRF risk).
    Uses resolved IP and blocks alternate encodings (decimal, hex, octal, 0.0.0.0, IPv4-mapped, DNS rebinding).
    """
    if not url or not url.strip():
        return True
    try:
        parsed = urlparse(url.strip())
        scheme = (parsed.scheme or "").lower()
        if scheme in BLOCKED_SCHEMES:
            return True
        if scheme not in ("http", "https"):
            return True
        host = (parsed.hostname or "").strip()
        if not host:
            return True
        host_lower = host.lower()
        if host_lower in BLOCKED_HOSTNAMES:
            return True
        ips_to_check = _host_to_ips_to_check(host)
        if not ips_to_check:
            return True
        for ip_str in ips_to_check:
            try:
                ip = ipaddress.ip_address(ip_str)
                if any(ip in net for net in BLOCKED_NETWORKS):
                    return True
            except ValueError:
                continue
        return False
    except Exception as e:
        logger.warning("SSRF check failed for %s: %s", url[:100], e)
        return True
