"""SSRF protection: block internal/private IPs and metadata URLs from DAST targets."""
import ipaddress
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("10.0.0.0/8"),       # private
    ipaddress.ip_network("172.16.0.0/12"),    # private (incl. Docker 172.17–172.31)
    ipaddress.ip_network("192.168.0.0/16"),   # private
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / AWS IMDS
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),        # IPv6 unique local
]


def is_ssrf_blocked_url(url: str) -> bool:
    """
    Return True if the URL targets an internal/blocked host (SSRF risk).
    Call this before starting any DAST scan or crawl with user-supplied target_url.
    """
    if not url or not url.strip():
        return True
    try:
        parsed = urlparse(url.strip())
        host = (parsed.hostname or "").strip()
        if not host:
            return True
        host_lower = host.lower()
        if host_lower in ("localhost", "localhost.localdomain", "ip6-localhost"):
            return True
        try:
            ip = ipaddress.ip_address(host)
            return any(ip in net for net in BLOCKED_NETWORKS)
        except ValueError:
            pass
        return False
    except Exception as e:
        logger.warning("SSRF check failed for %s: %s", url[:100], e)
        return True
