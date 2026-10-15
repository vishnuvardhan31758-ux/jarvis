"""jarvis/web/security.py — SSRF & Local Network Guard."""
from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from jarvis.contracts import PolicyDeniedError

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "metadata.google.internal",
    "169.254.169.254",
    "0.0.0.0",
}


class SSRFGuard:
    def _check_ip(self, ip_str: str) -> None:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise PolicyDeniedError(f"SSRF Guard blocked restricted IP address: {ip}")

    def validate_url(self, url: str, resolve_dns: bool = True) -> str:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise PolicyDeniedError(f"Disallowed URL scheme: {parsed.scheme}")
        if not parsed.hostname or parsed.username or parsed.password:
            raise PolicyDeniedError("Invalid hostname or embedded credentials in URL")

        host = parsed.hostname.lower()
        if host in BLOCKED_HOSTS:
            raise PolicyDeniedError(f"SSRF Guard blocked internal hostname: {host}")

        try:
            self._check_ip(host)
            return url
        except ValueError:
            pass

        if resolve_dns:
            try:
                infos = socket.getaddrinfo(host, None)
                for info in infos:
                    self._check_ip(info[4][0])
            except socket.gaierror:
                pass
        return url
