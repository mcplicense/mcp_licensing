"""Who is calling: the visitor's address as CloudFront reports it.

Behind CloudFront the API only sees CloudFront's own address, and
X-Forwarded-For can be forged by the visitor. CloudFront sets
CloudFront-Viewer-Address itself (it overwrites anything the visitor sends), as
"203.0.113.9:4430" for IPv4 and "2001:db8::1:4430" or "[2001:db8::1]:4430" for
IPv6, so that is the header to trust. The origin request policy must forward it.
"""
import ipaddress

from core.http import get_header

HEADER = "CloudFront-Viewer-Address"
UNKNOWN = "unknown"


def client_ip(event):
    """The viewer's ip_address object, or None when the header is missing or odd."""
    value = (get_header(event, HEADER) or "").strip()
    if not value:
        return None
    if value.startswith("["):                 # [2001:db8::1]:4430
        host = value[1:].split("]", 1)[0]
    elif value.count(":") == 1:               # 203.0.113.9:4430
        host = value.split(":", 1)[0]
    else:                                     # 2001:db8::1:4430, the port appended to an IPv6 address
        host = value.rsplit(":", 1)[0]
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def rate_key(event):
    """A string that stands for the visitor in a limit: the IPv4 address, or the
    IPv6 /64 (one household or subscriber holds a whole /64, so counting single
    IPv6 addresses would let one person dodge a limit by rotating them). Without
    a usable address every request shares one key, which is the safe direction."""
    ip = client_ip(event)
    if ip is None:
        return UNKNOWN
    if ip.version == 6:
        return str(ipaddress.ip_network("{}/64".format(ip), strict=False))
    return str(ip)
