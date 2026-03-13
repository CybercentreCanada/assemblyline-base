from ipaddress import ip_address, IPv4Network
import socket
import os
import functools


from assemblyline.common.net_static import TLDS_ALPHA_BY_DOMAIN, TLDS_SPECIAL_BY_DOMAIN
SYSTEM_LOCAL_TLD = os.getenv('SYSTEM_LOCAL_TLD', '')


def is_valid_port(value: int) -> bool:
    try:
        if 1 <= int(value) <= 65535:
            return True
    except ValueError:
        pass

    return False


@functools.cache
def find_top_level_domains():
    """Combine (once and memoize) the three different sources of TLD."""
    combined_tlds = TLDS_ALPHA_BY_DOMAIN.union({d for d in TLDS_SPECIAL_BY_DOMAIN if '.' not in d})
    local_tld = [tld.strip().strip('.').upper() for tld in SYSTEM_LOCAL_TLD.split(";")]
    combined_tlds |= {tld for tld in local_tld if tld}
    return combined_tlds


def is_valid_domain(domain: str) -> bool:
    if "@" in domain:
        return False

    if "." in domain:
        domain = domain.upper()
        tld = domain.split(".")[-1]
        if not tld.isascii():
            try:
                tld = tld.encode('idna').decode('ascii').upper()
            except ValueError:
                return False

        combined_tlds = find_top_level_domains()
        if tld in combined_tlds:
            # Single term TLD check
            return True

        elif any(domain.endswith(d) for d in TLDS_SPECIAL_BY_DOMAIN):
            # Multi-term TLD check
            return True

    return False


def is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) == 4:
        for p in parts:
            try:
                if not (0 <= int(p) <= 255):
                    return False
            except ValueError:
                return False

        if int(parts[0]) == 0:
            return False

        if int(parts[3]) == 0:
            return False

        return True

    return False


def is_ip_in_network(ip: str, network: IPv4Network) -> bool:
    if not is_valid_ip(ip):
        return False

    return ip_address(ip) in network


def is_valid_email(email: str) -> bool:
    parts = email.split("@")
    if len(parts) == 2:
        if is_valid_domain(parts[1]):
            return True

    return False


def get_hostname() -> str:
    return socket.gethostname()
