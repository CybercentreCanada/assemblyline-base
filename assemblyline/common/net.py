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
def find_top_level_domains() -> set[str]:
    """Combine (once and memoize) the three different sources of TLD."""
    single_label_special = {d for d in TLDS_SPECIAL_BY_DOMAIN if '.' not in d}
    local_tlds = {
        tld.strip().strip('.').upper()
        for tld in SYSTEM_LOCAL_TLD.split(";")
        if tld.strip().strip('.')
    }
    return TLDS_ALPHA_BY_DOMAIN | single_label_special | local_tlds


def is_valid_domain(domain: str) -> bool:
    """
    Validate a domain name.

    Checks:
    - No @ symbol
    - Each label contains only alphanumeric characters or hyphens
    - No leading or trailing hyphens in labels
    - TLD is a recognized top-level domain
    """
    if "@" in domain or not domain:
        return False

    labels = domain.split(".")
    for label in labels:
        if not label or label.startswith("-") or label.endswith("-"):
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False

    if len(labels) < 2:
        return False

    tld = labels[-1].upper()
    if not tld.isascii():
        try:
            tld = tld.encode('idna').decode('ascii').upper()
        except ValueError:
            return False

    combined_tlds = find_top_level_domains()
    if tld in combined_tlds:
        return True

    domain_upper = domain.upper()
    return any(domain_upper.endswith(d) for d in TLDS_SPECIAL_BY_DOMAIN)


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
    """
    Validate an email address.

    Checks:
    - Exactly one @ symbol
    - Non-empty local and domain parts
    - Domain passes is_valid_domain()
    - Unquoted local part: no leading/trailing dots, no consecutive dots
    - Quoted local part (e.g., "user..name"): allowed as-is
    """
    if email.count("@") != 1:
        return False

    local, domain = email.rsplit("@", 1)

    if not local or not domain:
        return False

    if not is_valid_domain(domain):
        return False

    if local.startswith('"') and local.endswith('"'):
        return len(local) > 2

    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False

    return True


def get_hostname() -> str:
    return socket.gethostname()
