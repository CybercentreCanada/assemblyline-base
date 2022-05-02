from ipaddress import ip_address, IPv4Network
import socket
import subprocess
import sys
import uuid
from random import randint

import netifaces as nif
import pr2modules.iproute as iproute

from assemblyline.common.net_static import TLDS_ALPHA_BY_DOMAIN


def is_valid_port(value: int) -> bool:
    try:
        if 1 <= int(value) <= 65535:
            return True
    except ValueError:
        pass

    return False


def is_valid_domain(domain: str) -> bool:
    if "@" in domain:
        return False

    if "." in domain:
        tld = domain.split(".")[-1]
        return tld.upper() in TLDS_ALPHA_BY_DOMAIN

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


def get_mac_address() -> str:
    return "".join(["{0:02x}".format((uuid.getnode() >> i) & 0xff) for i in range(0, 8 * 6, 8)][::-1]).upper()


def get_mac_for_ip(ip: str) -> str:
    for i in nif.interfaces():
        addrs = nif.ifaddresses(i)
        try:
            if_mac = addrs[nif.AF_LINK][0]['addr']
            if_ip = addrs[nif.AF_INET][0]['addr']
        except (IndexError, KeyError):
            if_mac = if_ip = None

        if if_ip == ip:
            return if_mac.replace(':', '').upper()

    # If we couldn't match on IP just use the old uuid based approach.
    return get_mac_address()


def get_random_mac(separator: str = ':') -> str:
    oui = [0x52, 0x54, 0x00]
    mac = oui + [randint(0, 0xff), randint(0, 0xff), randint(0, 0xff)]
    return separator.join("%02x" % x for x in mac).upper()


def get_route_to(dst: str) -> str:
    ret_val = None
    try:
        with iproute.IPRoute() as ipr:
            for k, v in ipr.route('get', dst=dst)[0]['attrs']:
                if k == "RTA_PREFSRC":
                    ret_val = v
                    break
    except (ImportError, KeyError, ValueError):
        if sys.platform.startswith('linux'):
            cmdline = 'ip route get to {dst} | sed -e "s/.*src //" | head -n 1 | sed -e "s/ .*//"'.format(dst=dst)
            p = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdout, stderr = p.communicate()
            if stdout:
                ret_val = stdout.strip()
    finally:
        return ret_val


def get_hostip() -> str:
    ip = None
    try:
        from assemblyline.common import forge
        config = forge.get_config()
        ip = get_route_to(config.datastore.hosts[0])
    except Exception:
        pass

    return ip or get_default_gateway_ip()


def get_default_gateway_ip() -> str:
    # fetch the nic serving up the default gateway
    if_default = nif.gateways().get('default')
    (ip, nic) = if_default.get(nif.AF_INET)
    # Fetch the IP of that nic
    try:
        ip = nif.ifaddresses(nic).get(nif.AF_INET)[0].get('addr')
    except (IndexError, KeyError):
        subnet = ip.split(".")[0]
        if sys.platform.startswith('win'):
            proc = subprocess.Popen('ipconfig', stdout=subprocess.PIPE, text=True)
            output = proc.stdout.read()
            for line in output.split('\n'):
                if "IP Address" in line and ": %s" % subnet in line:
                    ip = line.split(": ")[1].replace('\r', '')
                    break

        else:
            proc = subprocess.Popen('ifconfig', stdout=subprocess.PIPE, text=True)
            output = proc.stdout.read()

            for line in output.split('\n'):
                if "addr:%s" % subnet in line:
                    ip = line.split("addr:")[1].split(" ")[0]
                    break

    return ip
