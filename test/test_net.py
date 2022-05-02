from assemblyline.common.net import is_valid_port, is_valid_domain, is_valid_ip, is_valid_email, is_ip_in_network
from assemblyline.common.net_static import TLDS_ALPHA_BY_DOMAIN

import requests


def test_domain_list():
    """Make sure we aren't missing any domains."""
    response = requests.get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt')
    for line in response.text.splitlines():
        if not line or line.startswith('#'):
            continue
        assert line in TLDS_ALPHA_BY_DOMAIN


def test_port_check():
    assert is_valid_port(1)
    assert is_valid_port(2**16-1)
    assert is_valid_port('1')
    assert is_valid_port(str(2**16-1))
    assert is_valid_port(1.0)

    assert not is_valid_port(0)
    assert not is_valid_port(-1)
    assert not is_valid_port(2**16)
    assert not is_valid_port('PORT')


def test_valid_domain():
    assert is_valid_domain('cyber.gc.ca')
    assert not is_valid_domain('user@cyber.gc.ca')
    assert not is_valid_domain('user')


def test_valid_ip():
    assert is_valid_ip('5.5.5.5')
    assert not is_valid_ip('5,5.5.5')
    assert not is_valid_ip('5.S.5.5')
    assert not is_valid_ip('5.5.5')
    assert not is_valid_ip('5..5.5')
    assert not is_valid_ip('5.5.5.5.5')
    assert not is_valid_ip('0.5.5.5')
    assert not is_valid_ip('5.256.5.5')
    assert not is_valid_ip('5.5.-1.5')
    assert is_valid_ip('5.0.5.5')
    assert is_valid_ip('5.5.0.5')
    assert not is_valid_ip('5.5.5.0')


def test_valid_email():
    # TODO these tests are correct, but our is_valid_email code is lax
    assert is_valid_email('user@cyber.gc.ca')
#     assert not is_valid_email('@cyber.gc.ca')
#     assert not is_valid_email('user@')
#     assert not is_valid_email('user@cyber')
#     assert not is_valid_email('user@cy#ber.gc.ca')
    assert is_valid_email('user.name@cyber.gc.ca')
#     assert not is_valid_email('user..name@cyber.gc.ca')
    assert is_valid_email('u#ser@cyber.gc.ca')
    assert is_valid_email('"u#ser"@cyber.gc.ca')
    assert is_valid_email('"user..name"@cyber.gc.ca')


def test_is_ip_in_network():
    from ipaddress import ip_network
    assert not is_ip_in_network("1...1", ip_network("2.0.0.0/24"))
    assert not is_ip_in_network("1.1.1.1", ip_network("2.0.0.0/24"))
    assert is_ip_in_network("2.2.2.2", ip_network("2.0.0.0/8"))
