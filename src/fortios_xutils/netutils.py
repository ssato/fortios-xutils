#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Network relaated functions.
"""
from __future__ import absolute_import

import functools
import ipaddress
import math
import operator
import re

import netaddr

from . import utils


IPV4_IP_RE_S = r"^(\d{1,3}\.){3}\d{1,3}"
IPV4_IP_RE = re.compile(IPV4_IP_RE_S + r'(/\d{1,2})?$')
UNI_NETMASK_RE = re.compile(r"^255.255.255.255$")

NET_MAX_PREFIX = 24


@functools.lru_cache(maxsize=32)
def normalize_ip(ip_s, prefix="/32"):
    """
    >>> normalize_ip("192.168.122.1")
    '192.168.122.1/32'
    >>> normalize_ip("192.168.122.1/32")
    '192.168.122.1/32'
    >>> normalize_ip("192.168.122.0/24")
    '192.168.122.0/24'
    """
    if not utils.is_str(ip_s):
        raise ValueError("A str was expected but got: {!r}".format(ip_s))

    if '/' not in ip_s:  # e.g. 192.168.122.1
        return ip_s + prefix  # Normalize it.

    return ip_s


@functools.lru_cache(maxsize=32)
def is_network_address(addr, sep='/'):
    """
    :param addr: IP address string with prefix, e.g. 192.168.1.0/24

    >>> is_network_address("10.0.0.1/32")
    False
    >>> is_network_address("10.0.0.0/8")
    True
    """
    if not utils.is_str(addr):
        raise ValueError("A str is expected but not: {!r}".format(addr))

    if sep in addr:
        return addr.split(sep)[-1] != '32'

    return ipaddress.ip_network(addr).num_addresses > 1


@functools.lru_cache(maxsize=32)
def subnet_to_ip(addr, netmask):
    """
    Convert fortios 'subnet' (addr, netmask) to ipaddress object.

    :return: <ip_address_with_prefix :: str>, e.g. 192.168.1.0/24, 10.0.0.1/32
    """
    if not utils.is_str(addr) or not utils.is_str(netmask):
        raise ValueError("Should be str but: {!r}/{!r}".format(addr, netmask))

    if not IPV4_IP_RE.match(addr) or not IPV4_IP_RE.match(netmask):
        raise ValueError("Should be address but: "
                         "{!s}/{!s}".format(addr, netmask))

    if UNI_NETMASK_RE.match(netmask):  # Unicast (host) address
        return str(ipaddress.ip_interface(addr))

    try:
        return str(ipaddress.ip_network('/'.join((addr, netmask))))
    except ValueError:  # It should be a host address with mask other than /32.
        return str(ipaddress.ip_interface(addr))  # Ignore the original netmask


@functools.lru_cache(maxsize=32)
def iprange_to_ipsets(start_ip, end_ip, prefix=32):
    """
    Convert IP range {start_ip, end_ip} to IP sets [<ip_0>, ...]

    >>> iprange_to_ipsets("192.168.122.1", "192.168.122.3")
    ['192.168.122.1/32', '192.168.122.2/32', '192.168.122.3/32']
    >>> iprange_to_ipsets("192.168.122.1", "192.168.122.3", 24)
    ['192.168.122.1/24', '192.168.122.2/24', '192.168.122.3/24']
    """
    if not utils.is_str(start_ip) or not utils.is_str(end_ip):
        raise ValueError("Should be str but: {!r}/{!r}".format(start_ip,
                                                               end_ip))

    if not IPV4_IP_RE.match(start_ip) or not IPV4_IP_RE.match(end_ip):
        raise ValueError("Should be address but: "
                         "{}/{}".format(start_ip, end_ip))

    # start_ip and end_ip should be in different networks.
    if start_ip.split('.')[0] != end_ip.split('.')[0]:
        raise ValueError("Looks in different networks: "
                         "{}/{}".format(start_ip, end_ip))

    return ["{!s}/{!s}".format(ip, prefix)
            for ip in netaddr.iter_iprange(start_ip, end_ip)]


@functools.lru_cache(maxsize=32)
def to_network(addr_s):
    """
    :param addr_s:
        A str represents an any IP address, maybe a host (unicast) or network
        address
    :return: An IPv*Network object
    :raises: ValueError if given object `addr_s` is not an ip address str

    >>> to_network("10.0.1.0/24")
    IPv4Network('10.0.1.0/24')
    >>> to_network("10.0.1.2/32")
    IPv4Network('10.0.1.2/32')
    >>> to_network("10.0.1.2")
    IPv4Network('10.0.1.2/32')
    >>> to_network("10.0.1.2/24")
    IPv4Network('10.0.1.2/32')
    >>> to_network("aaa")  # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError: ...
    """
    if isinstance(addr_s, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return addr_s  # Nothing to do.

    if not utils.is_str(addr_s):
        raise ValueError("A str was expected but got: {!r}".format(addr_s))

    if not IPV4_IP_RE.match(addr_s):
        raise ValueError("An ip address str was expected but got: "
                         "{!s}".format(addr_s))

    try:
        return ipaddress.ip_network(addr_s)

    # addr_s is an address with host bit set.
    except ValueError:
        addr_s = normalize_ip(addr_s.split('/')[0])
        return ipaddress.ip_network(addr_s)


def to_networks(*addrs):
    """
    :param addrs:
        A list of a str represents an any IP address, maybe a host (unicast) or
        network address
    :return: A list of IPv*Network objects
    """
    return [n for n in (to_network(a) for a in addrs) if n]


def list_addrs_contain_the_ip_itr(ip_s, addrs):
    """
    :param ip_s: A str represents an (unicast, host) IP address, e.g. 10.1.1.1
    :param addrs:
        An iterable of each item represents a host or a network address, e.g.
        10.0.0.0/8, 192.168.122.1/32

    :return: A list of ip addresses of networks contain the ip `ip_s`

    >>> addrs = ("192.168.122.0/24", "192.168.1.0/24", "10.0.1.0/24",
    ...          "192.168.122.1/32", "10.0.1.254/32")
    >>> list(list_addrs_contain_the_ip_itr("192.168.10.254", addrs))
    []
    >>> list(list_addrs_contain_the_ip_itr("10.1.0.254", addrs))
    []
    >>> list(list_addrs_contain_the_ip_itr("192.168.122.1", addrs))
    ['192.168.122.0/24', '192.168.122.1/32']
    >>> list(list_addrs_contain_the_ip_itr("192.168.122.254", addrs))
    ['192.168.122.0/24']
    >>> list(list_addrs_contain_the_ip_itr("10.0.1.1", addrs))
    ['10.0.1.0/24']
    """
    if not addrs:
        return

    ipa = normalize_ip(ip_s)  # Add prefix if it's not set.

    for addr in addrs:
        if ipa == addr:  # Try exact match case first.
            yield addr
            continue

        # Test if the network `addr` contains the ip `ipa`.
        net = to_network(addr)
        if net is None:
            net = to_network(addr.split('/')[0])  # Strip prefix and ...

        if ipaddress.ip_interface(ipa) in net:
            yield addr


def is_ip_in_addrs(ip_s, addrs):
    """
    :param ip_s: A str represents an (unicast, host) IP address, e.g. 10.1.1.1
    :param addrs:
        An iterable of each item represents a host or a network address, e.g.
        10.0.0.0/8, 192.168.122.1/32

    :return: True if the network `net_s` contains the ip `ip_s`

    >>> addrs = ("192.168.122.0/24", "192.168.1.0/24", "10.0.1.0/24",
    ...          "192.168.122.1/32", "10.0.1.254/24")
    >>> is_ip_in_addrs("192.168.10.254", addrs)
    False
    >>> is_ip_in_addrs("10.1.0.254", addrs)
    False
    >>> is_ip_in_addrs("192.168.122.1", addrs)
    True
    >>> is_ip_in_addrs("192.168.122.254", addrs)
    True
    >>> is_ip_in_addrs("10.0.1.1", addrs)
    True
    """
    return any(list_addrs_contain_the_ip_itr(ip_s, addrs))


def _is_subnet_of(net1, net2):
    """An wrapper around ipaddress.IP*Network.subnet_of.

    >>> net1 = ipaddress.ip_network("192.168.122.0/24")
    >>> net2 = ipaddress.ip_network("192.168.0.0/16")
    >>> net3 = ipaddress.ip_network("192.168.1.0/24")
    >>> _is_subnet_of(net1, net1)
    True
    >>> _is_subnet_of(net1, net2)
    True
    >>> _is_subnet_of(net1, net3)
    False
    """
    try:
        return net1.subnet_of(net2)
    except AttributeError:  # ipaddress in py36 does not have the above.
        return (net1 == net2 or
                (net2.network_address <= net1.network_address and
                 net2.broadcast_address >= net1.broadcast_address))


def supernet_of_networks(*net_addrs, max_prefix=32):
    """
    Degenerate and summarize given network addresses. For example,

    :param net_addrs:
        A list of strings gives and ip address with prefix or
        ipaddress.IPv*Network objects
    :param max_prefix: Max prefix of candidate networks

    >>> net1 = "192.168.122.0/24"
    >>> net2 = "192.168.122.2/24"  # !net
    >>> net3 = ipaddress.ip_network("192.168.122.0/28")
    >>> net4 = ipaddress.ip_network("192.168.1.0/24")
    >>> net5 = ipaddress.ip_network("192.168.1.10/32")  # host
    >>> supernet_of_networks(net1, net2, net3)
    IPv4Network('192.168.122.0/24')
    >>> supernet_of_networks(net1, net2, net3, net4)
    IPv4Network('192.168.0.0/17')
    >>> supernet_of_networks(net1, net4, max_prefix=16)
    IPv4Network('192.168.0.0/16')
    >>> net5 = ipaddress.ip_network("10.1.0.0/16")
    >>> supernet_of_networks(net1, net5)
    >>> supernet_of_networks(net1, net5, max_prefix=1)
    """
    nets = sorted(to_networks(*net_addrs),
                  key=operator.attrgetter("prefixlen"))
    if not nets:
        return None

    max_prefix = min(nets[0].prefixlen, max_prefix)

    # try to find the "smallest" (broadest) network.
    for prefix in reversed(range(1, max_prefix + 1)):
        cnet = nets[0].supernet(new_prefix=prefix)
        if all(_is_subnet_of(n, cnet) for n in nets[1:]):
            return cnet

    return None


def distance(net1, net2, base=1):
    """
    Compute 'distance' between a pair of networks by these addresses only.

    :param net1: A str represents a network with prefix, e.g. 10.0.1.0/24
    :param net2: Likewise
    :return: An int gives 'distance' indicator between a pair of networks

    >>> net0 = "192.168.122.1"
    >>> net1 = "192.168.122.0/24"
    >>> net2 = "192.168.0.0/16"
    >>> net3 = "192.168.1.0/24"
    >>> net4 = "192.168.254.0/24"
    >>> net5 = "0.0.0.0/32"
    >>> distance(net1, net1)
    0
    >>> distance(net0, net1)
    1
    >>> distance(net1, net2)
    8
    >>> distance(net1, net3)
    14
    >>> distance(net3, net4)
    16
    >>> distance(net1, net5)
    inf
    """
    if net1 == net2:
        return 0

    no1 = ipaddress.ip_network(net1)
    no2 = ipaddress.ip_network(net2)

    # Case that either net1 or net2 is a host address in other network.
    if no1.num_addresses == 1 and ipaddress.ip_interface(net1) in no2:
        return base

    if no2.num_addresses == 1 and ipaddress.ip_interface(net2) in no1:
        return base

    # Case that either net1 or net2 contains other network.
    if _is_subnet_of(no1, no2) or _is_subnet_of(no2, no1):
        return base * abs(no1.prefixlen - no2.prefixlen)

    snet = supernet_of_networks(no1, no2)
    if snet is None:
        return math.inf

    return base * (no1.prefixlen + no2.prefixlen - 2 * snet.prefixlen)


def find_nearest_network(ipa, nets):
    """
    :param ipa: An ip address string
    :param nets:
        A of str gives and ip address with prefix, e.g. 10.0.1.0/24

    >>> net1 = "192.168.122.0/24"
    >>> net2 = "192.168.0.0/16"
    >>> net3 = "192.168.1.0/24"
    >>> net4 = "192.168.254.0/24"
    >>> net5 = "0.0.0.0/32"
    >>> find_nearest_network(net1, [net1, net5])
    '192.168.122.0/24'
    >>> find_nearest_network(net2, [net1, net5])
    '192.168.122.0/24'
    >>> find_nearest_network(net1, [net2, net3])
    '192.168.0.0/16'
    >>> find_nearest_network(net3, [net1, net4])
    '192.168.122.0/24'
    """
    return sorted(nets, key=functools.partial(distance, ipa))[0]

# vim:sw=4:ts=4:et:
