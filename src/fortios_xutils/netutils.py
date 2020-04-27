#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Network relaated functions.
"""
from __future__ import absolute_import

import functools
import ipaddress
import re

import netaddr

from . import utils


IPV4_IP_RE_S = r"^(\d{1,3}\.){3}\d{1,3}"
IPV4_IP_RE = re.compile(IPV4_IP_RE_S + r'$')
CIDR_RE = re.compile(IPV4_IP_RE_S + r'/' + IPV4_IP_RE_S + r'$')
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


def is_network_address_object(obj):
    """
    :return: True if given `obj` is an IPv*Network object

    >>> net1 = "192.168.122.0/24"
    >>> is_network_address_object(ipaddress.ip_network(net1))
    True
    >>> is_network_address_object(net1)
    False
    """
    return isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network))


@functools.lru_cache(maxsize=32)
def is_ip_in_network(ip_s, net_s):
    """
    :param ip_s: A str represents an (unicast, host) IP address, e.g. 10.1.1.1
    :param net_s: A str represents a network address, e.g. 10.0.0.0/8
    :return: True if the network `net_s` contains the ip `ip_s`
    """
    try:
        return ipaddress.ip_interface(ip_s) in ipaddress.ip_network(net_s)
    except ValueError:  # Wrong type of ip_s and/or net_s were given.
        return False


@functools.lru_cache(maxsize=32)
def ip_to_network(net_s):
    """
    Convert a str `net_s` to ipaddress.IPv*Network object.
    """
    try:
        return ipaddress.ip_network(net_s)
    except ValueError:
        pass

    return []   # Mzero for (ipaddress.IP*, in operator)


@functools.lru_cache(maxsize=32)
def is_ip_in_networks(ip_s, nets):
    """
    :param ip_s: A str gives an (unicast, host) IP address, e.g. 10.1.1.1
    :param nets: A list of str-es give network addresses, e.g. 10.0.0.0/8

    :return: True if any of the network in `nets` contains the ip `ip_s`
    """
    try:
        ipi = ipaddress.ip_interface(ip_s)
        return any(ipi in ipaddress.ip_network(n) for n in nets)
    except ValueError:  # Wrong type of ip_s and/or net_s were given.
        return False


@functools.lru_cache(maxsize=32)
def to_network_or_interface(addr_s):
    """
    :param addr_s:
        A str represents an any IP address, maybe a host (unicast) or network
        address
    """
    if isinstance(addr_s, (ipaddress.IPv4Network, ipaddress.IPv6Network,
                           ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
        return addr_s  # Nothing to do.

    if not utils.is_str(addr_s):
        raise ValueError("A str is expected but not: {!r}".format(addr_s))

    obj = ipaddress.ip_interface(addr_s)
    if str(obj.network) == addr_s:  # It's a network address
        return ipaddress.ip_network(addr_s)

    return obj


def to_networks_or_interfaces_itr(addrs):
    """
    :param addrs:
        A list of a str represents an any IP address, maybe a host (unicast) or
        network address
    """
    for addr in addrs:
        yield to_network_or_interface(addr)


def is_ip_in_addrs(ip_s, addrs):
    """
    :param ip_s: A str represents an (unicast, host) IP address, e.g. 10.1.1.1
    :param addrs:
        A list of str represents a host or a network address, e.g. 10.0.0.0/8,
        192.168.122.1/32

    :return: True if the network `net_s` contains the ip `ip_s`
    """
    if not addrs:
        return False

    ipa = normalize_ip(ip_s)

    if ipa in addrs:  # Try to find exact match case first.
        return True

    ipi = ipaddress.ip_interface(ipa)
    return any(ipi in n for n in (ipaddress.ip_network(a) for a in addrs))


@functools.lru_cache(maxsize=32)
def network_prefix(net_addr):
    """
    :param net_addr: IPv*Network object
    :return: Int value gives a prefix of given network
    :throw: ValueError

    >>> net = ipaddress.ip_network("192.168.122.0/24")
    >>> network_prefix(net)
    24
    >>> intf = ipaddress.ip_interface("192.168.122.1/24")
    >>> ipaddress.ip_network(intf)  # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError: ...
    """
    if not is_network_address_object(net_addr):
        net_addr = ipaddress.ip_network(net_addr)  # :throw: ValueError

    return int(net_addr.compressed.split('/')[-1])


def select_networks_from_addrs_itr(*addrs):
    """
    :param addrs:
        A list of a str represents an IP address or network, or one of
        IPv*Network objects
    :
    """
    for addr in addrs:
        if utils.is_str(addr):
            addr = to_network_or_interface(addr)

        if is_network_address_object(addr):
            yield addr


def summarize_networks(*net_addrs, max_prefix=None):
    """
    Degenerate and summarize given network addresses. For example,

    :param net_addrs: A list of ipaddress.IPv*Network objects
    :param max_prefix: Max prefix of candidate networks

    >>> net1 = ipaddress.ip_network("192.168.122.0/24")
    >>> net2 = ipaddress.ip_interface("192.168.122.2/24")  # !net
    >>> net3 = ipaddress.ip_network("192.168.122.0/28")
    >>> net4 = ipaddress.ip_network("192.168.1.0/24")
    >>> summarize_networks(net1, net2, net3)
    IPv4Network('192.168.122.0/24')
    >>> summarize_networks(net1, net2, net3, net4)
    IPv4Network('192.168.0.0/17')
    >>> summarize_networks(net1, net4, max_prefix=16)
    IPv4Network('192.168.0.0/16')
    >>> net5 = ipaddress.ip_network("10.1.0.0/16")
    >>> summarize_networks(net1, net5)
    >>> summarize_networks(net1, net5, max_prefix=1)
    """
    nets = sorted(select_networks_from_addrs_itr(*net_addrs),
                  key=network_prefix)
    if not nets:
        return None

    if max_prefix is None:
        max_prefix = network_prefix(nets[0])

    # try to find the "smallest" (broadest) network.
    for prefix in sorted(range(1, max_prefix + 1), reverse=True):
        cnet = nets[0].supernet(new_prefix=prefix)
        if all(n.subnet_of(cnet) for n in nets):
            return cnet

    return None

# vim:sw=4:ts=4:et:
