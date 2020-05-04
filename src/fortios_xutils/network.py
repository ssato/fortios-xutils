#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Collect network info from fortios' configuration.
"""
from __future__ import absolute_import

import functools
import ipaddress
import os.path

import anyconfig

from . import netutils, parser, utils


NET_MAX_PREFIX = 24
NET_FILENAME = "netowrks.json"


def list_interfaces_from_configs_itr(cnf, **sargs):
    """
    Get a list of interface addresses from interface configuration data.

    :param cnf: A mapping object holding fortios configuration data
    :param sargs: Keyword argument will be passed to parser.jmespath_search

    :yield: A list of ipaddress.IPv*Interface objects give interface addresses
    """
    query = "configs[?config=='system interface'].edits[].ip"

    return [ipaddress.ip_interface("{}/{}".format(*ip)) for ip
            in parser.jmespath_search(query, cnf, **sargs)]


@functools.lru_cache(maxsize=32)
def network_from_ipa(ipa, netmask=None):
    """
    :param ipa: ip address string
    :param netmask: netmask string

    :return: A str gives network address of given `ipa`

    >>> network_from_ipa("192.168.1.1")
    '192.168.1.1/32'
    >>> network_from_ipa("192.168.1.0", "255.255.255.0")
    '192.168.1.0/24'
    """
    if not netmask:
        netmask = '32'  # prefix for the network has an IP in it.

    return str(ipaddress.ip_interface("{}/{}".format(ipa, netmask)).network)


def networks_from_firewall_address_configs(cnf, **sargs):
    """
    Get a list of network addresses from firewall address configuration data.

    :param cnf: A mapping object holding fortios configuration data
    :param sargs: Keyword argument will be passed to parser.jmespath_search

    :yield: A str gives a network address
    """
    query = "configs[?config=='firewall address'].edits[][?subnet].subnet"

    return list(set(network_from_ipa(ipa, nmask) for ipa, nmask
                    in parser.jmespath_search(query, cnf, **sargs)))


def make_net_node(net):
    """
    :param net: A ipaddress.IPv*Network object
    :return: A mapping object represents the network node

    :return: A mapping object will be used in D3.js
    """
    net_s = str(net)
    return dict(id=net_s, name=net_s, type="network", addrs=[net_s])


def make_edge_node(nodes, weight, distance):
    """
    :param nodes: A tuple of address strings
    :param weight: An int gives edge's weight
    :param distance: 'Distance' between edges

    :return: A mapping object will be used in D3.js
    """
    name = "{}_{}".format(*nodes)

    return dict(type="edge", weight=weight, distance=distance,
                id=name, name=name, source=nodes[0], target=nodes[1])


def _node_and_edges_from_fa_networks_itr(inets, nets):
    """
    :param inets:
        A list of network addresses with prefix, e.g. 10.0.1.0/24, of which
        network is linked to the interface
    :param networks:
        A list of network addresses with prefix same as the above but came from
        the other configuration data such like firewall address list
    """
    for net in nets:
        inet = netutils.find_nearest_network(net, inets)
        if inet == net:
            continue

        distance = netutils.distance(net, inet)
        weight = 10 / distance

        yield make_net_node(net)
        yield make_edge_node((inet, net), weight, distance)


def node_and_edges_from_config_file_itr(filepath, prefix=NET_MAX_PREFIX):
    """
    Get a node and edges (node and network links) information from fortigate's
    parsed configuration file.

    :param filepath: Path to the JSON file contains fortigate's configurations
    :param prefix: 'Largest' network prefix to find

    :return: A graph data
    """
    cnf = parser.load(filepath)
    opts = dict(has_vdoms_=parser.has_vdom(cnf))

    hostname = parser.hostname_from_configs(cnf, **opts)
    ifaces = list(list_interfaces_from_configs_itr(cnf, **opts))

    host = dict(id=hostname, type="firewall", addrs=[str(i) for i in ifaces])
    yield host  # host node

    ifns = [i.network for i in ifaces]  # :: [IPv4Network]
    for ifn in ifns:
        yield make_net_node(ifn)  # (network) node
        yield make_edge_node((hostname, str(ifn)), 10, 1)

    inets = [str(i) for i in ifns]  # :: [str]
    nfas = networks_from_firewall_address_configs(cnf, **opts)  # :: [str]

    # networks connected from the interfaces
    cnets = [a for a in nfas
             if (netutils.is_network_address(a) and
                 a not in inets and
                 a != "0.0.0.0/32")]
    for obj in _node_and_edges_from_fa_networks_itr(inets, cnets):
        yield obj

    # compute networks contains the hosts not in the previous `cnets` connected
    # from the interfaces.
    cnets = set(str(ipaddress.ip_network(a).supernet(new_prefix=prefix))
                for a in nfas
                if (a not in cnets + inets and
                    not netutils.is_ip_in_addrs(a, cnets)))

    for obj in _node_and_edges_from_fa_networks_itr(inets, cnets):
        yield obj


def make_ans_save_networks_from_config_file(filepath, outpath=None,
                                            prefix=NET_MAX_PREFIX):
    """
    Make a graph of networks of nodes and edges (node and network links)
    information from fortigate's parsed configuration file.

    :param filepath: Path to the JSON file contains fortigate's configurations
    :param prefix: 'Largest' network prefix to find

    :return: A graph data
    """
    graph = list(node_and_edges_from_config_file_itr(filepath, prefix=prefix))
    nodes = [x for x in graph if x["type"] != "edge"]
    edges = [x for x in graph if x["type"] == "edge"]

    if not outpath:
        outpath = os.path.join(os.path.dirname(filepath), NET_FILENAME)

    metadata = dict(input=filepath, prefix=prefix, timestamp=utils.timestamp())
    res = dict(metadata=metadata, nodes=nodes, links=edges)

    utils.ensure_dir_exists(outpath)
    anyconfig.dump(res, outpath)

    return res

# vim:sw=4:ts=4:et:
