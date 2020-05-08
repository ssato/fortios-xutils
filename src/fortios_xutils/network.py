#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Collect network info from fortios' configuration.
"""
from __future__ import absolute_import

import collections.abc
import functools
import ipaddress
import itertools
import logging
import os.path

import anyconfig

from . import netutils, parser, utils


NET_MAX_PREFIX = 24
NET_FILENAME = "networks.yml"
NET_ALL_FILENAME = "composed_networks.json"

NET_DATA_FMT_VER = "1.0"

LOGGER = logging.getLogger(__name__)


def list_interfaces_from_configs(cnf, **sargs):
    """
    Get a list of interface addresses from interface configuration data.

    :param cnf: A mapping object holding fortios configuration data
    :param sargs: Keyword argument will be passed to parser.jmespath_search

    :return: A list of ipaddress.IPv*Interface objects give interface addresses
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


def make_edge_node(nodes, distance):
    """
    :param nodes: A tuple of address strings
    :param distance: 'Distance' between edges

    :return: A mapping object will be used in D3.js
    """
    name = "{}_{}".format(*nodes)

    return dict(type="edge", distance=distance, id=name,
                source=nodes[0], target=nodes[1])


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
        if distance == netutils.math.inf:
            distance = 32 * 2  # Avoid JSON syntax error by math.inf.

        yield make_net_node(net)
        yield make_edge_node((inet, net), distance)


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
    ifaces = list_interfaces_from_configs(cnf, **opts)

    host = dict(id=hostname, name=hostname, type="firewall",
                addrs=[str(i) for i in ifaces])
    yield host  # host node

    ifns = [i.network for i in ifaces]  # :: [IPv4Network]
    for ifn in ifns:
        yield make_net_node(ifn)  # (network) node
        yield make_edge_node((hostname, str(ifn)), 1)

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


def make_and_save_networks_from_config_file(filepath, outpath=None,
                                            prefix=NET_MAX_PREFIX):
    """
    Make a graph of networks of nodes and edges (node and network links)
    information from fortigate's parsed configuration file.

    :param filepath: Path to the JSON file contains fortigate's configurations
    :param prefix: 'Largest' network prefix to find

    :return: A graph data contains metadata, nodes and links data
    """
    graph = list(node_and_edges_from_config_file_itr(filepath, prefix=prefix))
    nodes = [x for x in graph if x["type"] != "edge"]
    edges = [x for x in graph if x["type"] == "edge"]

    if not outpath:
        outpath = os.path.join(os.path.dirname(filepath), NET_FILENAME)

    metadata = dict(type="metadata" ,input=filepath, prefix=prefix,
                    timestamp=utils.timestamp(), version=NET_DATA_FMT_VER)
    res = dict(metadata=metadata, nodes=nodes, links=edges)

    utils.ensure_dir_exists(outpath)
    anyconfig.dump(res, outpath)

    return res


def make_and_save_networks_from_config_files_itr(filepaths,
                                                 prefix=NET_MAX_PREFIX):
    """
    Similar to :func:`make_and_save_networks_from_config_file` but allow giving
    multiple file paths.

    :param filepaths:
        A list of paths to the JSON files contains the parsed results of
        fortigate's 'show configuration' outputs
    :param prefix: 'Largest' network prefix to find

    :yield:
        A tuple of (input file path, graph data contains metadata, nodes and
        links data)
    """
    for fpath in filepaths:
        yield (fpath,
               make_and_save_networks_from_config_file(fpath, prefix=prefix))


def load_network_graph_files_itr(filepaths):
    """
    Load netowrk graph data

    :param filepaths:
        A list of path to the JSON file contains network graph data

    :return: A graph data contains metadata, nodes and links data
    """
    for filepath in filepaths:
        graph = anyconfig.load(filepath)

        if not isinstance(graph, collections.abc.Mapping) or \
                "nodes" not in graph or "links" not in graph:
            LOGGER.warning("Not look network graph data: %s", filepath)
            continue

        yield graph["metadata"]

        for node in graph["nodes"]:
            yield node

        for link in graph["links"]:
            yield link


def _compose_nodes_itr(graph):
    """Compose nodes.
    """
    # select unique nodes
    nodes = {n["id"]: n for n in graph
             if n["type"] not in ("edge", "metadata")}.values()

    for node in nodes:
        node["class"] = "node {type}".format(**node)
        node["label"] = "{id} {type}".format(**node)

        yield node


def compose_network_graph_files(filepaths, outpath=None):
    """
    Make a graph of networks of nodes and edges (node and network links)
    information from fortigate's parsed configuration file.

    :param filepaths:
        A list of path to the JSON file contains network graph data
    :param outpath: Output file path

    :return: A graph data contains metadata, nodes and links data
    """
    (nit, lit, mit) = itertools.tee(load_network_graph_files_itr(filepaths), 3)

    nodes = list(_compose_nodes_itr(nit))
    links = list({l["id"]: l for l in lit if l["type"] == "edge"}.values())

    metadata = dict(inputs=[m["input"] for m in mit
                            if m["type"] == "metadata"],
                    timestamp=utils.timestamp(), version=NET_DATA_FMT_VER)

    res = dict(metadata=metadata, nodes=nodes, links=links)

    if not outpath:
        outpath = os.path.join(os.path.dirname(filepaths[0]), NET_ALL_FILENAME)

    utils.ensure_dir_exists(outpath)
    anyconfig.dump(res, outpath)

    return res

# vim:sw=4:ts=4:et:
