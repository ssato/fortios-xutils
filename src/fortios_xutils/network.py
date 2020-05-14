#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Collect network info from fortios' configuration.
"""
from __future__ import absolute_import

import collections.abc
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

# Node is an object may have some attributes.
# - id: a str or int identifies that node
# - name: a str or something describes what that node is
# - type: a str, see the definition of NODE_TYPES below
# - addrs: A list of strings each gives any IP network with prefix
# - **other optional keyword arguments
NODE_TYPES = (
    NODE_ANY, NODE_NET, NODE_HOST, NODE_ROUTER, NODE_SWITCH, NODE_FIREWALL
) = (
    "any", "network", "host", "router", "switch", "firewall"
)

LOGGER = logging.getLogger(__name__)


def add_node_info(node):
    """
    :param node: A mapping object denotes the network / host node
    :return: The mapping object with additional info
    """
    node["type_id"] = NODE_TYPES.index(node["type"])
    node["class"] = "node {0[type]}".format(node)
    node["label"] = "{0[name]} ({0[type]})".format(node)

    return node


def make_net_node(net, extra_info=True):
    """
    :param net: A ipaddress.IPv*Network object
    :return: A mapping object represents the network node
    """
    net_s = str(net)
    node = dict(id=net_s, name=net_s, type=NODE_NET, addrs=[net_s])

    if extra_info:
        node = add_node_info(node)

    return node


def make_edge(nodes, distance):
    """
    :param nodes: A tuple of address strings
    :param distance: 'Distance' between edges

    :return: A mapping object will be used in D3.js
    """
    name = "{}_{}".format(*nodes)

    return dict(type="edge", distance=distance, id=name,
                source=nodes[0], target=nodes[1])


def list_interface_addrs(cnf, **sargs):
    """
    Get a list of interface addresses from interface configuration data.

    :param cnf: A mapping object holding fortios configuration data
    :param sargs: Keyword argument will be passed to parser.jmespath_search

    :return: A list of ipaddress.IPv*Interface objects give interface addresses
    """
    query = "configs[?config=='system interface'].edits[].ip"
    qres = parser.jmespath_search(query, cnf, **sargs) or []

    return [ipaddress.ip_interface("{}/{}".format(*ip)) for ip in qres]


def list_firewall_addrs(cnf, **sargs):
    """
    Get a list of network addresses from firewall address configuration data.

    :param cnf: A mapping object holding fortios configuration data
    :param sargs: Keyword argument will be passed to parser.jmespath_search

    :yield: A str gives a network address
    """
    # .. note:: I don't know why it doesn't work as expected always.
    # query = "configs[?config=='firewall address'].edits[][?subnet].subnet"
    query = "configs[?config=='firewall address'].edits[]"
    qres = parser.jmespath_search(query, cnf, **sargs)
    if not qres:
        return []

    sns = [netutils.subnet_to_ip(*x["subnet"]) for x in qres if "subnet" in x]
    irs = list(itertools.chain.from_iterable(
        netutils.iprange_to_ipsets(x["start-ip"], x["end-ip"])
        for x in qres if x.get("type") == "iprange"
    ))
    return list(set(sns + irs))


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
        yield make_edge((inet, net), distance)


def node_and_edges_from_config_file_itr(filepath, prefix=NET_MAX_PREFIX):
    """
    Get a node and edges (node and network links) information from fortigate's
    parsed configuration file.

    :param filepath: Path to the JSON file contains fortigate's configurations
    :param prefix: 'Largest' network prefix to find

    :return: A graph data
    :raises: ValueError
    """
    cnf = parser.load(filepath)
    if not cnf:
        raise ValueError("Something goes wrong with the input: "
                         "{}".format(filepath))

    opts = dict(has_vdoms_=parser.has_vdom(cnf))

    hostname = parser.hostname_from_configs(cnf, **opts)
    if not hostname:
        raise ValueError("Hostname configuration was not found. "
                         "Is this valid config data?: "
                         "{}".format(filepath))

    ifas = list_interface_addrs(cnf, **opts)  # [<ip_addr_str_w_prefix>]
    if not ifas:
        raise ValueError("Interfaces were not found or ip address "
                         "is not set. Check the configuration data: "
                         "{}".format(filepath))

    host = add_node_info(dict(id=hostname, name=hostname, type=NODE_FIREWALL,
                              addrs=[str(i) for i in ifas]))
    yield host  # host node

    ifns = [i.network for i in ifas]  # :: [IPv4Network]
    for ifn in ifns:
        yield make_net_node(ifn)  # (network) node
        yield make_edge((hostname, str(ifn)), 1)

    inets = [str(i) for i in ifns]  # :: [str]
    fas = list_firewall_addrs(cnf, **opts)  # :: [str]

    # networks connected from the interfaces
    cnets = [a for a in fas
             if (netutils.is_network_address(a) and
                 a not in inets and
                 a != "0.0.0.0/32")]
    for obj in _node_and_edges_from_fa_networks_itr(inets, cnets):
        yield obj

    # compute networks contains the hosts not in the previous `cnets` connected
    # from the interfaces.
    cnets = set(str(ipaddress.ip_network(a).supernet(new_prefix=prefix))
                for a in fas
                if (a not in cnets + inets and
                    not netutils.is_ip_in_addrs(a, cnets)))

    for obj in _node_and_edges_from_fa_networks_itr(inets, cnets):
        yield obj


def collect_networks_from_config_file(filepath, prefix=NET_MAX_PREFIX):
    """
    Collect network infrmation from fortigate's parsed configuration file, and
    make a graph of netwrks of nodes and edges (node and network links).

    :param filepath: Path to the JSON file contains fortigate's configurations
    :param prefix: 'Largest' network prefix to find

    :return: A graph data contains metadata, nodes and links data
    :raises: ValueError
    """
    graph = list(node_and_edges_from_config_file_itr(filepath, prefix=prefix))
    nodes = [x for x in graph if x["type"] != "edge"]
    edges = [x for x in graph if x["type"] == "edge"]

    metadata = dict(type="metadata", source=filepath, network_prefix=prefix,
                    timestamp=utils.timestamp(), version=NET_DATA_FMT_VER)
    return dict(metadata=metadata, nodes=nodes, links=edges)


def collect_networks_from_config_files(filepaths, prefix=NET_MAX_PREFIX):
    """
    Similar to :func:`collect_networks_from_config_file` but collect data from
    multiple files.

    :param filepaths:
        A list of paths to the JSON files contains the parsed results of
        fortigate's 'show configuration' outputs
    :param prefix: 'Largest' network prefix to find

    :return: A list of graph data contains metadata, nodes and links data
    """
    return [collect_networks_from_config_file(f, prefix=prefix)
            for f in filepaths]


def collect_and_save_networks_from_config_files_itr(filepaths, outdir=False,
                                                    prefix=NET_MAX_PREFIX):
    """
    Collect network infrmation from fortigate's parsed configuration file, and
    make a graph of netwrks of nodes and edges (node and network links).

    :param filepaths:
        A list of paths to the JSON files contains the parsed results of
        fortigate's 'show configuration' outputs
    :param outdir: Dir to save outputs [same dir input files exist]
    :param prefix: 'Largest' network prefix to find

    :return: A list of graph data contains metadata, nodes and links data
    """
    for fpath, outpath in utils.get_io_paths(filepaths, NET_FILENAME,
                                             outdir=outdir):
        data = collect_networks_from_config_file(fpath, prefix=prefix)
        utils.save_file(data, outpath)
        yield data


def collect_and_save_networks_from_config_files(filepaths, outdir=False,
                                                prefix=NET_MAX_PREFIX):
    """
    Collect network infrmation from fortigate's parsed configuration file, and
    make a graph of netwrks of nodes and edges (node and network links).

    :param filepaths:
        A list of paths to the JSON files contains the parsed results of
        fortigate's 'show configuration' outputs
    :param outdir: Dir to save outputs [same dir input files exist]
    :param prefix: 'Largest' network prefix to find

    :return: A list of graph data contains metadata, nodes and links data
    """
    return list(
        collect_and_save_networks_from_config_files_itr(
            filepaths, outdir=outdir, prefix=prefix
        )
    )


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


def compose_network_files(filepaths):
    """
    Compose a network graphs consist of nodes and edges (node and network
    links) information collected from fortigate's parsed configuration file.

    :param filepaths:
        A list of path to the JSON file contains network graph data

    :return: A graph data contains metadata, nodes and links data
    """
    (nit, lit, mit) = itertools.tee(load_network_graph_files_itr(filepaths), 3)

    nodes = list(_compose_nodes_itr(nit))
    links = list({link["id"]: link for link in lit
                  if link["type"] == "edge"}.values())

    metadata = dict(sources=[m["source"] for m in mit
                             if m["type"] == "metadata"],
                    timestamp=utils.timestamp(), version=NET_DATA_FMT_VER)

    return dict(metadata=metadata, nodes=nodes, links=links)


def compose_and_save_network_files(filepaths, outpath=False):
    """
    Compose a network graphs consist of nodes and edges (node and network
    links) information collected from fortigate's parsed configuration file.

    :param filepaths:
        A list of path to the JSON file contains network graph data
    :param outpath: Output file path

    :return: A graph data contains metadata, nodes and links data
    """
    res = compose_network_files(filepaths)

    if not outpath:
        outpath = os.path.join(os.path.dirname(filepaths[0]), NET_ALL_FILENAME)

    utils.save_file(res, outpath)

    return res

# vim:sw=4:ts=4:et:
