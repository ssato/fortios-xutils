#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Find network nodes.
"""
from __future__ import absolute_import

import collections.abc
import itertools

import networkx

from . import netutils, utils
from .network import NODE_ANY


def validate(cnf, filepath='N/A'):
    """
    Validate `cnf` to fail first.

    :param cnf: Config data loaded or parsed log.
    :param filepath: File path gives config data `cnf`

    :raises: ValueError, TypeError
    """
    if not cnf:
        raise ValueError("No expected data was found in {}".format(filepath))

    if not isinstance(cnf, collections.abc.Mapping):
        raise TypeError("Invalid typed data was found in {}".format(filepath))

    if any(k not in cnf for k in ("nodes", "links")):
        raise ValueError("Nodes and/or links were not found in "
                         "{}".format(filepath))

    if any(not isinstance(cnf[k], collections.abc.Iterable)
           for k in ("nodes", "links")):
        raise ValueError("Invalid types of nodes and links were "
                         "found in {}".format(filepath))


def load(filepath):
    """
    :param filepath:
        File path of network graph data ({'nodes': ..., 'links': ...})
    :param ac_args: keyword arguments given to anyconfig.load

    :return: An instance of networkx.Graph
    """
    cnf = utils.try_ac_load(filepath)
    validate(cnf, filepath)

    graph = networkx.Graph()
    graph.add_nodes_from((n["id"], n) for n in cnf["nodes"])
    for edge in cnf["links"]:
        graph.add_edge(edge["source"], edge["target"], **edge)

    return graph


def graph_nodes_itr(graph):
    """
    :param graph: A networkx.Graph object
    :yield: [{'addrs': [<ip_or_net_address_object>], ...}]
    """
    for idx in graph.nodes:
        yield graph.nodes[idx]


def find_nodes_by_ip_itr(nodes, ipa):
    """
    :param nodes: {'addrs': [<ip_network_address>], 'type': ..., ...}
    :param ipa: A str gives an ip address

    .. note:: 10.0.0.0/8 < 10.1.1.0/24 in ipaddress
    """
    for node in nodes:
        if netutils.is_ip_in_addrs(ipa, node.get("addrs", [])):
            yield node


def find_net_nodes_by_ip(nodes, ipa):
    """
    :param nodes: {'addrs': [<ip_network_address>], 'type': ..., ...}
    :param ipa: A str gives an ip address

    :return: [] or a list of network nodes sorted by its prefix

    .. note:: 10.0.0.0/8 < 10.1.1.0/24 in ipaddress
    """
    def _net_key_fun(node):
        """
        Compute the prefix length of the network `addr` to be used as key to
        sort network address list.
        """
        addr = node["addrs"][0]  # Net nodes should have an addr in addrs only.
        return netutils.to_network(addr).prefixlen

    return sorted(find_nodes_by_ip_itr(nodes, ipa), key=_net_key_fun,
                  reverse=True)


def find_a_net_node_by_ip(nodes, ipa):
    """
    :param nodes: {'addrs': [<ip_network_address>], 'type': ..., ...}
    :param ipa: A str gives an ip address

    :return: A network node or None

    .. seealso:: :func:`find_net_nodes_by_ip`
    """
    nets = find_net_nodes_by_ip(nodes, ipa)
    return nets[0] if nets else None


def select_unique_paths_itr(paths):
    """
    :param paths: A list of lists of nodes in the found paths
    :return: A generator yields a filtered a list of nodes in the paths
    """
    seen = set()
    for path in paths:  # path :: [{id: ..., } (node), ...]
        path_by_node_ids = tuple(n["id"] for n in path)
        if path_by_node_ids not in seen:
            seen.add(path_by_node_ids)
            yield path


def find_paths_itr(graph, src, dst, node_type=False, **nx_opts):
    """
    :param graph: networkx.Graph object to find paths from
    :param src: ipaddress.ip_address object or a string represents IP address
    :param dst: ipaddress.ip_address object or a string represents IP address
    :param node_type: Node type to filter results if given
    :param nx_opts:
        Keyword options given to networkx.all_shortest_paths() such as method,
        and weight

    :yield: A lists of nodes in the found paths
    :raises: ValueError if given src and/or dst is not an IP address string
    """
    (nodes_1, nodes_2) = itertools.tee(graph_nodes_itr(graph))

    src_net = find_a_net_node_by_ip(nodes_1, src)
    dst_net = find_a_net_node_by_ip(nodes_2, dst)

    if not src_net or not dst_net:
        return

    if src_net == dst_net:
        if not node_type or (node_type and node_type != NODE_ANY and
                             src_net["type"] == node_type):
            yield [src_net]

        return

    nss = networkx.all_shortest_paths(graph, src_net["id"], dst_net["id"],
                                      **nx_opts)
    res = [[n for n in graph_nodes_itr(graph) if n["id"] in ns] for ns in nss]

    if node_type and node_type != NODE_ANY:
        # Those paths might be degenerated and need to remove duplicates.
        pitr = ([n for n in ns if n["type"] == node_type] for ns in res)
        res = list(select_unique_paths_itr(pitr))

    for npath in res:
        # yield [src_net] + npath + [dst_net]
        yield npath


def find_paths(graph, src, dst, node_type=False, **nx_opts):
    """
    :param graph: networkx.Graph object to find paths from
    :param src: ipaddress.ip_address object or a string represents IP address
    :param dst: ipaddress.ip_address object or a string represents IP address
    :param node_type: Node type to filter results if given
    :param nx_opts:
        Keyword options given to networkx.all_shortest_paths() such as method,
        and weight

    :yield: A lists of nodes in the found paths
    :raises: ValueError if given src and/or dst is not an IP address string
    """
    return list(find_paths_itr(graph, src, dst, node_type=node_type,
                               **nx_opts))

# vim:sw=4:ts=4:et:
