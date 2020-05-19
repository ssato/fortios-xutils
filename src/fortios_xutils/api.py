#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Find network nodes.
"""
from __future__ import absolute_import

from . import finder, firewall, network, parser, utils

# pylint: disable=unused-import
from .network import (  # noqa: F401
    NODE_TYPES,
    NODE_ANY, NODE_NET, NODE_HOST, NODE_ROUTER, NODE_SWITCH, NODE_FIREWALL
)


def parse_and_save_show_configs(filepaths, outdir):
    """
    :param filepaths:
        An iterable object yields a str or :class:`pathlib.Path` object gives a
        file path, or a str contains '*' (glob) pattern will be expanded to a
        list of strings each gives a file path. Each files must contain
        fortigate's "show full-configuration" or any other 'show ...' outputs
        to parse.

    :param outdir:
        Dir to save parsed results as JSON files. "out/" relative to paths in
        given `filepaths` by default.

    :return:
        A list of a tuple of (input file path, mapping object contains parsed
        results)
    :raises: IOError, OSError
    """
    fsit = utils.expand_glob_paths_itr(filepaths)
    return list(parser.parse_show_configs_and_dump_itr(fsit, outdir))


def _query_json_files_itr(filepaths, path_exp):
    """
    :param filepaths:
        An iterable object yields a str or :class:`pathlib.Path` object gives a
        file path, or a str contains '*' (glob) pattern will be expanded to a
        list of strings each gives a file path. Each files must be in JSON
        format to query using JMESPath expression `path_exp`.

    :param path_exp: JMESPath expression to query

    :yields:
        A tuple of (input file path, a mapping object gives the query result)
    """
    for filepath in utils.expand_glob_paths_itr(filepaths):
        cnf = parser.load(filepath)
        res = parser.jmespath_search(path_exp, cnf,
                                     has_vdoms_=parser.has_vdom(cnf))
        yield (filepath, res)


def query_json_files(filepaths, path_exp):
    """
    :param filepaths:
        An iterable object yields a str or :class:`pathlib.Path` object gives a
        file path, or a str contains '*' (glob) pattern will be expanded to a
        list of strings each gives a file path. Each files must be in JSON
        format to query using JMESPath expression `path_exp`.

    :param path_exp: JMESPath expression to query

    :return:
        A list of tuples of (input file path, a mapping object gives the query
        result)
    """
    return [dict(filepath=t[0], results=t[1]) for t
            in _query_json_files_itr(filepaths, path_exp)]


def collect_networks(filepaths, prefix=network.NET_MAX_PREFIX):
    """
    :param filepaths:
        An iterable object yields a str or :class:`pathlib.Path` object gives a
        file path, or a str contains '*' (glob) pattern will be expanded to a
        list of strings each gives a file path. Each files must be in JSON
        format and contain parsed result of fortigate's "show
        full-configuration" or any other 'show ...' outputs.

    :param prefix:
        Max network prefix to collect; networks with prefix larger than this
        value will be summarized to networks with smaller prefix.

    :return: A tuple of (input file path, a mapping object gives the result)
    """
    fsit = utils.expand_glob_paths_itr(filepaths)
    return network.collect_networks_from_config_files(fsit, prefix=prefix)


def collect_and_save_networks(filepaths, outdir=False,
                              prefix=network.NET_MAX_PREFIX):
    """
    :param filepaths:
        An iterable object yields a str or :class:`pathlib.Path` object gives a
        file path, or a str contains '*' (glob) pattern will be expanded to a
        list of strings each gives a file path. Each files must be in JSON
        format and contain parsed result of fortigate's "show
        full-configuration" or any other 'show ...' outputs.

    :param outdir: Dir to save outputs [same dir input files exist]
    :param prefix:
        Max network prefix to collect; networks with prefix larger than this
        value will be summarized to networks with smaller prefix.

    :return: A tuple of (input file path, a mapping object gives the result)
    """
    fsit = utils.expand_glob_paths_itr(filepaths)
    opts = dict(outdir=outdir, prefix=prefix)

    return network.collect_and_save_networks_from_config_files(fsit, **opts)


def compose_networks(filepaths):
    """
    Compose a network graphs consist of nodes and edges (node and network
    links) information collected from fortigate's parsed configuration file.

    :param filepaths:
        An iterable object yields a path to the JSON file contains network
        graph data

    :return: A graph data contains metadata, nodes and links data
    """
    fsit = utils.expand_glob_paths_itr(filepaths)
    return network.compose_network_files(fsit)


def compose_and_save_networks(filepaths, outpath=False):
    """
    Compose a network graphs consist of nodes and edges (node and network
    links) information collected from fortigate's parsed configuration file.

    :param filepaths:
        An iterable object yields a path to the JSON file contains network
        graph data

    :param outpath: Output file path

    :return: A graph data contains metadata, nodes and links data
    """
    fsit = utils.expand_glob_paths_itr(filepaths)
    return network.compose_and_save_network_files(fsit, outpath=outpath)


def make_firewall_policy_table(filepath):
    """
    :param filepaths:
        An iterable object yields a str or :class:`pathlib.Path` object gives a
        file path, or a str contains '*' (glob) pattern will be expanded to a
        list of strings each gives a file path. Each files must be in JSON
        format and contain parsed result of fortigate's "show
        full-configuration" or any other 'show ...' outputs.

    :return:
        A :class:`pandas.DataFrame` object contains the firewall policy table
        data
    """
    return firewall.make_firewall_policy_table(filepath)


def make_firewall_policy_tables(filepaths):
    """
    :param filepaths:
        An iterable object yields a str or :class:`pathlib.Path` object gives a
        file path, or a str contains '*' (glob) pattern will be expanded to a
        list of strings each gives a file path. Each files must be in JSON
        format and contain parsed result of fortigate's "show
        full-configuration" or any other 'show ...' outputs.

    :return:
        A list of :class:`pandas.DataFrame` objects contain the firewall policy
        table data
    """
    return firewall.make_firewall_policy_tables(filepaths)


def make_and_save_firewall_policy_tables(filepaths, outdir=False):
    """
    :param filepaths:
        An iterable object yields a str or :class:`pathlib.Path` object gives a
        file path, or a str contains '*' (glob) pattern will be expanded to a
        list of strings each gives a file path. Each files must be in JSON
        format and contain parsed result of fortigate's "show
        full-configuration" or any other 'show ...' outputs.

    :param outdir: Output dir to save results

    :return:
        A list of :class:`pandas.DataFrame` objects contain the firewall policy
        table data
    """
    return firewall.make_and_save_firewall_policy_tables(
        filepaths, outdir=outdir
    )


def load_firewall_policy_table(filepath):
    """
    :param filepath:
        Path to the file contains the :class:`pandas.DataFrame` object gives
        firewall policy table data

    :return:
        A :class:`pandas.DataFrame` object gives firewall policy table data
    """
    return firewall.load_firewall_policy_table(filepath)


def search_firewall_policy_table_by_addr(ip_s, tbl_df):
    """
    :param ip_s: A str represents an IP address
    :param filepath:
        Path to the file contains the :class:`pandas.DataFrame` object gives
        firewall policy table data

    :return: A list of mappping objects contains results
    """
    return firewall.search_by_addr_1(ip_s, tbl_df)


def load_network_graph(filepath):
    """
    :param filepath:
        A str or :class:`pathlib.Path` object gives a path of network graph
        data ({'nodes': ..., 'links': ...}) in JSON or YAML formats

    :return: A :class:`networkx.Graph` object contains the network data
    """
    return finder.load(filepath)


def find_network_nodes_by_ip(filepath, ipa):
    """
    :param filepath:
        A str or :class:`pathlib.Path` object gives a path of network graph
        data ({'nodes': ..., 'links': ...}) in JSON or YAML formats

    :param ipa: A str gives an ip address to find nodes

    :return: [] or a list of network nodes sorted by its prefix

    .. note:: 10.0.0.0/8 < 10.1.1.0/24 in ipaddress
    """
    return finder.find_net_nodes_by_ip(filepath, ipa)


def find_network_paths(filepath, src, dst, node_type=False, **nx_opts):
    """
    :param filepath:
        A str or :class:`pathlib.Path` object gives a path of network graph
        data ({'nodes': ..., 'links': ...}) in JSON or YAML formats

    :param src: A str gives an ip address of the source
    :param dst: A str gives an ip address of the destination
    :param node_type: Node type to filter results if given
    :param nx_opts:
        Keyword options given to networkx.all_shortest_paths() such as method,
        and weight

    :return: An iterable object to yield nodes in the found paths
    :raises:
        ValueError if given src and/or dst is not an IP address string, etc.
    """
    return finder.find_paths(filepath, src, dst, node_type=node_type,
                             **nx_opts)

# vim:sw=4:ts=4:et:
