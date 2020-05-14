#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Find network nodes.
"""
from __future__ import absolute_import

from . import network, parser, utils


def parse_and_save_show_configs(filepaths, outdir):
    """
    :param filepaths:
        An iterable yields path might contains '*' (glob) pattern will be
        expanded to a list of paths of files each gives a str or
        :class:`pathlib.Path` object represents file path contains 'show
        full-configuration` or any other 'show ...' outputs
    :param outdir:
        Dir to save parsed results as JSON files [out/ relative to filepaths]

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
        An iterable yields a path might contain '*' (glob) pattern will be
        expanded to a list of paths to JSON input files to query using JMESPath
        expression.
    :param path_exp: JMESPath expression to query

    :yields: A tuple of (input file path, a mapping object gives the result)
    """
    for filepath in utils.expand_glob_paths_itr(filepaths):
        cnf = parser.load(filepath)
        res = parser.jmespath_search(path_exp, cnf,
                                     has_vdoms_=parser.has_vdom(cnf))
        yield (filepath, res)


def query_json_files(filepaths, path_exp):
    """
    :param filepaths:
        An iterable yields a path might contain '*' (glob) pattern will be
        expanded to a list of paths to JSON input files to query using JMESPath
        expression.
    :param path_exp: JMESPath expression to query

    :return: A tuple of (input file path, a mapping object gives the result)
    """
    return [dict(filepath=t[0], results=t[1]) for t
            in _query_json_files_itr(filepaths, path_exp)]


def collect_networks(filepaths, prefix=network.NET_MAX_PREFIX):
    """
    :param filepaths:
        An iterable yields a path might contain '*' (glob) pattern will be
        expanded to a list of paths to JSON input files which contains parsed
        and structured results of fortigate's configuration outputs
    :param prefix: Max network prefix to collect

    :return: A tuple of (input file path, a mapping object gives the result)
    """
    fsit = utils.expand_glob_paths_itr(filepaths)
    return network.collect_networks_from_config_files(fsit, prefix=prefix)


def collect_and_save_networks(filepaths, outdir=False,
                              prefix=network.NET_MAX_PREFIX):
    """
    :param filepaths:
        An iterable yields a path might contain '*' (glob) pattern will be
        expanded to a list of paths to JSON input files which contains parsed
        and structured results of fortigate's configuration outputs
    :param outdir: Dir to save outputs [same dir input files exist]
    :param prefix: Max network prefix to collect

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
        A list of path to the JSON file contains network graph data

    :return: A graph data contains metadata, nodes and links data
    """
    fsit = utils.expand_glob_paths_itr(filepaths)
    return network.compose_network_files(fsit)


def compose_and_save_networks(filepaths, outpath=False):
    """
    Compose a network graphs consist of nodes and edges (node and network
    links) information collected from fortigate's parsed configuration file.

    :param filepaths:
        A list of path to the JSON file contains network graph data
    :param outpath: Output file path

    :return: A graph data contains metadata, nodes and links data
    """
    fsit = utils.expand_glob_paths_itr(filepaths)
    return network.compose_and_save_network_files(fsit, outpath=outpath)

# vim:sw=4:ts=4:et:
