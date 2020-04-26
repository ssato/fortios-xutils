#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Parse fortios' `show *configuration' outputs and generates various outputs.

.. versionadded:: 0.1.0

   - initial checkin
"""
from __future__ import absolute_import

import os.path

import pandas

from . import netutils, parser, utils


ADDR_TYPES = (IP_SET, IP_NETWORK) = ("ipset", "network")

DF_ZERO = pandas.DataFrame()


def df_by_query(path_exp, data, normalize_fn=None,
                has_vdoms_=False, vdom=None):
    """
    Make :class:`pandas.DataFrame` object from the result of JMESPath query to
    given data `data`.

    :param path_exp: JMESPath expression for search results
    :param data: A list of mapping objects
    :param has_vdoms_: True if givne `cnf` contains vdoms
    :param vdom: Specify vdom to make table

    :return: A :class:`pandas.DataFrame` object
    """
    return pandas.DataFrame(
        parser.jmespath_search(
            path_exp, data, normalize_fn=normalize_fn,
            has_vdoms_=has_vdoms_, vdom=vdom)
    )


def normalize_fa(fa_dict):
    """
    It seems that there are the following types of firewall address 'edit'
    configurations.

    - No IP address:

      {"edit": <edit_id :: int>, "uuid": ...}

    - fqdn:

      {"edit": <edit_id :: int>, "uuid": ...,
       "type": "wildcard-fqdn",
       "wildcard-fqdn": "*.google.com"}   # or "fqdn": "www.example.com"

    - ipset:

      {"edit": <edit_id :: int>, "uuid": ...,
       "type": "ipset",
       "addrs": ['0.0.0.0/32']}

    - iprange:

      {"edit": <edit_id :: int>, "uuid": ...,
       "type": "iprange",
       "start-ip": <ip_address>,
       "end-ip": <ip_address>}

    - unicast (host) ip address or ip network address

      {"edit": <edit_id :: int>, "uuid": ...,
       "associated-interface": <interface_name>,  # 'system interface' list
       "subnet": [<ip_address>, <netmask>]}
    """
    if "start-ip" in fa_dict:  # iprange
        ipset = netutils.iprange_to_ipsets(fa_dict["start-ip"],
                                           fa_dict["end-ip"])
        fa_dict["type"] = IP_SET
        fa_dict["addrs"] = [str(a) for a in ipset]  # expanded ipset
        fa_dict["addr"] = False

    elif "subnet" in fa_dict:  # ip address or ip network
        obj = netutils.subnet_to_ip(*fa_dict["subnet"])

        if netutils.is_network_address_object(obj):
            fa_dict["type"] = IP_NETWORK
            fa_dict["addr"] = str(obj)
            fa_dict["addrs"] = []
        else:
            fa_dict["type"] = IP_SET
            fa_dict["addrs"] = [str(a) for a in obj]
            fa_dict["addr"] = False

    else:
        fa_dict["addr"] = False
        fa_dict["addrs"] = []

    return fa_dict


def make_firewall_address_table_1(cnf, has_vdoms_=False, vdom=None):
    """
    :param cnf: A mapping object contains firewall configurations
    :param has_vdoms: True if givne `cnf` contains vdoms
    :param vdom: Specify vdom to make table

    :return: A :class:`pandas.DataFrame` object
    """
    rdf = df_by_query("configs[?config==`firewall address`].edits[]",
                      cnf, normalize_fn=normalize_fa,
                      has_vdoms_=has_vdoms_, vdom=vdom)
    return rdf


def make_firewall_addrgrp_table(cnf, has_vdoms_=False, vdom=None):
    """
    :param cnf: A mapping object contains firewall configurations
    :param has_vdoms: True if givne `cnf` contains vdoms
    :param vdom: Specify vdom to make table

    :return: A :class:`pandas.DataFrame` object
    """
    rdf = df_by_query("configs[?config==`firewall addrgrp`].edits[]",
                      cnf, normalize_fn=normalize_fa,
                      has_vdoms_=has_vdoms_, vdom=vdom
                      ).explode("member").reset_index(drop=True)
    return rdf


def make_firewall_address_table(cnf, vdom=None):
    """
    :param cnf: A mapping object contains firewall configurations
    :param has_vdoms: True if givne `cnf` contains vdoms
    :param vdom: Specify vdom to make table

    :return: A :class:`pandas.DataFrame` object
    """
    has_vdoms_ = parser.has_vdom(cnf)
    opts = dict(has_vdoms_=has_vdoms_, vdom=vdom)

    df_fa = make_firewall_address_table_1(cnf, **opts)
    df_ag = make_firewall_addrgrp_table(cnf, **opts)

    # Add columns (addr*, ...) from df_fa
    df_diff = pandas.merge(
        df_ag, df_fa, left_on="member", right_on="edit",
        suffixes=('', '_r')
    ).drop(columns="edit_r").drop(columns="uuid_r").drop(columns="member")

    return pandas.concat([df_fa, df_diff], sort=False)


def guess_filetype(filepath, compression=None):
    """
    :param filepath: File path
    :param filetype: File type of `filepath`
    :param compression: Compression type
    """
    if compression:
        fext = os.path.splitext(os.path.splitext(filepath)[0])[-1]
    else:
        fext = os.path.splitext(filepath)[-1]

    return fext.replace('.', '')


def pandas_save(rdf, outpath, filetype=None, compression=None):
    """
    :param rdf: A :class:`pandas.DataFrame` object
    :param outpath: Output file path
    :param filetype: File type to save as
    :param compression: Compression method
    """
    if filetype:
        save_fn_name = "to_" + filetype
    else:
        save_fn_name = "to_" + guess_filetype(outpath, compression=compression)
    try:
        save_fn = getattr(rdf, save_fn_name)
    except AttributeError:
        raise ValueError("Could not find appropriate save functions: "
                         "outpath={}, filetype={!s}".format(outpath, filetype))

    utils.ensure_dir_exists(outpath)
    save_fn(outpath, compression=compression)


def pandas_load(inpath, filetype=None, compression=None):
    """
    :param inpath: Output file path
    :param filetype: File type to save as
    :param compression: Compression method
    """
    load_fn_name = "read_" + (filetype if filetype else guess_filetype(inpath))
    try:
        load_fn = getattr(pandas, load_fn_name)
    except AttributeError:
        raise ValueError("Could not find appropriate load functions: "
                         "inpath={}, filetype={!s}".format(inpath, filetype))

    return load_fn(inpath, compression=compression)


def make_and_save_firewall_address_table(cnf, outpath, vdom=None,
                                         filetype=None, compression=None):
    """
    :param cnf: A mapping object contains firewall configurations
    :param outpath: Output file path
    :param vdom: Specify vdom to make table
    :param filetype: File type to save as
    :param compression: Compression method

    :return: A :class:`pandas.DataFrame` object
    """
    rdf = make_firewall_address_table(cnf, vdom=vdom)
    pandas_save(rdf, outpath, filetype=filetype, compression=compression)

    return rdf


def search_by_addr_1(ip_s, tbl_df):
    """
    :param ip_s: A str represents an IP address
    :param tbl_df: :class:`pandas.DataFrame` object contains ip addresses
    """
    if not utils.is_str(ip_s):
        raise ValueError("Expected a str but: {!r}".format(ip_s))

    if '/' not in ip_s:  # e.g. 192.168.122.1
        ip_s = ip_s + '/32'  # Normalize it.

    def _ip_in_ipset(addrs):
        """Is given IP in the ipsets `addrs`?"""
        return ip_s in addrs if addrs else False

    def _ip_in_net(addr):
        """Is given IP in the network `addrs`?"""
        return netutils.is_ip_in_network(ip_s, addr) if addr else False

    try:
        ipsets = tbl_df[tbl_df.addrs.apply(_ip_in_ipset)]
    except KeyError:
        ipsets = DF_ZERO  # Not found rows have key 'addrs'.

    try:
        nets = tbl_df[tbl_df.addr.apply(_ip_in_net)]
    except KeyError:
        nets = DF_ZERO  # Not found rows have key 'addr'.

    if ipsets.empty:
        return nets

    if nets.empty:
        return ipsets

    return pandas.merge(ipsets, nets, how="outer", on="uuid")

# vim:sw=4:ts=4:et:
