#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Parse fortios' `show *configuration' outputs and generates various outputs.

.. versionadded:: 0.1.0

   - initial checkin
"""
from __future__ import absolute_import

import functools
import itertools
import os.path

import pandas

from . import netutils, parser, utils


ADDR_TYPES = (IP_SET, IP_NETWORK) = ("ipset", "network")

DF_ZERO = pandas.DataFrame()

ADDRS_COL_NAMES = ("addrs", "srcaddrs", "dstaddrs")

FWP_TABLE_FILENAME = "firewall_policy_table.data.pickle.gz"
COMPRESSION_MAPS = dict(gz="gzip", bz2="bz2", zip='zip', xz='xz')
DEFAULT_COMPRESSION = "gzip"


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

    - iprange:

      {"edit": <edit_id :: int>, "uuid": ...,
       "type": "iprange",
       "start-ip": <ip_address>,
       "end-ip": <ip_address>}

    - unicast (host) or network address

      {"edit": <edit_id :: int>, "uuid": ...,
       "associated-interface": <interface_name>,  # 'system interface' list
       "subnet": [<ip_address>, <netmask>]}
    """
    if "start-ip" in fa_dict:  # iprange
        ipset = netutils.iprange_to_ipsets(fa_dict["start-ip"],
                                           fa_dict["end-ip"])
        fa_dict["addr_type"] = IP_SET
        fa_dict["addrs"] = ipset  # or? ' '.join(ipset)

    elif "subnet" in fa_dict:  # ip address or ip network
        ipa = netutils.subnet_to_ip(*fa_dict["subnet"])  # :: str
        if netutils.is_network_address(ipa):
            fa_dict["addr_type"] = IP_NETWORK
        else:
            fa_dict["type"] = IP_SET

        fa_dict["addrs"] = [ipa]

    else:
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
    keys = ["edit", "uuid", "member"]
    rdf = df_by_query("configs[?config==`firewall addrgrp`].edits[]",
                      cnf, normalize_fn=None,
                      has_vdoms_=has_vdoms_, vdom=vdom
                      )
    if rdf.empty:
        return rdf

    return rdf.explode("member")[keys].reset_index(drop=True)


def make_firewall_address_table(cnf, has_vdoms_=False, vdom=None):
    """
    :param cnf: A mapping object contains firewall configurations
    :param has_vdoms: True if givne `cnf` contains vdoms
    :param vdom: Specify vdom to make table

    :return: A :class:`pandas.DataFrame` object
    """
    opts = dict(has_vdoms_=has_vdoms_, vdom=vdom)

    df_fa = make_firewall_address_table_1(cnf, **opts)
    df_ag = make_firewall_addrgrp_table(cnf, **opts)

    if df_ag.empty:
        return df_fa

    # Add columns (addr*, ...) from df_fa
    df_diff = pandas.merge(
        df_ag, df_fa, left_on="member", right_on="edit",
        suffixes=('', '_r'), how="left"
    ).drop(columns="edit_r").drop(columns="uuid_r").drop(columns="member")

    return pandas.concat([df_fa, df_diff], sort=False)


def get_firewall_address_by_edit(edit, df_fa=DF_ZERO):
    """
    :param edit: A str gives an edit ID
    :param df_fa: A :class:`pandas.DataFrame` object holds firewall addresses

    :return: A list of str gives IP addresses with prefix
    """
    return sorted(itertools.chain.from_iterable(
        e["addrs"] for e
        in df_fa[df_fa["edit"] == edit].fillna('').to_dict(orient="record")
        if e.get("addrs")
    ))


def get_firewall_address_by_edits(edits, df_fa=DF_ZERO):
    """
    :param edits: A edit or a list of edits
    :param df_fa: A :class:`pandas.DataFrame` object holds firewall addresses

    :return: A list of str gives IP addresses with prefix
    """
    if utils.is_str(edits):
        return get_firewall_address_by_edit(edits, df_fa)

    return sorted(itertools.chain.from_iterable(
        get_firewall_address_by_edit(e, df_fa=df_fa) for e in edits
    ))


def resolv_src_and_dst_in_fp(fp_dict, df_fa=DF_ZERO):
    """
    :param fp_dict: A mapping object represents a firewall policy
    :param df_fa: A :class:`pandas.DataFrame` object holds firewall addresses
    """
    fnc = functools.partial(get_firewall_address_by_edits, df_fa=df_fa)

    srcaddr = fp_dict.get("srcaddr", False)
    if srcaddr:
        fp_dict["srcaddrs"] = fnc(srcaddr)

    dstaddr = fp_dict.get("dstaddr", False)
    if dstaddr:
        fp_dict["dstaddrs"] = fnc(dstaddr)

    return fp_dict


def make_firewall_policy_table_1(cnf, df_fa, has_vdoms_=False, vdom=None):
    """
    :param cnf: A mapping object contains firewall configurations
    :param df_fa: A :class:`pandas.DataFrame` object holds firewall addresses
    :param has_vdoms: True if givne `cnf` contains vdoms
    :param vdom: Specify vdom to make table

    :return: A :class:`pandas.DataFrame` object
    """
    fa_keys = ["edit", "addr", "addrs", "comment"]  # TBD
    df_fa = df_fa.drop(columns=[k for k in df_fa.columns if k not in fa_keys])

    fnc = functools.partial(resolv_src_and_dst_in_fp, df_fa=df_fa)

    df_fp = df_by_query("configs[?config==`firewall policy`].edits[]",
                        cnf, normalize_fn=fnc,
                        has_vdoms_=has_vdoms_, vdom=vdom)

    return df_fp


def make_firewall_policy_table(filepath, vdom=None):
    """
    :param filepath: Path to the JSON file contains fortigate's configurations
    :param vdom: Specify vdom to make table

    :return: A :class:`pandas.DataFrame` object
    """
    cnf = parser.load(filepath)
    opts = dict(has_vdoms_=parser.has_vdom(cnf), vdom=vdom)

    df_fa = make_firewall_address_table(cnf, **opts)
    rdf = make_firewall_policy_table_1(cnf, df_fa, **opts)

    return rdf


def make_firewall_policy_tables(filepaths, vdom=None):
    """
    :param filepath: Path to the JSON file contains fortigate's configurations
    :param vdom: Specify vdom to make table

    :return: A list of :class:`pandas.DataFrame` object
    """
    return [make_firewall_policy_table(f, vdom=vdom) for f in filepaths]


def guess_filetype(filepath, compression=None):
    """
    :param filepath: File path
    :param filetype: File type of `filepath`
    :param compression: Compression type
    """
    comp_exts = COMPRESSION_MAPS.keys()
    maybe_ext = os.path.splitext(filepath)[-1]

    if compression or maybe_ext.replace('.', '') in comp_exts:
        maybe_ext = os.path.splitext(os.path.splitext(filepath)[0])[-1]

    return maybe_ext.replace('.', '')


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


def make_and_save_firewall_policy_table(filepath, outpath, vdom=None,
                                        filetype=None,
                                        compression=DEFAULT_COMPRESSION):
    """
    :param filepath: Path to the JSON file contains fortigate's configurations
    :param outpath: Output file path
    :param vdom: Specify vdom to make table
    :param filetype: File type to save as
    :param compression: Compression method

    :return: A :class:`pandas.DataFrame` object
    """
    rdf = make_firewall_policy_table(filepath, vdom=vdom)
    pandas_save(rdf, outpath, filetype=filetype, compression=compression)

    return rdf


def make_and_save_firewall_policy_tables_itr(filepaths, outdir=False,
                                             vdom=None):
    """
    :param filepath: Path to the JSON file contains fortigate's configurations
    :param outdir: Dir to save outputs [same dir input files exist]
    :param vdom: Specify vdom to make table

    :return: A generator yields :class:`pandas.DataFrame` object
    """
    for fpath, outpath in utils.get_io_paths(filepaths, FWP_TABLE_FILENAME,
                                             outdir):
        yield make_and_save_firewall_policy_table(fpath, outpath, vdom=vdom)


def make_and_save_firewall_policy_tables(filepaths, outdir=False, vdom=None):
    """
    :param filepath: Path to the JSON file contains fortigate's configurations
    :param outdir: Dir to save outputs [same dir input files exist]
    :param vdom: Specify vdom to make table

    :return: A list of :class:`pandas.DataFrame` objects
    """
    return list(
        make_and_save_firewall_policy_tables_itr(
            filepaths, outdir=outdir, vdom=vdom
        )
    )


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


def load_firewall_policy_table(filepath, compression=DEFAULT_COMPRESSION):
    """
    :param filepath: Path to the JSON file contains fortigate's configurations
    :param compression: Compression method

    :return: A :class:`pandas.DataFrame` object
    """
    return pandas_load(filepath, compression=compression)


def search_by_addr_1(ip_s, tbl_df, addrs_cols=ADDRS_COL_NAMES):
    """
    :param ip_s: A str represents an IP address
    :param tbl_df:
        A :class:`pandas.DataFrame` object contains ip addresses in the columns
        have one or some of `addrs_cols`.
    :param addrs_cols:
        A list of names of columns may have a set of ip addresses
    """
    if not utils.is_str(ip_s):
        raise ValueError("Expected a str but: {!r}".format(ip_s))

    ip_s = netutils.normalize_ip(ip_s)

    # TODO: I don't know how to accomplish this with pandas.DataFrame.
    rdf = tbl_df.fillna('').to_dict(orient="record")
    res = (x for x in rdf
           if any(netutils.is_ip_in_addrs(ip_s, x.get(k, []))
                  for k in addrs_cols))

    return list(res)

# vim:sw=4:ts=4:et:
