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

FWP_TABLE_FILENAME = "firewall_policy_table.data.json"

# .. seealso:: :func:`pandas.DataFrame.to_json`
COMPRESSION_EXTS = set("gz bz2 zip xz".split())


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
        in df_fa[df_fa["edit"] == edit].fillna('').to_dict(orient="records")
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


def _get_exts(filepath):
    """
    >>> _get_exts("/a/b.pickle.gz")
    ['gz', 'pickle']
    >>> _get_exts("/a/b.pickle")
    ['pickle']
    >>> _get_exts("/a/b/c")
    []
    """
    return list(reversed(os.path.basename(filepath).split('.')[1:]))


def guess_file_type(filepath):
    """
    :param filepath: File path
    :return: a str denotes the file type

    >>> guess_file_type(  # doctest: +IGNORE_EXCEPTION_DETAIL
    ...     "x",
    ... )
    Traceback (most recent call last):
    ValueError: ...
    >>> guess_file_type("/a/b.pickle.gz")
    'pickle'
    >>> guess_file_type("/a/b.json")
    'json'
    >>> guess_file_type("c.pickle")
    'pickle'
    """
    fname = os.path.basename(filepath)
    exts = _get_exts(fname)

    if not exts or '.' not in fname:
        raise ValueError("Unknown file type: " + fname)

    if exts[0] in COMPRESSION_EXTS:
        if len(exts) < 2:
            raise ValueError("Invalid file type: " + fname)

        return exts[1]

    return exts[0]


def pandas_save(rdf, outpath):
    """
    :param rdf: A :class:`pandas.DataFrame` object
    :param outpath: Output file path
    """
    ftype = guess_file_type(outpath)
    try:
        save_fn = getattr(rdf, "to_{}".format(ftype))
    except AttributeError:
        raise ValueError("Looks an invalid filetype: outpath={}, "
                         "(detected/given) filetype={}".format(outpath, ftype))

    utils.ensure_dir_exists(outpath)
    save_fn(outpath)


def make_and_save_firewall_policy_table(filepath, outpath, vdom=None):
    """
    :param filepath: Path to the JSON file contains fortigate's configurations
    :param outpath: Output file path
    :param vdom: Specify vdom to make table

    :return: A :class:`pandas.DataFrame` object
    """
    rdf = make_firewall_policy_table(filepath, vdom=vdom)
    pandas_save(rdf, outpath)

    return rdf


def make_and_save_firewall_policy_tables_itr(filepaths, outname=None,
                                             outdir=False, vdom=None):
    """
    :param filepath: Path to the JSON file contains fortigate's configurations
    :param outpath: Output file path for the first filepath
    :param outdir: Dir to save outputs [same dir input files exist]
    :param vdom: Specify vdom to make table

    :return: A generator yields :class:`pandas.DataFrame` object
    """
    oname = outname if outname else FWP_TABLE_FILENAME

    for fpath, outpath in utils.get_io_paths(filepaths, oname, outdir=outdir):
        yield make_and_save_firewall_policy_table(fpath, outpath, vdom=vdom)


def make_and_save_firewall_policy_tables(filepaths, outname=None, outdir=False,
                                         vdom=None):
    """
    :param filepath: Path to the JSON file contains fortigate's configurations
    :param outname: Output file name for the first filepath
    :param outdir: Dir to save outputs [same dir input files exist]
    :param vdom: Specify vdom to make table

    :return: A list of :class:`pandas.DataFrame` objects
    """
    return list(
        make_and_save_firewall_policy_tables_itr(
            filepaths, outname=outname, outdir=outdir, vdom=vdom
        )
    )


def pandas_load(inpath):
    """
    :param inpath: Output file path
    """
    ftype = guess_file_type(inpath)
    try:
        load_fn = getattr(pandas, "read_{}".format(ftype))
    except AttributeError:
        raise ValueError("Looks an invalid filetype: outpath={}, "
                         "(detected/given) filetype={}".format(inpath, ftype))

    return load_fn(inpath)


def load_firewall_policy_table(filepath):
    """
    :param filepath: Path to the JSON file contains fortigate's configurations

    :return: A :class:`pandas.DataFrame` object
    """
    return pandas_load(filepath)


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
    rdf = tbl_df.fillna('').to_dict(orient="records")
    res = (x for x in rdf
           if any(netutils.is_ip_in_addrs(ip_s, x.get(k, []))
                  for k in addrs_cols))

    return list(res)

# vim:sw=4:ts=4:et:
