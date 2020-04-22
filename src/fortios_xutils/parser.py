#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Parse fortios' `show *configuration' outputs and generates various outputs.

.. versionadded:: 0.1.0

   - initial checkin
"""
from __future__ import absolute_import

import collections.abc
import logging
import os.path
import re

import anyconfig

from . import utils


CNF_NAMES = ("system.*",
             "firewall service category",
             "firewall service group",
             "firewall service custom",
             "firewall addrgrp",
             "firewall address",
             "firewall policy")

METADATA_FILENAME = "metadata.json"
ALL_FILENAME = "all.json"

LOG = logging.getLogger(__name__)


def has_vdom(cnf):
    """
    .. note:: I guess that it's effective and faster than the following.

       ::

         return bool(jmespath.search("configs[?config=='vdom']", cnf))

    :param cnf: A mapping objects should have key: configs
    :return: True if vdoms are found in given configurations
    """
    return any(c for c in cnf.get("configs", []) if c.get("config") == "vdom")


def jmespath_search_1(path_exp, data, normalize_fn=None):
    """
    Return the result of JMESPath query to
    given data `data`.

    :param path_exp: JMESPath expression for search results
    :param data: A list of mapping objects

    :return: JMESPath search result :: [<mapping object>]
    """
    LOG.debug("%s: JMESPath exp: %s", __name__, path_exp)
    res = utils.search(path_exp, data)
    if callable(normalize_fn):
        if not utils.is_str(res) and isinstance(res, collections.Sequence):
            res = [normalize_fn(r) for r in res]
        else:
            res = normalize_fn(res)

    return res


def _global_path_exp(path_exp):
    """
    :param path_exp: JMESPath expression for search results
    :return: A JMESPath expression to search results

    >>> _global_path_exp("configs[?config=='system global']")
    "configs[?config=='global'] | [0].configs[?config=='system global']"
    """
    return "configs[?config=='global'] | [0]." + path_exp


def _vdoms_path_exp(path_exp, vdom=None):
    """
    :param path_exp: JMESPath expression for search results
    :param vdom: Specify vdom to search for

    :return: A JMESPath expression to search results

    >>> _vdoms_path_exp("configs[?config=='system global']")
    "configs[?config=='vdom'].edits[].configs[?config=='system global'][]"
    >>> _vdoms_path_exp("configs[]", vdom="root")
    "configs[?config=='vdom' && edits[0].edit=='root'].edits[].configs[]"
    """
    if vdom:
        return ("configs[?config=='vdom' && edits[0].edit=='{}']"
                ".edits[].".format(vdom) + path_exp)

    return "configs[?config=='vdom'].edits[]." + path_exp + "[]"


def jmespath_search(path_exp, data, normalize_fn=None, has_vdoms_=False,
                    vdom=None):
    """
    Similar to the above :func:`jmespath_search_1` but takes care the cases of
    configurations have multi vdoms.

    :param path_exp: JMESPath expression for search results
    :param data: A list of mapping objects
    :param has_vdoms_: True if givne `cnf` contains vdoms
    :param vdom: Specify vdom to make table

    :return: JMESPath search result :: [<mapping object>]
    """
    if not has_vdoms_:
        return jmespath_search_1(path_exp, data, normalize_fn=normalize_fn)

    # Both of the following results are type of [dict].
    res_global = jmespath_search_1(_global_path_exp(path_exp), data,
                                   normalize_fn=normalize_fn)
    res_vdoms = jmespath_search_1(_vdoms_path_exp(path_exp, vdom=vdom),
                                  data, normalize_fn=normalize_fn)
    if not res_global:
        return res_vdoms

    return res_global + res_vdoms


def _config_edits_path_exp(cname):
    """
    :param cname: name of the configuration to search

    >>> _config_edits_path_exp("firewall address")
    "configs[?config=='firewall address'].edits[]"
    """
    return "configs[?config=='{}'].edits[]".format(cname)


def config_edits_search(cname, data, normalize_fn=None, has_vdoms_=False,
                        vdom=None):
    """
    Search configruations (edits).

    :param cname: Name of the configuration to search
    :param data: A list of mapping objects
    :param has_vdoms_: True if givne `cnf` contains vdoms
    :param vdom: Specify vdom to make table

    :return: JMESPath search result :: [<mapping object>]
    """
    return config_edits_search(cname, data, normalize_fn=normalize_fn,
                               has_vdoms_=has_vdoms_, vdom=vdom)


def validate(cnf, filepath=None):
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

    if "configs" not in cnf:
        raise ValueError("Configs were not found in {}".format(filepath))

    if not isinstance(cnf["configs"], collections.abc.Iterable):
        raise ValueError("Configs :: [] was not found in {}".format(filepath))


def parse_show_config(filepath):
    """
    Parse 'show full-configuration output and returns a list of parsed configs.

    :param filepath:
        a str or :class:`pathlib.Path` object represents file path contains
        'show full-configuration` or 'show' output

    :return: A mapping object holding configurations
    :raises: IOError, OSError and so on
    """
    cnf = utils.try_ac_load(filepath, type_="fortios")
    validate(cnf, filepath)

    return cnf


def load(filepath):
    """
    Load JSON file contains parsed results

    :param filepath:
        a str or :class:`pathlib.Path` object represents file path contains
        parsed results of 'show full-configuration` or 'show' output

    :return: A mapping object holding configurations
    :raises: IOError, OSError and so on
    """
    cnf = utils.try_ac_load(filepath)
    validate(cnf, filepath)

    return cnf


def hostname_from_configs(cnf, has_vdoms_=False):
    """
    Detect hostname of the fortigate node from its 'system global'
    configuration.

    :param cnf: Config data loaded or parsed log.
    :param has_vdoms_: True if givne `cnf` contains vdoms

    :return: hostname str or None (if hostname was not found)
    """
    sgcnf = jmespath_search("configs[?config=='system global']", cnf,
                            has_vdoms_=has_vdoms_)

    if not sgcnf:  # I believe that it never happen.
        raise ValueError("No system global configs found. Is it correct data?")

    return sgcnf[0].get("hostname", '').lower() or None


def list_vdom_names(cnf):
    """
    Pattern:
        {"config": "vdom",
         "edits": [{"edit": "root"}, ...]}

    :param cnf: Config data loaded or parsed log.
    :param list_names: List vdoms with names

    :return: A list of the name of VDoms
    """
    if not has_vdom(cnf):
        return ["root"]

    vdoms = jmespath_search("configs[?config=='vdom'].edits[0].edit", cnf)
    if not vdoms:
        raise ValueError("VDoms were not found. Is it correct data?")

    return vdoms


def unknown_name():
    """
    Compute the hostname using checksum of `inpath`
    """
    return "unknown-{}".format(utils.timestamp())


def cname_to_filename(cname, ext=".json"):
    """
    :return: A filename generated from `cname`
    """
    return re.sub(r"[\s\"']", '_', cname) + ext


def list_cnames_for_regexp(cnf, regexp=None):
    """List config names.
    """
    return sorted(c for c in jmespath_search("configs[].config[]", cnf)
                  if regexp.match(c))


def parse_show_config_and_dump(inpath, outdir, cnames=CNF_NAMES):
    """
    :param inpath:
        a str or :class:`pathlib.Path` object represents file path contains
        'show full-configuration` or any other 'show ...' outputs
    :param outdir: Dir to save parsed results as JSON files

    :return: A mapping object contains parsed results
    :raises: IOError, OSError
    """
    cnf = parse_show_config(inpath)  # {"configs": [...]}

    vdoms = list_vdom_names(cnf)
    _has_vdoms = vdoms and len(vdoms) > 1

    try:
        # It should have this in most cases.
        hostname = hostname_from_configs(cnf, has_vdoms_=_has_vdoms)
    except ValueError as exc:
        LOG.warning("%r: %s\nCould not resovle hostname", exc, inpath)
        hostname = unknown_name()

    houtdir = os.path.join(outdir, hostname)
    utils.ensure_dir_exists(houtdir)

    anyconfig.dump(cnf, os.path.join(houtdir, ALL_FILENAME))

    gmark = '*'
    opts = dict(has_vdoms_=_has_vdoms)
    for cname in cnames:
        if gmark in cname:
            cregexp = re.compile(cname)
            if cregexp:
                ccnames = list_cnames_for_regexp(cnf, regexp=cregexp)

                for ccn in ccnames:
                    pexp = "configs[?config=='{}'].edits[]".format(ccn)
                    ccnf = jmespath_search(pexp, cnf, **opts)
                    ccname = cname_to_filename(ccn)
                    anyconfig.dump(ccnf, os.path.join(houtdir, ccname))
        else:
            # TODO: Save configs per global and VDoms?
            pexp = "configs[?config=='{}'].edits[]".format(cname)
            ccnf = jmespath_search(pexp, cnf, **opts)
            ccname = cname_to_filename(cname)
            anyconfig.dump(ccnf, os.path.join(houtdir, ccname))

    anyconfig.dump(dict(timestamp=utils.timestamp(), hostname=hostname,
                        vdoms=vdoms, origina_data=inpath),
                   os.path.join(houtdir, METADATA_FILENAME))

    return cnf

# vim:sw=4:ts=4:et: