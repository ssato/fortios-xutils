#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Misc CLI commands.

.. versionadded:: 0.1.0

   - initial checkin
"""
from __future__ import absolute_import

import os.path

import anyconfig
import click

from fortios_xutils import parser, firewall


@click.command()
@click.argument("filepath", type=click.Path(exists=True, readable=True))
@click.option("-O", "--outdir",
              help=("Output dir to save parsed results [out relative to "
                    "input filepath"), default=None)
def parse(filepath, outdir):
    """
    :param filepath: Path of the input fortios' "show *configuration" output
    :param outdir: Dir to save parsed results as JSON files
    """
    if not outdir:
        outdir = os.path.join(os.path.dirname(filepath), "out")

    parser.parse_show_config_and_dump(filepath, outdir)


@click.command()
@click.argument("filepath", type=click.Path(exists=True, readable=True))
@click.argument("path_exp")
def search(filepath, path_exp):
    """
    :param filepath: Path of the JSON input file contains parsed results
    :param path_exp: JMESPath expression to search for
    """
    cnf = parser.load(filepath)
    res = parser.jmespath_search(path_exp, cnf,
                                 has_vdoms_=parser.has_vdom(cnf))
    print(anyconfig.dumps(res, ac_parser="json", indent=2))


@click.command()
@click.argument("filepath", type=click.Path(exists=True, readable=True))
@click.option("-o", "--outpath",
              help="Path of the outpath file to save pandas.DataFrame data",
              default=None)
def firewall_save(filepath, outpath):
    """
    Make and save firewall address table (:class:`pandas.DataFrame` object).

    :param filepath: Path of the input fortios' "show *configuration" outpath
    :param outpath: Path of the file to save data
    """
    if not outpath:
        outpath = os.path.join(os.path.dirname(filepath), "out",
                               "result.pickle.gz")

    cnf = parser.load(filepath)
    firewall.make_and_save_firewall_address_table(cnf, outpath,
                                                  compression="gzip")


@click.command()
@click.argument("filepath", type=click.Path(exists=True, readable=True))
@click.argument("ip_s")
@click.option("--pdf", help="File is the pandas.DataFrame data file",
              default=False)
def firewall_search(filepath, ip_s, pdf):
    """
    Make and save firewall address table (:class:`pandas.DataFrame` object).

    :param filepath:
        Path of the json file contains parsed results of fortios' "show
        *configuration" outputs, or pandas.DataFrame data file
    :param ip_s: IP address string to search
    :param pd: True if the file `filepath` is a pandas.DataFrame data
    """
    if pdf:
        rdf = firewall.pandas_load(filepath, compression="gzip")
    else:
        cnf = parser.load(filepath)
        rdf = firewall.make_firewall_address_table(cnf)

    rdf = firewall.search_by_addr_1(ip_s, rdf)

    # Dirty hack to pretty print JSON string as .to_json in pandas < 1.0.x
    # lacks of 'indent' support.
    aopts = dict(ac_parser="json", indent=2)
    print(anyconfig.dumps(anyconfig.loads(rdf.to_json(), **aopts), **aopts))


@click.group()
def main():
    """CLI frontend entrypoint.
    """
    pass


for cmd in (parse, search, firewall_save, firewall_search):
    main.add_command(cmd)

if __name__ == '__main__':
    main()

# vim:sw=4:ts=4:et: