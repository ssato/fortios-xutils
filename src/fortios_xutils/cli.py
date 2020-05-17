#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
r"""Misc CLI commands.

.. versionadded:: 0.1.0

   - initial checkin
"""
from __future__ import absolute_import

import logging

import anyconfig
import click

import fortios_xutils
import fortios_xutils.api


LOG = logging.getLogger("fortios_xutils")


@click.command()
@click.argument("filepaths", nargs=-1,
                type=click.Path(exists=True, readable=True))
@click.option("-O", "--outdir",
              help=("Output dir to save parsed results [out/ relative to "
                    "input filepath]"), default=None)
def parse(filepaths, outdir):
    """
    Parse fortigate CLI's "show *configuration* outputs and generate a
    structured JSON file. FILEPATHS is a list of file paths or a glob pattern
    gives that.

    Examples:

    \b
        $ fortios_xutils parse -O /tmp/0 \\
        > tests/res/show_configs/fortigate_cli_show_sample_*.txt
        $ ls /tmp/0
        fortigate-01  fortigate-02
        $ ls /tmp/0/fortigate-01:
        all.json                         firewall_address.json
        firewall_addrgrp.json            firewall_policy.json
        firewall_service_category.json   firewall_service_custom.json
        firewall_service_group.json      metadata.json
        system_global.json               system_interface.json
        system_object-tagging.json       system_replacemsg-group.json
        system_settings.json
        $ jq '.' /tmp/0/fortigate-01/system_interface.json
        [
          {
            "edit": "dmz",
            "vdom": "root",
            "status": "down",
            "type": "physical",
            "role": "dmz",
            "snmp-index": "1"
          },
          {
            "edit": "port1",
            "vdom": "root",
            "ip": [
              "192.168.122.10",
              "255.255.255.0"
            ],
                ... (snip) ...
    \f
    :param filepaths:
        A list of path of the input fortios' "show *configuration" output

    :param outdir: Dir to save parsed results as JSON files
    """
    fortios_xutils.parse_and_save_show_configs(filepaths, outdir)


@click.command()
@click.argument("filepaths", nargs=-1,
                type=click.Path(exists=True, readable=True))
@click.option("-P", "--path", "path_exp", help="JMESPath expression to query")
def search(filepaths, path_exp):
    """
    Search an item or items from JSON file generated previously by 'parse' sub
    command. FILEPATHS is a list of file paths or a glob pattern gives that.

    Examples:

    \b
        $ # List ip addresses of system interfaces.
        $ fortios_xutils search \\
        > -P "configs[?config=='system interface'].edits[].ip" \\
        > tests/res/parsed/fortigate-01/all.json
        [
            [
                "192.168.122.10",
                "255.255.255.0"
            ],
            [
                "192.168.1.10",
                "255.255.255.0"
            ]
        ]
        $
    \f
    :param filepaths:
        A list of the JSON input file paths. Each JSON file contains parsed
        results
    :param path_exp: JMESPath expression to search for
    """
    res = fortios_xutils.query_json_files(filepaths, path_exp)

    if len(res) == 1:
        print(anyconfig.dumps(res[0]["results"], ac_parser="json", indent=2))
    else:
        print(anyconfig.dumps(res, ac_parser="json", indent=2))


@click.command()
@click.argument("filepaths", nargs=-1,
                type=click.Path(exists=True, readable=True))
@click.option("-O", "--outdir", help="Dir to save results")
@click.option("-P", "--prefix", help="Max network prefix [24]")
def network_collect(filepaths, outdir=False, prefix=24):
    """
    Collect and save network data from the parsed and structured fortigate's
    configuration files in JSON formats. FILEPATHS is a list of path of the
    JSON file, the parsed results of fortigate CLI's "show \\*configuration"
    outputs.

    Examples:

    \b
        $ fortios_xutils network-collect tests/res/parsed/*/all.json
        $ head -n 10 tests/res/parsed/fortigate-01/networks.yml
        metadata:
          type: metadata
          input: tests/res/parsed/fortigate-01/all.json
          prefix: 24
          timestamp: 2020-05-12_04_58_57
          version: '1.0'
        nodes:
        - id: fortigate-01
          name: fortigate-01
          type: firewall
        $

    \f
    :param filepaths:
        A list of path of the input JSON file which is the parsed results of
        fortios' "show *configuration" outputs
    :param outdir: Dir to save outputs [same dir input files exist]
    :param prefix: Max network prefix to search networks for
    """
    fortios_xutils.collect_and_save_networks(filepaths, outdir=outdir,
                                             prefix=prefix)


@click.command()
@click.argument("filepaths", nargs=-1,
                type=click.Path(exists=True, readable=True))
@click.option("-o", "--outpath",
              help="Path of the outpath file to save network JSON data",
              default=None)
def network_compose(filepaths, outpath):
    """
    Compose network files collected from the fortigate CLI's configurations
    from multiple fortigate hosts using the preivous network-collect command,
    into a network file.

    Examples:

    \b
        $ fortios_xutils network-compose \\
        > tests/res/parsed/fortigate-0*/networks.yml \\
        > -o tests/res/networks/all.yml
        $ head -n 10 tests/res/networks/all.yml
        metadata:
          inputs:
          - tests/res/parsed/fortigate-01/all.json
          - tests/res/parsed/fortigate-02/all.json
          timestamp: 2020-05-12_05_02_49
          version: '1.0'
        nodes:
        - id: fortigate-01
          name: fortigate-01
          type: firewall
        $

    \f
    :param filepaths:
        A list of network graph data files generated by `network_collect` sub
        command in advance.
    :param outpath: Path of the file to save data
    """
    fortios_xutils.compose_and_save_networks(filepaths, outpath=outpath)


@click.command()
@click.argument("filepaths", nargs=-1,
                type=click.Path(exists=True, readable=True))
@click.option("-O", "--outdir",
              help="Dir to save results [same dir input files exist]")
def firewall_policy_save(filepaths, outdir):
    """
    Make and save firewall policy table (:class:`pandas.DataFrame` object).

    Examples:

    \b
        $ fortios_xutils firewall-policy-save \\
        > -o /tmp/0/test.pickle.gz \\
        > tests/res/parsed/fortigate-01/all.json
        $ file /tmp/0/test.pickle.gz
        /tmp/0/test.pickle.gz: gzip compressed data, was "test.pickle"  ...
        $

    \f
    :param filepath:
        Path of the input JSON file which is the parsed results of fortios'
        "show *configuration" outpath
    :param outdir: Dir to save outputs [same dir input files exist]
    """
    fortios_xutils.make_and_save_firewall_policy_tables(filepaths,
                                                        outdir=outdir)


@click.command()
@click.argument("filepath", type=click.Path(exists=True, readable=True))
@click.option("-i", "--ip", "ip_s",
              help="Specify an IP address to search")
def firewall_policy_search(filepath, ip_s):
    """
    Search firewall policy table generated by 'firewall-policy-save' command,
    by ip address. FILEPATH is a file path to the pandas dataframe file
    generated by 'firewall-policy-save' command.

    Examples:

    \b
        $ fortios_xutils firewall-policy-search \\
        > --ip 192.168.122.3 /tmp/0/test.pickle.gz
        [
          {
            "edit": "20",
            "name": "Monitor_Servers_02",
            "uuid": "3da73baa-dacb-48cb-852c-c4be245b4609",
            "srcintf": "port1",
            "dstintf": "",
            "srcaddr": "host_192.168.122.1",
            "dstaddr": "network_192.168.122.0/24",
            "action": "accept",
            "schedule": "always",
            "service": [
              "HTTPS",
              "HTTP"
            ],
            "inspection-mode": "",
            "nat": "",
            "srcaddrs": [
              "192.168.122.1/32"
            ],
            "dstaddrs": [
              "192.168.122.0/24"
            ],
            "comments": ""
          }
        ]

    \f
    :param filepath:
        Path to a pandas.DataFrame data file contains firewall policy table
    :param ip_s: IP address string to search
    """
    rdf = fortios_xutils.load_firewall_policy_table(filepath)
    res = fortios_xutils.search_firewall_policy_table_by_addr(ip_s, rdf)

    print(anyconfig.dumps(res, ac_parser="json", indent=2))


@click.command()
@click.argument("filepath", type=click.Path(exists=True, readable=True))
@click.argument("src_ip")
@click.argument("dst_ip")
@click.option("-N", "--ntype",
              help="Specify node type from the list: "
                   "{}".format(", ".join(fortios_xutils.api.NODE_TYPES)))
def network_find_paths(filepath, src_ip, dst_ip, ntype=None):
    """
    Search paths from the source `src_ip` to the destination `dst_ip`.

    Examples:

    \b
        $ fortios_xutils/cli.py network-find-paths \\
        > tests/res/networks/graph.yml 192.168.122.2 192.168.5.10
        [
          [
            {
              "id": "fortigate-01",
              "name": "fortigate-01",
              "type": "firewall",
              "addrs": [
                "192.168.122.10/24",
                "192.168.1.10/24"
              ],
              "type_id": 5,
              "class": "node firewall",
              "label": "fortigate-01 firewall"
            },
            {
              "id": "192.168.122.0/24",
              "name": "192.168.122.0/24",
              "type": "network",
              "addrs": [
                "192.168.122.0/24"
              ],
              "type_id": 1,
              "class": "node network",
              "label": "192.168.122.0/24 network"
            },
                ... (snip) ...
            {
              "id": "192.168.5.0/24",
              "name": "192.168.5.0/24",
              "type": "network",
              "addrs": [
                "192.168.5.0/24"
              ],
              "type_id": 1,
              "class": "node network",
              "label": "192.168.5.0/24 network"
            }
          ],
            ... (snip) ...
        $

    \f
    :param filepath:
        Path of the json or yaml file contains netowrk nodes and links
        information.
    :param src_ip: IP address of the source
    :param dst_ip: IP address of the destination
    """
    res = fortios_xutils.find_network_paths(filepath, src_ip, dst_ip)

    aopts = dict(ac_parser="json", indent=2)
    print(anyconfig.dumps(res, **aopts))


@click.group()
@click.option("-v", "--verbose", count=True, default=0)
def main(verbose=0):
    """CLI frontend entrypoint.
    """
    verbose = min(verbose, 2)
    LOG.setLevel([logging.WARNING, logging.INFO, logging.DEBUG][verbose])


for cmd in (parse, search, network_collect, network_compose,
            firewall_policy_save, firewall_policy_search,
            network_find_paths):
    main.add_command(cmd)

if __name__ == '__main__':
    main()

# vim:sw=4:ts=4:et:
