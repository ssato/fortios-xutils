#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>
# SPDX-License-Identifier: MIT
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import os.path

import fortios_xutils.network as TT
import fortios_xutils.parser as P
import tests.common as C


class Base(C.TestCase):

    cpaths = C.list_res_files("show_configs", "*.txt")
    cnfs = [P.parse_show_config(p) for p in cpaths]
    hnames = [P.hostname_from_configs(c, P.has_vdom(c)) for c in cnfs]
    sargss = [dict(has_vdoms_=P.has_vdom(c)) for c in cnfs]

    # .. seealso:: tests/res/show_configs/*.txt
    ref_ips = [TT.ipaddress.ip_interface("192.168.122.10/24"),
               TT.ipaddress.ip_interface("192.168.1.10/24")]
    ref_fas = set(("0.0.0.0/32",
                   "192.168.3.3/32",
                   "192.168.3.1/32",
                   "192.168.3.5/32",
                   "192.168.122.0/24",
                   "192.168.122.1/32",
                   "192.168.1.0/24",
                   "192.168.2.3/32",
                   "192.168.2.2/32",
                   "192.168.5.202/32",
                   "192.168.2.1/32",
                   "192.168.5.201/32",
                   "192.168.5.200/32"))


class TestCases_10(Base):

    def test_10_list_interface_addrs__no_data(self):
        for cnf, sargs in [({}, {})]:
            res = TT.list_interface_addrs(cnf, **sargs)
            self.assertFalse(res)

    def test_12_list_interface_addrs__found(self):
        for cnf, sargs in zip(self.cnfs, self.sargss):
            res = TT.list_interface_addrs(cnf, **sargs)
            self.assertTrue(res)
            self.assertEqual(res, self.ref_ips)

    def test_30_list_firewall_addrs__no_data(self):
        for cnf, sargs in [({}, {})]:
            res = TT.list_firewall_addrs(cnf, **sargs)
            self.assertFalse(res)

    def test_32_list_firewall_addrs(self):
        for cnf, sargs in zip(self.cnfs, self.sargss):
            res = TT.list_firewall_addrs(cnf, **sargs)
            self.assertTrue(res)
            self.assertEqual(set(res), self.ref_fas)


NG_CNF_S_1 = """
{"configs": [{"config": "system global", "hostname": "foo-1"}]}
"""

NG_CNF_S_2 = """
{"configs": [
    {"config": "global",
     "configs": [
        {"config": "system global",
         "hostname": "fortigate-02"}
     ]
    }
  ]
}
"""


def node_and_edges_from_config_file(fpath):
    return list(TT.node_and_edges_from_config_file_itr(fpath))


class TestCases_20(C.TestCaseWithWorkdir, Base):

    def test_10_node_and_edges_from_config_file_itr__wrong_data(self):
        cpath = os.path.join(self.workdir, "test.json")
        open(cpath, 'w').write("{}")
        self.assertRaises(ValueError, node_and_edges_from_config_file, cpath)

        open(cpath, 'w').write(NG_CNF_S_1)
        self.assertRaises(ValueError, node_and_edges_from_config_file, cpath)

        open(cpath, 'w').write(NG_CNF_S_2)
        self.assertRaises(ValueError, node_and_edges_from_config_file, cpath)

    def test_12_node_and_edges_from_config_file_itr(self):
        for (hname, cnf) in zip(self.hnames, self.cnfs):
            cpath = os.path.join(self.workdir, hname, "test.json")
            TT.utils.save_file(cnf, cpath)

            res = node_and_edges_from_config_file(cpath)
            self.assertTrue(res)
            self.assertTrue(any(x for x in res if x.get("type", "firewall")))
            self.assertTrue(any(x for x in res if x.get("type", "network")))
            self.assertTrue(any(x for x in res if x.get("type", "edge")))

    def test_20_collect_networks_from_config_file__no_data(self):
        cpath = os.path.join(self.workdir, "test.json")
        fun = TT.collect_networks_from_config_file

        open(cpath, 'w').write("{}")
        self.assertRaises(ValueError, fun, cpath)

        open(cpath, 'w').write(NG_CNF_S_1)
        self.assertRaises(ValueError, fun, cpath)

        open(cpath, 'w').write(NG_CNF_S_2)
        self.assertRaises(ValueError, fun, cpath)

    def test_22_collect_networks_from_config_file(self):
        for (hname, cnf) in zip(self.hnames, self.cnfs):
            cpath = os.path.join(self.workdir, hname, "test.json")
            TT.utils.save_file(cnf, cpath)

            res = TT.collect_networks_from_config_file(cpath)
            self.assertTrue(res)

    def test_30_collect_networks_from_config_files(self):
        cpaths = [os.path.join(self.workdir, hname, "test.json")
                  for hname in self.hnames]

        for idx, cnf in enumerate(self.cnfs):
            TT.utils.save_file(cnf, cpaths[idx])

        fun = TT.collect_networks_from_config_files
        for res in fun(cpaths):
            self.assertTrue(res)

# vim:sw=4:ts=4:et:
