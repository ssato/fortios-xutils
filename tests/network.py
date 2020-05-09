#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>
# SPDX-License-Identifier: MIT
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import fortios_xutils.network as TT
import fortios_xutils.parser as P
import tests.common as C


class TestCases_20(C.TestCaseWithWorkdir):

    cpaths = C.list_res_files("show_configs", "*.txt")
    cnfs = [P.parse_show_config(p) for p in cpaths]
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
                   "192.168.1.0/24"))

    def test_10_list_interfaces_from_configs__no_data(self):
        for cnf, sargs in [({}, {})]:
            res = TT.list_interfaces_from_configs(cnf, **sargs)
            self.assertFalse(res)

    def test_12_list_interfaces_from_configs__found(self):
        for cnf, sargs in zip(self.cnfs, self.sargss):
            res = TT.list_interfaces_from_configs(cnf, **sargs)
            self.assertTrue(res)
            self.assertEqual(res, self.ref_ips)

    def test_30_networks_from_firewall_address_configs__no_data(self):
        for cnf, sargs in [({}, {})]:
            res = TT.networks_from_firewall_address_configs(cnf, **sargs)
            self.assertFalse(res)

    def test_32_networks_from_firewall_address_configs(self):
        for cnf, sargs in zip(self.cnfs, self.sargss):
            res = TT.networks_from_firewall_address_configs(cnf, **sargs)
            self.assertTrue(res)
            self.assertEqual(set(res), self.ref_fas)

# vim:sw=4:ts=4:et:
