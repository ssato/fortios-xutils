#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>
# SPDX-License-Identifier: MIT
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import fortios_xutils.netutils as TT
import tests.common as C


class TestCase_10_functions(C.unittest.TestCase):

    def test_20_subnet_to_ip__ng(self):
        self.assertRaises(ValueError, TT.subnet_to_ip, 1, 2)
        self.assertRaises(ValueError, TT.subnet_to_ip, "10.0.0.1", 8)
        self.assertRaises(ValueError, TT.subnet_to_ip, "10.0.0.1", "8")

    def test_22_subnet_to_ip__ok(self):
        self.assertEqual(TT.subnet_to_ip("10.0.0.0", "255.0.0.0"),
                         "10.0.0.0/8")
        self.assertEqual(TT.subnet_to_ip("10.0.0.1", "255.255.255.255"),
                         "10.0.0.1/32")
        self.assertEqual(TT.subnet_to_ip("10.0.0.1", "255.0.0.0"),
                         "10.0.0.1/32")

    def test_30_iprange_to_ipsets__ng(self):
        self.assertRaises(ValueError, TT.iprange_to_ipsets, 1, 2)
        self.assertRaises(ValueError, TT.iprange_to_ipsets, "10.0.0.1", 1)
        self.assertRaises(ValueError, TT.iprange_to_ipsets, 1, "10.0.0.1")
        self.assertRaises(ValueError,
                          TT.iprange_to_ipsets, "10.0.0.1", "192.168.1.1")

    def test_32_iprange_to_ipsets__ok(self):
        self.assertEqual(TT.iprange_to_ipsets("10.0.0.1", "10.0.0.3"),
                         ["10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"])

    def test_50_is_ip_in_addrs__ng(self):
        ngs = [("10.1.1.1", []),
               ("10.1.1.1", ["192.168.1.0/24"]),
               ("10.0.0.1", ["10.1.0.0/16"]),
               ("10.0.0.0", ["10.1.0.0/16"])]

        for ip_s, nets in ngs:
            self.assertFalse(TT.is_ip_in_addrs(ip_s, nets))

    def test_52_is_ip_in_addrs__ok(self):
        ngs = [("10.1.1.1", ["10.1.1.1/32"]),
               ("10.1.1.1", ["192.168.1.0/24", "10.1.1.1/32"]),
               ("10.0.0.1", ["10.0.0.0/8"]),
               ("10.0.0.0", ["10.0.0.0/8"])]

        for ip_s, nets in ngs:
            self.assertTrue(TT.is_ip_in_addrs(ip_s, nets))

# vim:sw=4:ts=4:et:
