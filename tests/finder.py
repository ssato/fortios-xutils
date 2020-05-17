#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>
# SPDX-License-Identifier: MIT
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import functools

import fortios_xutils.finder as TT
import tests.common as C


# tests/res/networks/graph.yml
NET_CONF_PATH = C.list_res_files("networks", pattern="*.yml")[0]


class TestCases_10(C.unittest.TestCase):

    def test_10_validate(self):
        self.assertRaises(ValueError, TT.validate, {})
        self.assertRaises(TypeError, TT.validate, [1])
        self.assertRaises(ValueError, TT.validate, dict(a=1))
        self.assertRaises(ValueError, TT.validate, dict(nodes=1, links=[]))
        self.assertRaises(ValueError, TT.validate, dict(nodes=[], links=1))

    def test_20_load(self):
        self.assertTrue(TT.load(NET_CONF_PATH))

    def test_30_find_paths(self):
        fnc = functools.partial(TT.find_paths, NET_CONF_PATH)

        pss = fnc("192.168.122.2", "192.168.5.10")
        self.assertTrue(pss)
        self.assertTrue(pss[0])
        self.assertTrue(n.get("id", '') == "192.168.122.0/24" for n in pss)
        self.assertTrue(n.get("id", '') == "192.168.5.0/24" for n in pss)

# vim:sw=4:ts=4:et:
