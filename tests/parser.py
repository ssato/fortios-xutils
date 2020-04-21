#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>
# SPDX-License-Identifier: MIT
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import fortios_xutils.parser as TT
import tests.common as C


class SimpleFunctionTestCases(C.unittest.TestCase):

    maxDiff = None

    def test_10_has_vdom(self):
        cnf = dict(configs=[dict(config="vdom")])
        self.assertTrue(TT.has_vdom(cnf))
        self.assertFalse(TT.has_vdom({}))

    def test_20_jmespath_search_1(self):
        cnf = dict(a=dict(b=[dict(c="D")]))

        self.assertEqual(TT.jmespath_search_1("a.b[?c=='D'] | [0].c", cnf),
                         'D')

        self.assertEqual(TT.jmespath_search_1("a.b[?c=='D'] | [0].c", cnf,
                                              normalize_fn=str.lower),
                         'd')

# vim:sw=4:ts=4:et:
