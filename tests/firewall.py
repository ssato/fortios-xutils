#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>
# SPDX-License-Identifier: MIT
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import fortios_xutils.firewall as TT
import fortios_xutils.parser as P
import tests.common as C


class TestCases_10(C.unittest.TestCase):

    def test_10_df_by_query__mzero(self):
        rdf = TT.df_by_query("configs[]", {})
        self.assertTrue(rdf.empty)

    def test_30_guess_filetype(self):
        self.assertEqual(TT.guess_filetype("foo.pickle"), "pickle")
        self.assertEqual(TT.guess_filetype("foo.json"), "json")
        self.assertEqual(TT.guess_filetype("foo.json.gz", compression=True),
                         "json")


class TestCases_20(C.TestCaseWithWorkdir):

    maxDiff = None

    def test_10_pandas_save_load(self):
        for ext in "pickle json".split():
            filepath = TT.os.path.join(self.workdir, "1", "test." + ext)
            TT.pandas_save(TT.DF_ZERO, filepath)
            rdf = TT.pandas_load(filepath)
            self.assertTrue(rdf.empty)

            TT.pandas_save(TT.DF_ZERO, filepath + ".gz", compression="gzip")
            self.assertTrue(TT.os.path.exists(filepath + ".gz"))

    def test_12_pandas_save_load__excs(self):
        self.assertRaises(ValueError, TT.pandas_save, TT.DF_ZERO,
                          "/a/b/c.ext_not_exist")
        self.assertRaises(ValueError, TT.pandas_load, "/a/b/c.ext_not_exist")


class TestCases_30(C.TestCaseWithWorkdir):

    maxDiff = None
    cpaths = C.list_res_files("show_configs", "*.txt")

    def test_20_make_and_save_firewall_address_table(self):
        for idx, cpath in enumerate(self.cpaths):
            opath = TT.os.path.join(self.workdir, str(idx), "fw.pickle")
            cnf = P.parse_show_config(cpath)
            rdf = TT.make_and_save_firewall_address_table(cnf, opath)
            self.assertFalse(rdf.empty)
            self.assertTrue(TT.os.path.exists(opath))


class TestCases_50(C.unittest.TestCase):

    maxDiff = None

    def setUp(self):
        self.cpaths = C.list_res_files("show_configs", "*.txt")
        self.cnfs = [P.parse_show_config(p) for p in self.cpaths]
        self.fdfs = [TT.make_firewall_address_table(c) for c in self.cnfs]

    def test_10_search_by_addr_1__not_found(self):
        for fdf in self.fdfs:
            rdf = TT.search_by_addr_1("127.0.0.1", fdf)
            self.assertTrue(rdf.empty)

    def test_20_search_by_addr_1__found_1(self):
        for fdf in self.fdfs:
            rdf = TT.search_by_addr_1("192.168.5.201", fdf)
            self.assertFalse(rdf.empty)
            self.assertEqual(len(rdf), 1)
            self.assertEqual(list(rdf["edit"])[0], "SSLVPN_TUNNEL_ADDR1")

# vim:sw=4:ts=4:et:
