#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>
# SPDX-License-Identifier: MIT
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import fortios_xutils.firewall as TT
import fortios_xutils.parser as P
import tests.common as C


class TestCases_10(C.TestCase):

    def test_10_df_by_query__mzero(self):
        rdf = TT.df_by_query("configs[]", {})
        self.assertTrue(rdf.empty)

    def test_12_df_by_query__found(self):
        rdf = TT.df_by_query("configs[]", dict(configs=[dict(a=1)]))
        self.assertFalse(rdf.empty)
        self.assertEqual(rdf.to_dict(orient="record"), [dict(a=1)])

    def test_30_guess_filetype(self):
        self.assertEqual(TT.guess_filetype("foo.pickle"), "pickle")
        self.assertEqual(TT.guess_filetype("foo.json"), "json")
        self.assertEqual(TT.guess_filetype("foo.json.gz", compression=True),
                         "json")


class TestCases_20(C.TestCaseWithWorkdir):

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


class TestCasesWithConfigs(C.TestCase):

    cpaths = C.list_res_files("parsed", "*/all.json")
    cnfs = [P.load(p) for p in cpaths]


class TestCases_30(C.TestCaseWithWorkdir, TestCasesWithConfigs):

    def test_20_make_and_save_firewall_policy_table(self):
        for idx, cpath in enumerate(self.cpaths):
            opath = TT.os.path.join(self.workdir, str(idx), "fw.pickle.gz")
            rdf = TT.make_and_save_firewall_policy_table(cpath, opath)
            self.assertFalse(rdf.empty)
            self.assertTrue(TT.os.path.exists(opath))


class TestCases_40(TestCasesWithConfigs):

    def test_10_make_firewall_address_table_1(self):
        for cnf in self.cnfs:
            rdf = TT.make_firewall_address_table_1(
                cnf,
                has_vdoms_=P.has_vdom(cnf)
            )
            self.assertFalse(rdf.empty)
            self.assertTrue("SSLVPN_TUNNEL_ADDR1" in rdf["edit"].values)

    def test_20_make_firewall_addrgrp_table(self):
        for cnf in self.cnfs:
            rdf = TT.make_firewall_addrgrp_table(
                cnf,
                has_vdoms_=P.has_vdom(cnf)
            )
            self.assertFalse(rdf.empty)
            self.assertTrue("G Suite" in rdf["edit"].values)
            self.assertTrue("host_192.168.3.1" in rdf["member"].values)

    def test_30_make_firewall_address_table(self):
        for cnf in self.cnfs:
            rdf = TT.make_firewall_address_table(
                cnf,
                has_vdoms_=P.has_vdom(cnf)
            )
            self.assertFalse(rdf.empty)
            self.assertTrue("SSLVPN_TUNNEL_ADDR1" in rdf["edit"].values)
            self.assertTrue("G Suite" in rdf["edit"].values)
            self.assertTrue(any("192.168.1.0/24" in addrs
                                for addrs in rdf["addrs"].values))
            self.assertTrue(any("192.168.3.3/32" in addrs
                                for addrs in rdf["addrs"].values))


class TestCases_50(TestCasesWithConfigs):

    def setUp(self):
        self.fdfs = [
            TT.make_firewall_address_table(c, has_vdoms_=P.has_vdom(c))
            for c in self.cnfs
        ]
        self.pdfs = [TT.make_firewall_policy_table(c) for c in self.cpaths]

    def test_10_search_by_addr_1__fa_not_found(self):
        for fdf in self.fdfs:
            res = TT.search_by_addr_1("127.0.0.1", fdf)
            self.assertFalse(res)

    def test_12_search_by_addr_1__fa_found_1(self):
        for fdf in self.fdfs:
            res = TT.search_by_addr_1("192.168.5.201", fdf)
            self.assertTrue(res)
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0]["edit"], "SSLVPN_TUNNEL_ADDR1")

    def test_20_search_by_addr_1__fp_not_found(self):
        for rdf in self.pdfs:
            res = TT.search_by_addr_1("127.0.0.1", rdf)
            self.assertFalse(res)

    def test_22_search_by_addr_1__fp_found_1(self):
        for rdf in self.pdfs:
            res = TT.search_by_addr_1("192.168.2.1", rdf)
            self.assertTrue(res)
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0]["name"], "Monitor_Servers_01")

# vim:sw=4:ts=4:et:
