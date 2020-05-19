#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>
# SPDX-License-Identifier: MIT
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import glob
import os.path

import fortios_xutils.api as TT
import fortios_xutils.firewall as F
import fortios_xutils.network as N
import fortios_xutils.parser as P
import tests.common as C


class TestCase(C.TestCaseWithWorkdir):

    mod = TT

    sources = C.list_res_files("show_configs", "*.txt")
    cpaths = C.list_res_files("parsed", os.path.join('*', P.ALL_FILENAME))
    fpaths = C.list_res_files("firewall",
                              os.path.join('*', F.FWP_TABLE_FILENAME))
    npaths = C.list_res_files("networks", "graph.yml")

    def _fun(self, fun):
        """Get a callable from the module `self.mod` lazily.
        """
        return getattr(self.mod, fun)

    def test_10__parse_and_save_show_configs_single_input(self):
        # Find test target function lazily.
        tfn = self._fun("parse_and_save_show_configs")

        outdir = os.path.join(self.workdir, "out")
        for src in self.sources:
            res = tfn([src], outdir)
            self.assertTrue(res)

            for fname in (P.METADATA_FILENAME, P.ALL_FILENAME):
                files = glob.glob(os.path.join(outdir, '*', fname))
                self.assertTrue(files)

    def test_12_parse_and_save_show_configs__multi_inputs(self):
        tfn = self._fun("parse_and_save_show_configs")

        outdir = os.path.join(self.workdir, "out")
        res = tfn(self.sources, outdir)
        self.assertTrue(res)

        for fname in (P.METADATA_FILENAME, P.ALL_FILENAME):
            files = glob.glob(os.path.join(outdir, '*', fname))
            self.assertTrue(files)

    def test_20_query_json_files__single_input(self):
        tfn = self._fun("query_json_files")

        query = "configs[?config=='system interface'].edits[].ip"
        for cpath in self.cpaths:
            res = tfn([cpath], query)
            self.assertTrue(res)

    def test_22_query_json_files__multi_inputs(self):
        tfn = self._fun("query_json_files")

        query = "configs[?config=='system interface'].edits[].ip"
        res = tfn(self.cpaths, query)
        self.assertTrue(res)

    def test_30_collect_networks__single_input(self):
        tfn = self._fun("collect_networks")

        for cpath in self.cpaths:
            res = tfn([cpath])
            self.assertTrue(res)

    def test_32_collect_networks__multi_inputs(self):
        tfn = self._fun("collect_networks")

        res = tfn(self.cpaths)
        self.assertTrue(res)

    def test_40_collect_and_save_networks__single_input(self):
        tfn = self._fun("collect_and_save_networks")

        for idx, cpath in enumerate(self.cpaths):
            outdir = os.path.join(self.workdir, "out-{!s}".format(idx))
            res = tfn([cpath], outdir=outdir)
            self.assertTrue(res)

            files = glob.glob(os.path.join(outdir, '*', N.NET_FILENAME))
            self.assertTrue(files)
            self.assertEqual(len(files), 1, files)

    def test_42_collect_and_save_networks__multi_inputs(self):
        tfn = self._fun("collect_and_save_networks")

        outdir = os.path.join(self.workdir, "out")
        res = tfn(self.cpaths, outdir=outdir)
        self.assertTrue(res)

        files = glob.glob(os.path.join(outdir, '*', N.NET_FILENAME))
        self.assertTrue(files)
        self.assertEqual(len(files), 2)

    def test_50_compose_networks__single_input(self):
        tfn = self._fun("compose_networks")

        for cpath in self.cpaths:
            res = tfn([cpath])
            self.assertTrue(res)

    def test_52_compose_networks__multi_inputs(self):
        tfn = self._fun("compose_networks")

        res = tfn(self.cpaths)
        self.assertTrue(res)

    def test_60_compose_and_save_networks__single_input(self):
        tfn = self._fun("compose_and_save_networks")

        opath = os.path.join(self.workdir, "out", N.NET_ALL_FILENAME)
        for cpath in self.cpaths:
            res = tfn([cpath], opath)
            self.assertTrue(res)
            self.assertTrue(os.path.exists(opath))

    def test_62_compose_and_save_networks__multi_inputs(self):
        tfn = self._fun("compose_and_save_networks")

        opath = os.path.join(self.workdir, "out", N.NET_ALL_FILENAME)
        res = tfn(self.cpaths, opath)
        self.assertTrue(res)
        self.assertTrue(os.path.exists(opath))

    def test_70_make_save_search_firewall_policy_tables__single_input(self):
        tfn1 = self._fun("make_and_save_firewall_policy_tables")
        tfn2 = self._fun("load_firewall_policy_table")
        tfn3 = self._fun("search_firewall_policy_table_by_addr")

        for idx, cpath in enumerate(self.cpaths):
            outdir = os.path.join(self.workdir, "out-{!s}".format(idx))
            res = tfn1([cpath], outdir)
            self.assertTrue(res)

            files = glob.glob(os.path.join(outdir, '*',
                                           F.FWP_TABLE_FILENAME))
            self.assertTrue(files)
            self.assertEqual(len(files), 1)
            fpath = files[0]

            rdf = tfn2(fpath)

            # not found
            ipa = "127.0.0.1"
            res = tfn3(ipa, rdf)
            self.assertFalse(res)

            # found
            ipa = "192.168.122.3"
            res = tfn3(ipa, rdf)
            self.assertTrue(res)

    def test_72_firewall_policy_save_and_search__multi_inputs(self):
        tfn1 = self._fun("make_and_save_firewall_policy_tables")
        tfn2 = self._fun("load_firewall_policy_table")
        tfn3 = self._fun("search_firewall_policy_table_by_addr")

        outdir = os.path.join(self.workdir, "out")
        res = tfn1(self.cpaths, outdir)
        self.assertTrue(res)

        files = sorted(glob.glob(os.path.join(outdir, '*',
                                              F.FWP_TABLE_FILENAME)))
        self.assertTrue(files)
        self.assertEqual(len(files), 2)

        # not found
        ipa = "127.0.0.1"
        for fpath in files:
            rdf = tfn2(fpath)
            res = tfn3(ipa, rdf)
            self.assertFalse(res)

        # found
        ipa = "192.168.122.3"
        for fpath in files:
            rdf = tfn2(fpath)
            res = tfn3(ipa, rdf)
            self.assertTrue(res)

    def test_80_find_network_paths__not_found(self):
        tfn = self._fun("find_network_paths")

        (src, dst) = ("127.0.0.1", "192.168.122.2")
        for npath in self.npaths:
            res = tfn(npath, src, dst)
            self.assertFalse(res)

    def test_82_find_network_paths__found(self):
        tfn = self._fun("find_network_paths")

        (src, dst) = ("192.168.122.2", "192.168.5.10")
        for npath in self.npaths:
            res = tfn(npath, src, dst)
            self.assertTrue(res)

# vim:sw=4:ts=4:et:
