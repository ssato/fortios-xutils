#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>
# SPDX-License-Identifier: MIT
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import glob
import os.path

import click.testing

import fortios_xutils.cli as TT
import fortios_xutils.firewall as F
import fortios_xutils.network as N
import fortios_xutils.parser as P
import tests.common as C


class Base(C.TestCase):

    sources = C.abspaths(C.list_res_files("show_configs", "*.txt"))
    cpaths = C.abspaths(C.list_res_files("parsed",
                                         os.path.join('*', P.ALL_FILENAME)))
    fpaths = C.abspaths(
        C.list_res_files("firewall",
                         os.path.join('*', F.FWP_TABLE_FILENAME))
    )
    npaths = C.abspaths(C.list_res_files("networks", "graph.yml"))

    # .. seealso:: tests/res/show_configs/*.txt
    ref_ips = ["192.168.122.10/24", "192.168.1.10/24"]
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


class TestCliCases(Base):

    def setUp(self):
        self.runner = click.testing.CliRunner()

    def test_10_parse__single_input(self):
        outdir = "out"
        for src in self.sources:
            with self.runner.isolated_filesystem():
                res = self.runner.invoke(TT.parse, [src, "-O", outdir])
                self.assertEqual(res.exit_code, 0)
                self.assertFalse(res.output)

                for fname in (P.METADATA_FILENAME, P.ALL_FILENAME):
                    files = glob.glob(os.path.join(outdir, '*', fname))
                    self.assertTrue(files)

    def test_12_parse__multi_inputs(self):
        outdir = "out"
        with self.runner.isolated_filesystem():
            res = self.runner.invoke(TT.parse, ["-O", outdir] + self.sources)
            self.assertEqual(res.exit_code, 0)
            self.assertFalse(res.output)

            for fname in (P.METADATA_FILENAME, P.ALL_FILENAME):
                files = glob.glob(os.path.join(outdir, '*', fname))
                self.assertTrue(files)

    def test_20_search__single_input(self):
        query = "configs[?config=='system interface'].edits[].ip"
        for cpath in self.cpaths:
            res = self.runner.invoke(TT.search, [cpath, "-P", query])
            self.assertEqual(res.exit_code, 0)
            self.assertTrue(res.output)

    def test_22_search__multi_inputs(self):
        query = "configs[?config=='system interface'].edits[].ip"
        res = self.runner.invoke(TT.search, ["-P", query] + self.cpaths)
        self.assertEqual(res.exit_code, 0)
        self.assertTrue(res.output)

    def test_30_network_collect__single_input(self):
        outdir = "out"
        for cpath in self.cpaths:
            with self.runner.isolated_filesystem():
                res = self.runner.invoke(TT.network_collect,
                                         ["-O", outdir, cpath])
                self.assertEqual(res.exit_code, 0)
                self.assertFalse(res.output)

                files = glob.glob(os.path.join(outdir, '*', N.NET_FILENAME))
                self.assertTrue(files)
                self.assertEqual(len(files), 1)

    def test_32_network_collect__multi_inputs(self):
        outdir = "out"
        with self.runner.isolated_filesystem():
            res = self.runner.invoke(TT.network_collect,
                                     ["-O", outdir] + self.cpaths)
            # self.assertEqual(res.exit_code, 0, res)
            self.assertFalse(res.output)

            files = glob.glob(os.path.join(outdir, '*', N.NET_FILENAME))
            self.assertTrue(files)
            self.assertEqual(len(files), 2)

    def test_40_network_compose__single_input(self):
        opath = os.path.join("out", N.NET_ALL_FILENAME)
        for cpath in self.cpaths:
            with self.runner.isolated_filesystem():
                res = self.runner.invoke(TT.network_compose,
                                         ["-o", opath, cpath])
                self.assertEqual(res.exit_code, 0)
                self.assertFalse(res.output)
                self.assertTrue(os.path.exists(opath))

    def test_42_network_compose__multi_inputs(self):
        opath = os.path.join("out", N.NET_ALL_FILENAME)
        with self.runner.isolated_filesystem():
            res = self.runner.invoke(TT.network_compose,
                                     ["-o", opath] + self.cpaths)
            self.assertEqual(res.exit_code, 0)
            self.assertFalse(res.output)
            self.assertTrue(os.path.exists(opath))

    def test_50_firewall_policy_save_and_search__single_input(self):
        outdir = "out"
        for cpath in self.cpaths:
            with self.runner.isolated_filesystem():
                res = self.runner.invoke(TT.firewall_policy_save,
                                         ["-O", outdir, cpath])
                self.assertEqual(res.exit_code, 0)
                self.assertFalse(res.output)

                files = glob.glob(os.path.join(outdir, '*',
                                               F.FWP_TABLE_FILENAME))
                self.assertTrue(files)
                self.assertEqual(len(files), 1)

                # not found
                ipa = "127.0.0.1"
                res = self.runner.invoke(TT.firewall_policy_search,
                                         ["-i", ipa, files[0]])
                self.assertEqual(res.exit_code, 0)
                self.assertTrue(res.output)
                self.assertEqual(res.output, "[]\n")

                # found
                ipa = "192.168.122.3"
                res = self.runner.invoke(TT.firewall_policy_search,
                                         ["-i", ipa, files[0]])
                self.assertEqual(res.exit_code, 0)
                self.assertTrue(res.output)
                self.assertNotEqual(res.output, "[]\n")

    def test_52_firewall_policy_save_and_search__multi_inputs(self):
        outdir = "out"
        with self.runner.isolated_filesystem():
            res = self.runner.invoke(TT.firewall_policy_save,
                                     ["-O", outdir] + self.cpaths)
            self.assertEqual(res.exit_code, 0)
            self.assertFalse(res.output)

            files = glob.glob(os.path.join(outdir, '*',
                                           F.FWP_TABLE_FILENAME))
            self.assertTrue(files)
            self.assertEqual(len(files), 2)

            # not found
            ipa = "127.0.0.1"
            for fdb in files:
                res = self.runner.invoke(TT.firewall_policy_search,
                                         ["-i", ipa, fdb])
                self.assertEqual(res.exit_code, 0)
                self.assertTrue(res.output)
                self.assertEqual(res.output, "[]\n")

            # found
            ipa = "192.168.122.3"
            for fdb in files:
                res = self.runner.invoke(TT.firewall_policy_search,
                                         ["-i", ipa, fdb])
                self.assertEqual(res.exit_code, 0)
                self.assertTrue(res.output)
                self.assertNotEqual(res.output, "[]\n")

    def test_70_network_find_paths__not_found(self):
        (src, dst) = ("127.0.0.1", "192.168.122.2")
        for npath in self.npaths:
            res = self.runner.invoke(TT.network_find_paths, [npath, src, dst])
            self.assertEqual(res.exit_code, 0)
            self.assertTrue(res.output)
            self.assertEqual(res.output, "[]\n")

    def test_72_network_find_paths__found(self):
        (src, dst) = ("192.168.122.2", "192.168.5.10")
        for npath in self.npaths:
            res = self.runner.invoke(TT.network_find_paths, [npath, src, dst])
            self.assertEqual(res.exit_code, 0)
            self.assertTrue(res.output)
            self.assertNotEqual(res.output, "[]\n")

# vim:sw=4:ts=4:et:
