#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>
# SPDX-License-Identifier: MIT
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import os.path
import subprocess

import fortios_xutils.utils as TT
import tests.common as C


class SimpleFunctionTestCases(C.unittest.TestCase):

    maxDiff = None

    def test_20_timestamp(self):
        dt = TT.datetime.datetime(2020, 1, 7, 1, 23, 45)
        ref = "2020-01-07_01_23_45"
        self.assertEqual(TT.timestamp(dt), ref)

    def test_30_checksum(self):
        cs = "md5sum {}".format(__file__).split()
        ref = subprocess.check_output(cs).decode("utf-8").split()[0]

        self.assertEqual(TT.checksum(__file__), ref)

    # TODO:
    def test_50_try_ac_load__ng(self):
        pass

    def test_52_try_ac_load__ok(self):
        ok_files = C.list_res_files("*_ok.json")
        for f in ok_files:
            self.assertTrue(TT.try_ac_load(f) is not None)

    def test_60_expand_glob_paths_itr(self):
        ref = sorted(
            os.path.join(
                ("tests/res/show_configs/fortigate_cli_show_sample_"
                 "{!s}.txt".format(idx)))
            for idx in [0, 1]
        )
        res = list(
            TT.expand_glob_paths_itr(["tests/res/show_configs/*.txt"])
        )
        self.assertEqual(res, ref)

# vim:sw=4:ts=4:et:
