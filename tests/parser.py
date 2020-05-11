#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>
# SPDX-License-Identifier: MIT
#
# pylint: disable=missing-docstring,invalid-name
from __future__ import absolute_import

import os.path

import fortios_xutils.parser as TT
import tests.common as C


class TestCases_10(C.unittest.TestCase):

    def test_10_has_vdom(self):
        cnf = dict(configs=[dict(config="vdom")])
        self.assertTrue(TT.has_vdom(cnf))
        self.assertFalse(TT.has_vdom({}))

    def test_20_validate(self):
        self.assertRaises(ValueError, TT.validate, {})
        self.assertRaises(TypeError, TT.validate, [1])
        self.assertRaises(ValueError, TT.validate, dict(a=1))
        self.assertRaises(ValueError, TT.validate, dict(configs=True))


class TestCases_20_jmespath_search(C.unittest.TestCase):

    maxDiff = None

    def test_20_jmespath_search_1(self):
        cnf = dict(a=dict(b=[dict(c="D")]))

        self.assertEqual(TT.jmespath_search_1("a.b[?c=='D'] | [0].c", cnf),
                         'D')

        self.assertEqual(TT.jmespath_search_1("a.b[?c=='D'] | [0].c", cnf,
                                              normalize_fn=str.lower),
                         'd')

    def test_30_jmespath_search__no_vdoms(self):
        cnf = dict(a=dict(b=[dict(c="D")]))
        pexp = "a.b[?c=='D'] | [0].c"

        ref = TT.jmespath_search_1(pexp, cnf)
        res = TT.jmespath_search(pexp, cnf)

        self.assertTrue(res)
        self.assertEqual(res, ref)

    def test_32_jmespath_search__w_vdoms_global_only(self):
        val = "foo-0"
        cnf = dict(configs=[dict(config="global",
                                 configs=[dict(config="system global",
                                               hostname=val)])])
        pexp = "configs[?config=='system global'] | [].hostname"

        res = TT.jmespath_search(pexp, cnf, has_vdoms_=True)

        self.assertTrue(res)
        self.assertEqual(res, [val])

    def test_34_jmespath_search__w_vdoms_vdoms_only(self):
        vals = ["foo-0", "bar-1"]
        scnf = dict(config="system global", hostname=vals[0])
        scnf_1 = dict(config="system global", hostname=vals[1])
        cnf = dict(configs=[dict(config="global", configs=[]),
                            dict(config="vdom",
                                 edits=[dict(edit="root",
                                             configs=[scnf]),
                                        dict(edit="mng",
                                             configs=[scnf_1])])])

        pexp = "configs[?config=='system global'] | [].hostname[]"

        res = TT.jmespath_search(pexp, cnf, has_vdoms_=True)

        self.assertTrue(res)
        self.assertEqual(res, vals)

    def test_36_jmespath_search__w_vdoms__both_global_and_vdoms(self):
        val = "foo-0"
        scnf = dict(config="system global", hostname=val)
        cnf = dict(configs=[dict(config="global",
                                 configs=[scnf]),
                            dict(config="vdom",
                                 edits=[dict(edit="root",
                                             configs=[scnf])])])

        pexp = "configs[?config=='system global'] | [].hostname[]"

        res = TT.jmespath_search(pexp, cnf, has_vdoms_=True)

        self.assertTrue(res)
        self.assertEqual(res, [val, val])

    def test_38_jmespath_search__w_vdoms_the_vdom_only(self):
        val = "foo-0"
        scnf = dict(config="system global", hostname=val)
        scnf_1 = dict(config="system global", hostname="bar-1")

        cnf = dict(configs=[dict(config="global", configs=[]),
                            dict(config="vdom",
                                 edits=[dict(edit="root",
                                             configs=[scnf])]),
                            dict(config="vdom",
                                 edits=[dict(edit="mng",
                                             configs=[scnf_1])])])

        pexp = "configs[?config=='system global'] | [].hostname[]"

        res = TT.jmespath_search(pexp, cnf, has_vdoms_=True, vdom="root")

        self.assertTrue(res)
        self.assertEqual(res, [val])


def _list_cnames_from_file(filepath):
    return sorted(set(line.replace("config ", '').rstrip()
                      for line in open(filepath)
                      if TT.re.match(r"^config firewall service.*", line)))


class TestCases_30_parse(C.unittest.TestCase):

    maxDiff = None
    cpaths = C.list_res_files("show_configs", "*.txt")

    def test_10_parse_show_config(self):
        for cpath in self.cpaths:
            cnf = TT.parse_show_config(cpath)
            self.assertTrue(cnf)
            TT.validate(cnf)

    def test_20_hostname_from_configs(self):
        cnf = TT.parse_show_config(self.cpaths[0])
        hostname = TT.hostname_from_configs(cnf)
        self.assertEqual(hostname, "fortigate-01")

        cnf = TT.parse_show_config(self.cpaths[1])
        hostname = TT.hostname_from_configs(cnf, has_vdoms_=True)
        self.assertEqual(hostname, "fortigate-02")

    def test_30_list_vdom_names(self):
        cnf = TT.parse_show_config(self.cpaths[0])
        self.assertEqual(TT.list_vdom_names(cnf), ["root"])

        cnf = TT.parse_show_config(self.cpaths[1])
        self.assertEqual(TT.list_vdom_names(cnf), ["ro", "root"])

    def test_50_list_cnames_for_regexp(self):
        reg = TT.re.compile(r"firewall service.*")
        for cpath in self.cpaths:
            ref = _list_cnames_from_file(cpath)
            cnf = TT.parse_show_config(cpath)
            opts = dict(has_vdoms_=TT.has_vdom(cnf))
            res = TT.list_cnames_for_regexp(cnf, reg, **opts)

            self.assertEqual(res, ref)


def houtdir(outdir, cnf):
    """Compute the output dir for each hosts.
    """
    opts = dict(has_vdoms_=TT.has_vdom(cnf))
    hostname = TT.hostname_from_configs(cnf, **opts)
    return os.path.join(outdir, hostname)


class TestCases_50(C.TestCaseWithWorkdir):

    maxDiff = None
    cpaths = C.list_res_files("show_configs", "*.txt")

    def test_10_parse_show_config_and_dump(self):
        for idx, cpath in enumerate(self.cpaths):
            outdir = TT.os.path.join(self.workdir, "{!s}".format(idx))
            cnf = TT.parse_show_config_and_dump(cpath, outdir)

            self.assertTrue(cnf)

            hdir = houtdir(self.workdir, cnf)
            for fname in (TT.METADATA_FILENAME, TT.ALL_FILENAME):
                self.assertTrue(os.path.join(hdir, fname))

    def test_20_parse_show_configs_and_dump(self):
        for _path, cnf in TT.parse_show_configs_and_dump_itr(self.cpaths,
                                                             self.workdir):
            self.assertTrue(cnf)

            hdir = houtdir(self.workdir, cnf)
            for fname in (TT.METADATA_FILENAME, TT.ALL_FILENAME):
                self.assertTrue(os.path.join(hdir, fname))

# vim:sw=4:ts=4:et:
