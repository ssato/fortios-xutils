#
# Copyright (C) 2020 Satoru SATOH <satoru.satoh@gmail.com>.
# SPDX-License-Identifier: MIT
#
"""Common test module
"""
import glob
import os.path
import os
import shutil
import tempfile
import unittest

try:
    from unittest import SkipTest
except ImportError:
    from nose.plugins.skip import SkipTest


def skip_test():
    """Skip test cases
    """
    raise SkipTest


def selfdir(self=__file__):
    """
    >>> os.path.exists(selfdir())
    True
    """
    return os.path.dirname(self)


def resdir(self=__file__):
    """
    >>> assert os.path.exists(resdir())
    """
    return os.path.join(selfdir(self), "res")


def list_res_files(subdir, pattern="*"):
    """List resource data files
    """
    return sorted(glob.glob(os.path.join(resdir(), subdir, pattern)))


def abspaths(paths):
    """
    an wrapper function of os.path.abspath to process mutliple paths.
    """
    return [os.path.abspath(p) for p in paths]


def setup_workdir():
    """Setup working dir
    """
    return tempfile.mkdtemp()


def prune_workdir(workdir):
    """Remove given `workdir` entirely.
    """
    shutil.rmtree(workdir)


class TestCase(unittest.TestCase):
    """Base class for test cases.
    """
    maxDiff = None


class TestCaseWithWorkdir(TestCase):
    """Base class for test cases need working dir.
    """
    cleanup = True
    workdir = None

    def setUp(self):
        """Prepare working dir
        """
        self.workdir = setup_workdir()

    def tearDown(self):
        """Cleanup working dir as needed
        """
        if self.cleanup:
            prune_workdir(self.workdir)

# vim:sw=4:ts=4:et:
