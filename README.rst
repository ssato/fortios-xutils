fortios-xutils
================

.. .. image:: https://img.shields.io/pypi/v/fortios-xutils.svg
   :target: https://pypi.python.org/pypi/fortios-xutils/
   :alt: [Latest Version]

.. .. image:: https://img.shields.io/pypi/pyversions/fortios-xutils.svg
   :target: https://pypi.python.org/pypi/fortios-xutils/
   :alt: [Python versions]

.. .. image:: https://img.shields.io/pypi/l/fortios-xutils.svg
   :target: https://pypi.python.org/pypi/fortios-xutils/
   :alt: MIT License

.. image:: https://img.shields.io/travis/ssato/fortios-xutils.svg
   :target: https://travis-ci.org/ssato/fortios-xutils
   :alt: Test status

.. .. image:: https://img.shields.io/coveralls/ssato/fortios-xutils.svg
      :target: https://coveralls.io/r/ssato/fortios-xutils
      :alt: Coverage Status

.. image:: https://img.shields.io/lgtm/grade/python/g/ssato/fortios-xutils.svg
   :target: https://lgtm.com/projects/g/ssato/fortios-xutils/context:python
   :alt: [Code Quality by LGTM]

Very experimental miscellaneous and extra utilities for fortios (fortigate).

Features
==========

- Parse and dump a structured JSON file from fortios CLI's "show
  \*configuration" outputs
- Search an item or items from JSON files generated as a parsed result from
  fortios CLI's "show \*configuration" outputs, using JMESPath query
- Collect nework information from the JSON files and generate a structured JSON
  files gives that network information
- Compose multiple network JSON files into a network file
- Analyze and dump firewall policy table as a pandas data for further analysis
- Seaerch firewall policy matches given ip address
- Find the network paths from network JSON file by ip address (src and dst)

CLI Usage
============

see fortios_xutils --help fore info.

.. vim:sw=4:ts=4:et:
