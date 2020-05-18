Introduction
================

Very experimental miscellaneous and extra utilities for fortios (fortigate).

Features
-----------

- Parse and dump a structured JSON file from fortios CLI's "show
  \*configuration" outputs
- Search an item or items from JSON files generated as a parsed result from
  fortios CLI's "show \*configuration" outputs, using JMESPath query
- Collect nework information from the JSON files and generate a structured JSON
  files gives that network information
- Compose multiple network JSON files into a network file
- Analyze and dump firewall policy table as a pandas data for further analysis
- Search firewall policy matches given ip address
- Find the network paths from network JSON file by ip address (src and dst) to
  figure out which firewall nodes to configure

.. vim:sw=4:ts=4:et:
