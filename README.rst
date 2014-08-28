======
PyKMIP
======

PyKMIP is a Python implementation of the Key Management Interoperability
Protocol (KMIP) specification, supporting version 1.1 of the KMIP standard.
The library currently provides a KMIP client, which supports the following
operations for KMIP SymmetricKey managed objects:

* create
* register
* get
* destroy

PyKMIP also provides a software-based KMIP server, which is intended for use
in testing and demonstration environments. The server is NOT intended to be
a substitute for secured hardware-based KMIP appliances.

Version
=======
This distribution of PyKMIP is version 0.0.1. Future work includes adding
support for basic KMIP profiles, including the basic supporting operations.

For more information on KMIP profiles, see the `OASIS documentation for
KMIP profiles
<http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html>`_.

Platform
========
PyKMIP has been tested and runs on Ubuntu 12.04 LTS.

References
==========

For more information on the KMIP specification, see the `OASIS documentation
for KMIP
<http://docs.oasis-open.org/kmip/spec/v1.1/os/kmip-spec-v1.1-os.html>`_.

Contributors
============

Many thanks to the developers who created PyKMIP:

Nathan Reller <nathan.reller@jhuapl.edu>
Peter Hamilton <peter.hamilton@jhuapl.edu>
Kaitlin Farr <kaitlin.farr@jhuapl.edu>
