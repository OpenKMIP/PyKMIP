------
PyKMIP
------
|pypi-version|
|travis-status|
|codecov-status|
|python-versions|

PyKMIP is a Python implementation of the Key Management Interoperability
Protocol (KMIP), an `OASIS`_ communication standard for the management of
objects stored and maintained by key management systems. KMIP defines how key
management operations and operation data should be encoded and communicated
between client and server applications. Supported operations include the full
`CRUD`_ key management lifecycle, including operations for managing object
metadata and for conducting cryptographic operations. Supported object types
include:

* symmetric/asymmetric encryption keys
* passwords/passphrases
* certificates
* opaque data blobs, and more

For more information on KMIP, check out the `OASIS KMIP Technical Committee`_
and the `OASIS KMIP Documentation`_.

For more information on PyKMIP, check out the project `Documentation`_.

Installation
------------
You can install PyKMIP via ``pip``:

.. code-block:: console

    $ pip install pykmip

See `Installation`_ for more information.

Community
---------
The PyKMIP community has various forums and resources you can use:

* `Source code`_
* `Issue tracker`_
* IRC: ``#pykmip`` on ``irc.freenode.net``
* Twitter: ``@pykmip``


.. _`CRUD`: https://en.wikipedia.org/wiki/Create,_read,_update_and_delete
.. _`OASIS`: https://www.oasis-open.org
.. _`OASIS KMIP Technical Committee`: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip
.. _`OASIS KMIP Documentation`: https://docs.oasis-open.org/kmip/spec/
.. _`Documentation`: https://pykmip.readthedocs.io/en/latest/index.html
.. _`Installation`: https://pykmip.readthedocs.io/en/latest/installation.html
.. _`Source code`: https://github.com/openkmip/pykmip
.. _`Issue tracker`: https://github.com/openkmip/pykmip/issues

.. |pypi-version| image:: https://img.shields.io/pypi/v/pykmip.svg
  :target: https://pypi.python.org/pypi/pykmip
  :alt: Latest Version
.. |travis-status| image:: https://travis-ci.org/OpenKMIP/PyKMIP.svg?branch=master
  :target: https://travis-ci.org/OpenKMIP/PyKMIP
.. |codecov-status| image:: https://codecov.io/github/OpenKMIP/PyKMIP/coverage.svg?branch=master
  :target: https://codecov.io/github/OpenKMIP/PyKMIP?branch=master
.. |python-versions| image:: https://img.shields.io/pypi/pyversions/PyKMIP.svg
  :target: https://github.com/OpenKMIP/PyKMIP
