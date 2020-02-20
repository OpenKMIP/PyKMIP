Welcome to PyKMIP
=================
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

Installation
------------
You can install PyKMIP via ``pip``:

.. code-block:: console

    $ pip install pykmip

See :doc:`Installation <installation>` for more information.

Layout
------
PyKMIP provides both client and server functionality, allowing developers
to incorporate the full key management lifecycle into their projects. For
more information, check out the various articles below.

.. toctree::
   :maxdepth: 2

   installation
   changelog
   faq
   development
   security
   client
   server
   community
   glossary

.. _`CRUD`: https://en.wikipedia.org/wiki/Create,_read,_update_and_delete
.. _`OASIS`: https://www.oasis-open.org
.. _`OASIS KMIP Technical Committee`: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip
.. _`OASIS KMIP Documentation`: https://docs.oasis-open.org/kmip/spec/
