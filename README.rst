------
PyKMIP
------
PyKMIP is a Python implementation of the Key Management Interoperability
Protocol (KMIP). KMIP is a client/server communication protocol for the
storage and maintenance of key, certificate, and secret objects. The standard
is governed by the `Organization for the Advancement of Structured Information
Standards`_ (OASIS). PyKMIP supports a subset of features in version 1.1 of
the KMIP specification.

The PyKMIP library provides a KMIP client supporting the following operations:

* Create
* CreateKeyPair
* Destroy
* DiscoverVersions
* Get
* Locate
* Query
* Register
* RekeyKeyPair

The library also includes a software-based KMIP server, which supports basic
versions of the following operations:

* Create
* Destroy
* Get
* Register

For a high-level overview of KMIP, check out the `KMIP Wikipedia page`_. For
comprehensive documentation from OASIS and information about the KMIP
community, visit the `KMIP Technical Committee home page`_.

Usage
=====
The KMIP client can be configured to connect to a KMIP server using settings
found in ``kmip/kmipconfig.ini``. Users can specify the connection
configuration settings to use on client instantiation, allowing applications
to support multiple key storage backends simultaneously, one client per
backend.

An example client configuration settings block is shown below::

  [client]
  host=127.0.0.1
  port=5696
  keyfile=/path/to/key/file
  certfile=/path/to/cert/file
  cert_reqs=CERT_REQUIRED
  ssl_version=PROTOCOL_SSLv23
  ca_certs=/path/to/ca/cert/file
  do_handshake_on_connect=True
  suppress_ragged_eofs=True
  username=None
  password=None

Many of these settings correspond to the settings for ``ssl.wrap_socket``,
which is used to establish secure connections to KMIP backends. For more
information, check out the `Python SSL library documentation`_.

The KMIP software server also pulls settings from ``kmip/kmipconfig.ini``.
However, the server is intended for use only in testing and demonstration
environments. The server is **not** intended to be a substitute for secure,
hardware-based key management appliances. The PyKMIP client should be used
for operational purposes **only** with a hardware-based KMIP server.

An example server configuration settings block is shown below::

  [server]
  host=127.0.0.1
  port=5696
  keyfile=/path/to/key/file
  certfile=/path/to/cert/file
  cert_reqs=CERT_NONE
  ssl_version=PROTOCOL_SSLv23
  ca_certs=/path/to/ca/cert/file
  do_handshake_on_connect=True
  suppress_ragged_eofs=True

When used together, the KMIP client and KMIP server use certificate files
found in ``kmip/demos/certs``. These files should be replaced with alternative
certificates for standalone deployments.

For examples of how to instantiate the KMIP client and how to use the
different client operations, check out the unit demos found under
``kmip/demos/units``.

Profiles
========
The KMIP standard includes various profiles that tailor the standard for
specific use cases (e.g., symmetric key storage with TLS 1.2). These profiles
specify conformance to certain operations and attributes.

The PyKMIP client provides full support for the following profile(s):

* Basic Discover Versions Client KMIP Profile

Development
===========
The development plan for PyKMIP follows the requirements for the following
KMIP profiles. The foundation for symmetric and asymmetric key operation
support is already built into the library.

Client profiles:

* Basic Baseline Client KMIP Profile
* Basic Symmetric Key Store Client KMIP Profile
* Basic Symmetric Key Foundry Client KMIP Profile
* Basic Asymmetric Key Store Client KMIP Profile
* Basic Asymmetric Key Foundry Client KMIP Profile

Server profiles:

* Basic Discover Versions Server KMIP Profile
* Basic Baseline Server KMIP Profile
* Basic Symmetric Key Store and Server KMIP Profile
* Basic Symmetric Key Foundry and Server KMIP Profile
* Basic Asymmetric Key Store Server KMIP Profile
* Basic Asymmetric Key Foundry and Server KMIP Profile

Testing
-------
The PyKMIP test suite is composed of two parts: a unit test suite composed of
over 500 unit tests, and an integration test suite that runs against
instantiations of the software KMIP server. The tests are managed by a
combination of the ``tox``, ``pytest``, and ``flake8`` libraries and cover
approximately 80% of the code.

There are several ways to run different versions of the tests. To run, use one
of the following commands in the PyKMIP root directory.

To run all of the tests::

  $ tox

To run the Python syntax and format compliance tests::

  $ tox -e pep8

To run the test suite against Python 2.7::

  $ tox -e py27

For more information and a list of supported ``tox`` environments, see
``tox.ini`` in the PyKMIP root directory.

Platforms
=========
PyKMIP has been tested and runs on the following platform(s):

* Ubuntu 12.04 LTS

References
==========
The source code for PyKMIP is hosted on GitHub and the library is available
for installation from the Python Package Index (PyPI):

* `PyKMIP on GitHub <https://github.com/OpenKMIP/PyKMIP>`_
* `PyKMIP on PyPI <https://pypi.python.org/pypi/PyKMIP>`_

For more information on KMIP version 1.1, see the following documentation:

* `Key Management Interoperability Protocol Specification Version 1.1`_
* `Key Management Interoperability Protocol Profiles Version 1.1`_
* `Key Management Interoperability Protocol Test Cases Version 1.1`_

.. _code base: https://github.com/OpenKMIP/PyKMIP
.. _Organization for the Advancement of Structured Information Standards: https://www.oasis-open.org/
.. _Key Management Interoperability Protocol Specification Version 1.1: http://docs.oasis-open.org/kmip/spec/v1.1/os/kmip-spec-v1.1-os.html
.. _Key Management Interoperability Protocol Profiles Version 1.1: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html
.. _Key Management Interoperability Protocol Test Cases Version 1.1: http://docs.oasis-open.org/kmip/testcases/v1.1/cn01/kmip-testcases-v1.1-cn01.html
.. _Python SSL library documentation: https://docs.python.org/dev/library/ssl.html#socket-creation
.. _KMIP Wikipedia page: https://en.wikipedia.org/wiki/Key_Management_Interoperability_Protocol
.. _KMIP Technical Committee home page: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip
