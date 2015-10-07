------
PyKMIP
------
|coverage-status|

PyKMIP is a Python implementation of the Key Management Interoperability
Protocol (KMIP). KMIP is a client/server communication protocol for the
storage and maintenance of key, certificate, and secret objects. The standard
is governed by the `Organization for the Advancement of Structured Information
Standards`_ (OASIS). PyKMIP supports a subset of features in version 1.1 of
the KMIP specification.

For a high-level overview of KMIP, check out the `KMIP Wikipedia page`_. For
comprehensive documentation from OASIS and information about the KMIP
community, visit the `KMIP Technical Committee home page`_.

.. _Usage:

Usage
=====
Client
------
There are two implementations of the KMIP client. The first,
``kmip.services.kmip_client.KMIPProxy``, is the original client and provides
support for the following operations:

* ``Create``
* ``CreateKeyPair``
* ``Register``
* ``Locate``
* ``Get``
* ``GetAttributeList``
* ``Activate``
* ``Revoke``
* ``Destroy``
* ``Query``
* ``DiscoverVersions``

The second client, ``kmip.pie.client.ProxyKmipClient``, wraps the original
``KMIPProxy`` and provides a simpler interface. It provides support for the
following operations:

* ``Create``
* ``CreateKeyPair``
* ``Register``
* ``Get``
* ``GetAttributeList``
* ``Destroy``

For examples of how to create and use the different clients, see the scripts
in ``kmip/demos``.

Configuration
*************
A KMIP client can be configured in different ways to connect to a KMIP server.
The first method is the default approach, which uses settings found in the
PyKMIP configuration file. The configuration file can be stored in several
different locations, including:

* ``<user home>/.pykmip/pykmip.conf``
* ``/etc/pykmip/pykmip.conf``
* ``<PyKMIP install>/kmip/pykmip.conf``
* ``<PyKMIP install>/kmip/kmipconfig.ini``

These locations are searched in order. For example, configuration data found
in ``/etc`` will take priority over configuration information found in the
PyKMIP installation directory. The ``kmipconfig.ini`` file name is supported
for legacy installations. Users can specify the connection configuration
settings to use on client instantiation, allowing applications to support
multiple key storage backends simultaneously, one client per backend.

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
  username=user
  password=password

The second configuration approach allows developers to specify the
configuration settings when creating the client at run time. The following
example demonstrates how to create the ``ProxyKmipClient``, directly
specifying the different configuration values::

  client = ProxyKmipClient(
      hostname='127.0.0.1',
      port=5696,
      cert='/path/to/cert/file/',
      key='/path/to/key/file/',
      ca='/path/to/ca/cert/file/',
      ssl_version='PROTOCOL_SSLv23',
      username='user',
      password='password',
      config='client')

A KMIP client will load the configuration settings found in the ``client``
settings block by default. Settings specified at runtime, as in the above
example, will take precedence over the default values found in the
configuration file.

Many of these settings correspond to the settings for ``ssl.wrap_socket``,
which is used to establish secure connections to KMIP backends. For more
information, check out the `Python SSL library documentation`_.

Server
------
In addition to the KMIP clients, PyKMIP provides a basic software
implementation of a KMIP server, ``kmip.services.kmip_server.KMIPServer``.
However, the server is intended for use only in testing and demonstration
environments. The server is **not** intended to be a substitute for a secure,
hardware-based key management appliance. The PyKMIP client should be used for
operational purposes **only** with a hardware-based KMIP server.

The KMIP server provides basic support for the following operations:

* ``Create``
* ``Register``
* ``Locate``
* ``Get``
* ``Destroy``

Configuration
*************
The KMIP software server also pulls settings from the PyKMIP configuration
file. An example server configuration settings block is shown below::

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

When used together, a KMIP client and KMIP server by default use certificate
files found in ``kmip/demos/certs``. These files should be replaced with
alternative certificates for standalone deployments.

Profiles
========
The KMIP standard includes various profiles that tailor the standard for
specific use cases (e.g., symmetric key storage with TLS 1.2). These profiles
specify conformance to certain operations and attributes.

The PyKMIP ``KMIPProxy`` client provides full support for the following
profile(s):

* Basic Discover Versions Client KMIP Profile

Development
===========
Roadmap
-------
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
The PyKMIP test suite is composed of two parts, a unit test suite and an
integration test suite that runs various tests against instantiations of the
software KMIP server and real KMIP appliances. The tests are managed by a
combination of the ``tox``, ``pytest``, and ``flake8`` libraries.

There are several ways to run different versions of the tests. To run, use one
of the following commands in the PyKMIP root directory.

To run all of the unit tests::

  $ tox

To run the Python syntax and format compliance tests::

  $ tox -e pep8

To run the unit test suite against Python 2.7::

  $ tox -e py27

The integration tests require a configuration flag whose value corresponds to
the name of a client configuration section in the ``kmipconfig.ini``
configuration file. See the Usage_ section for more information.

To run the integration test suite with a specific configuration setup::

  $ tox -e integration -- --config <section-name>

For more information and a list of supported ``tox`` environments, see
``tox.ini`` in the PyKMIP root directory.

Platforms
=========
PyKMIP has been tested and runs on the following platform(s):

* Ubuntu 12.04 LTS

PyKMIP is supported by Python 2.6, 2.7, 3.3, and 3.4.

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
.. |coverage-status| image:: https://coveralls.io/repos/OpenKMIP/PyKMIP/badge.svg
  :target: https://coveralls.io/github/OpenKMIP/PyKMIP


