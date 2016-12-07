------
PyKMIP
------
|pypi-version|
|travis-status|
|codecov-status|
|python-versions|

PyKMIP is a Python implementation of the Key Management Interoperability
Protocol (KMIP). KMIP is a client/server communication protocol for the
storage and maintenance of key, certificate, and secret objects. The standard
is governed by the `Organization for the Advancement of Structured Information
Standards`_ (OASIS). PyKMIP supports a subset of features in versions
1.0 - 1.2 of the KMIP specification.

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
* ``GetAttributes``
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
* ``GetAttributes``
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
      config='client'
  )

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
implementation of a KMIP server, ``kmip.services.server.KmipServer``.
However, the server is intended for use only in testing and demonstration
environments. The server is **not** intended to be a substitute for a secure,
hardware-based key management appliance. The PyKMIP client should be used for
operational purposes **only** with a hardware-based KMIP server.

The KMIP server provides support for the following operations:

* ``Create``
* ``CreateKeyPair``
* ``Register``
* ``Get``
* ``GetAttributes``
* ``Activate``
* ``Destroy``
* ``Query``
* ``DiscoverVersions``

Configuration
*************
The PyKMIP software server can be configured via configuration file, by
default located at ``/etc/pykmip/server.conf``. An example server
configuration settings block, as found in the configuration file, is shown
below::

  [server]
  hostname=127.0.0.1
  port=5696
  certificate_path=/path/to/certificate/file
  key_path=/path/to/certificate/key/file
  ca_path=/path/to/ca/certificate/file
  auth_suite=Basic
  policy_path=/path/to/policy/file

The server can also be configured manually. The following example shows how
to create the ``KmipServer`` in Python code, directly specifying the
different configuration values::

  server = KmipServer(
      hostname='127.0.0.1',
      port=5696,
      certificate_path='/path/to/certificate/file/',
      key_path='/path/to/certificate/key/file/',
      ca_path='/path/to/ca/certificate/file/',
      auth_suite='Basic',
      config_path='/etc/pykmip/server.conf',
      log_path='/var/log/pykmip/server.log',
      policy_path='/etc/pykmip/policies'
  )

**NOTE:** The ``kmip_server.KMIPServer`` implementation of the software
server is deprecated and will be removed in a future version of PyKMIP.

The different configuration options are defined below:

* ``hostname``
    A string representing either a hostname in Internet domain notation or an
    IPv4 address.
* ``port``
    An integer representing a port number. Recommended to be ``5696``
    according to the KMIP specification.
* ``certificate_path``
    A string representing a path to a PEM-encoded server certificate file. For
    more information, see the `Python SSL library documentation`_.
* ``key_path``
    A string representing a path to a PEM-encoded server certificate key file.
    The private key contained in the file must correspond to the certificate
    pointed to by ``certificate_path``. For more information, see the
    `Python SSL library documentation`_.
* ``ca_path``
    A string representing a path to a PEM-encoded certificate authority
    certificate file. If using a self-signed certificate, the ``ca_path`` and
    the ``certificate_path`` should be identical. For more information, see
    the `Python SSL library documentation`_.
* ``auth_suite``
    A string representing the type of authentication suite to use when
    establishing TLS connections. Acceptable values are ``Basic`` and
    ``TLS1.2``.
    **Note:** ``TLS1.2`` can only be used with versions of Python that support
    TLS 1.2 (e.g,. Python 2.7.9+ or Python 3.4+). If you are running on an
    older version of Python, you will only be able to use basic TLS 1.0
    authentication. For more information, see the
    `Python SSL library documentation`_ and the
    `Key Management Interoperability Protocol Profiles Version 1.1`_
    documentation.
* ``config_path``
    A string representing a path to a server configuration file, as shown
    above. Only set via the ``KmipServer`` constructor. Defaults to
    ``/etc/pykmip/server.conf``.
* ``log_path``
    A string representing a path to a log file. The server will set up a
    rotating file logger on this file. Only set via the ``KmipServer``
    constructor. Defaults to ``/var/log/pykmip/server.log``.
* ``policy_path``
    A string representing a path to the filesystem directory containing
    PyKMIP server operation policy JSON files.

**NOTE:** When installing PyKMIP and deploying the KMIP software server, you
must manually set up the server configuration file. It **will not** be placed
in ``/etc/pykmip`` automatically.

Usage
*****
The software server can be run using the ``bin/run_server.py`` startup script.
If you are currently in the PyKMIP root directory, use the following command::

  $ python bin/run_server.py

If you need more information about running the startup script, pass ``-h``
to it::

  $ python bin/run_server.py -h

**NOTE:** You may need to run the server as root, depending on the
permissions of the configuration, log, and certificate file directories.

If PyKMIP is installed and you are able to ``import kmip`` in Python, you can
copy the startup script and run it from any directory you choose.

Identity & Ownership
********************
The software server determines client identity using the client's TLS
certificate. Specifically, the common name of the certificate subject is used
as the client ID. Additionally, the client certificate must have an extended
key usage extension marked for client authentication. If this extension is
not included in the client certificate and/or the client does not define a
subject and common name, the server will fail to establish a client session.
For more information on certificates and their use in authentication, see
`RFC 5280`_.

The client identity described above is used to anchor object ownership.
Object ownership and access is governed by an object's operation policy,
defined on object creation. By default the KMIP specification defines two
operation policies, a ``default`` policy covering all objects and a
``public`` policy applied only to ``Template`` objects.

For example, if user A creates a symmetric key, user B will only be able
to retrieve that key if the key's operation policy indicates that the
key is accessible to all users. If the operation policy specifies that
the key is only available to the owner, only user A will be able to access
it.

Users can create their own operation policies by placing operation policy
JSON files in the policy directory pointed to by the ``policy_path``
configuration option. The server will load all policies from that directory
upon start up, allowing users to use those policies for their objects. A
template for the operation policy JSON file can be found under ``examples``.
Note that the ``default`` and ``public`` policies are reserved and cannot
be redefined by a user's policy.

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
the name of a client configuration section in the ``pykmip.conf``
configuration file. See the Usage_ section for more information.

To run the integration test suite with a specific configuration setup::

  $ tox -e integration -- --config <section-name>

For more information and a list of supported ``tox`` environments, see
``tox.ini`` in the PyKMIP root directory.

Platforms
=========
PyKMIP has been tested and runs on the following platform(s):

* Ubuntu: 12.04 LTS, 14.04 LTS, 16.04 LTS

PyKMIP is supported by Python 2.6, 2.7, 3.3 - 3.5.

**NOTE:** Support for Python 2.6 will be deprecated in a future release of PyKMIP.

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
.. _RFC 5280: https://tools.ietf.org/html/rfc5280

.. |pypi-version| image:: https://img.shields.io/pypi/v/pykmip.svg
  :target: https://pypi.python.org/pypi/pykmip
  :alt: Latest Version
.. |travis-status| image:: https://travis-ci.org/OpenKMIP/PyKMIP.svg?branch=master
  :target: https://travis-ci.org/OpenKMIP/PyKMIP
.. |codecov-status| image:: https://codecov.io/github/OpenKMIP/PyKMIP/coverage.svg?branch=master
  :target: https://codecov.io/github/OpenKMIP/PyKMIP?branch=master
.. |python-versions| image:: https://img.shields.io/pypi/pyversions/PyKMIP.svg
  :target: https://github.com/OpenKMIP/PyKMIP
