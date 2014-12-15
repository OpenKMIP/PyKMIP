------
PyKMIP
------

PyKMIP is a Python implementation of the Key Management Interoperability
Protocol (KMIP) specification, supporting version 1.1 of the KMIP standard.
The KMIP standard is governed by the `Organization for the Advancement of
Structured Information Standards`_ (OASIS) and specifies a
client/server-based protocol to perform key, certificate, and secret object
management, including storage and maintenance operations.

The PyKMIP library currently provides a KMIP client and server supporting
the following operations for the KMIP SymmetricKey managed object:

* Create
* Register
* Get
* Destroy

Note that KMIP specifies profiles that tailor the standard to specific use
cases. The `KMIP Profile Support`_ section includes several profiles that
need to be developed for PyKMIP to fully support symmetric key storage and
generation capabilities.  A list of operations necessary for these profiles
is included.

The PyKMIP software-based KMIP server is intended for use only in testing
and demonstration environments. Note that the PyKMIP server is **NOT**
intended to be a substitute for secured, hardware-based KMIP appliances.
The PyKMIP client should be used for operational purposes only with a
hardware-based KMIP server. The development of the PyKMIP client and server
should take place in parallel to facilitate testing of each operation as it
is developed.

Platforms
=========
PyKMIP has been tested and runs on Ubuntu 12.04 LTS.

.. _KMIP Profile Support:

KMIP Profile Support
====================
The KMIP standard includes various profiles that tailor the standard for
specific use cases (e.g., symmetric key storage with TLS 1.2). These
profiles specify conformance to certain operations and attributes. The
operations listed below are needed to support symmetric key profiles, which
are also provided below. We would appreciate help in the development of
these operations, and have listed our recommended order of development
prioritization in descending order. Since active development of these
features is already underway, please check the `code base`_ to assess the
status of operations prior to development.

KMIP operations to add to PyKMIP:

* Discover Versions
* List
* Check
* Revoke
* Get Attributes
* Get Attribute List
* Add Attribute
* Modify Attribute
* Delete Attribute
* Activate
* Query

Note that the Create, Register, Get, and Destroy operations were completed
with the initial version of PyKMIP to allow very basic KMIP symmetric key
operations.

Server Profiles
---------------
Server profiles that support KMIP symmetric key operations:

* `Basic Baseline Server KMIP Profile`_ (includes TLS 1.0+)

  * Client-to-Server operations needed for this (see the `Baseline Server Clause`_) include:

    * Locate
    * Check
    * Get
    * Get Attributes
    * Get Attribute
    * List
    * Add Attribute
    * Modify Attribute
    * Delete Attribute
    * Activate
    * Revoke
    * Destroy
    * Query
    * Discover Versions

* `Symmetric Key Store and Server TLS 1.2 Authentication KMIP Profile`_

  * Client-to-Server operations needed for this (see the `Symmetric Key Store and Server Conformance Clause`_) include all operations from the `Basic Baseline Server KMIP Profile`_ and also the Register operation.

* `Symmetric Key Foundry and Server TLS 1.2 Authentication KMIP profile`_

  * Client-to-Server operations needed for this (see the `Symmetric Key Foundry and Server Conformance Clause`_) include all operations from the `Basic Baseline Server KMIP Profile`_ and also the Create operation.

Client Profiles
---------------
Client profiles that support KMIP symmetric key operations:

* `Basic Baseline Client KMIP Profile`_ (includes TLS 1.0+)

  * Client-to-Server operations needed for this (see the `Baseline Client Clause`_) include:

    * Locate
    * Check
    * Get
    * Get Attributes
    * Get Attribute
    * List
    * Add Attribute
    * Modify Attribute
    * Delete Attribute
    * Activate
    * Revoke
    * Destroy
    * Query
    * Discover Versions

* `Symmetric Key Store Client TLS 1.2 Authentication KMIP Profile`_

  * Client-to-Server operations needed for this (see the `Symmetric Key Store Client Conformance Clause`_) include all operations from the `Basic Baseline Client KMIP Profile`_ and also the Register operation.

* `Symmetric Key Foundry Client TLS 1.2 Authentication KMIP Profile`_

  * Client-to-Server operations needed for this (see the `Symmetric Key Foundry Client Conformance Clause`_) include all operations from the `Basic Baseline Client KMIP Profile`_ and also the Create operation.

* `Storage Client TLS 1.2 Authentication KMIP Profile`_

  * Client-to-Server operations needed for this (see the `Storage Client Conformance Clauses`_) include all operations from the `Basic Baseline Client KMIP Profile`_, the Register operation from the `Symmetric Key Store Client TLS 1.2 Authentication KMIP Profile`_, and the Create operation from the `Symmetric Key Foundry Client TLS 1.2 Authentication KMIP Profile`_.

References
==========
The source code for PyKMIP is hosted on GitHub and the library is available
for installation from the Python Package Index (PyPI):

* `GitHub <https://github.com/OpenKMIP/PyKMIP>`_
* `PyPI <https://pypi.python.org/pypi/PyKMIP>`_

For more information on KMIP version 1.1, see the following documentation:

* `Key Management Interoperability Protocol Specification Version 1.1`_
* `Key Management Interoperability Protocol Profiles Version 1.1`_
* `Key Management Interoperability Protocol Test Cases Version 1.1`_

.. _code base: https://github.com/OpenKMIP/PyKMIP
.. _Organization for the Advancement of Structured Information Standards: https://www.oasis-open.org/
.. _Key Management Interoperability Protocol Specification Version 1.1: http://docs.oasis-open.org/kmip/spec/v1.1/os/kmip-spec-v1.1-os.html
.. _Key Management Interoperability Protocol Profiles Version 1.1: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html
.. _Key Management Interoperability Protocol Test Cases Version 1.1: http://docs.oasis-open.org/kmip/testcases/v1.1/cn01/kmip-testcases-v1.1-cn01.html
.. _Basic Baseline Server KMIP Profile: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820691
.. _Symmetric Key Store and Server TLS 1.2 Authentication KMIP Profile: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820703
.. _Symmetric Key Foundry and Server TLS 1.2 Authentication KMIP Profile: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820704
.. _Basic Baseline Client KMIP Profile: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820711
.. _Symmetric Key Store Client TLS 1.2 Authentication KMIP Profile: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820723
.. _Symmetric Key Foundry Client TLS 1.2 Authentication KMIP Profile: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820724
.. _Storage Client TLS 1.2 Authentication KMIP Profile: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820731
.. _Baseline Server Clause: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820736
.. _Symmetric Key Store and Server Conformance Clause: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820742
.. _Symmetric Key Foundry and Server Conformance Clause: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820745
.. _Baseline Client Clause: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820766
.. _Symmetric Key Store Client Conformance Clause: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820772
.. _Symmetric Key Foundry Client Conformance Clause: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820775
.. _Storage Client Conformance Clauses: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820793
