======
PyKMIP
======

PyKMIP is a Python implementation of the Key Management Interoperability
Protocol (KMIP) specification, supporting version 1.1 of the KMIP standard.
KMIP is an OASIS standard specifying a client/server-based protocol to perform
key, certificate, or generic object management relating generally to storage
and maintenance operations. The PyKMIP library currently provides a KMIP
client and server supporting the following operations for the KMIP
SymmetricKey managed object:

* create
* register
* get
* destroy

Note that KMIP specifies profiles that tailor the standard to specific use
cases. The KMIP Profile Support section below includes several profiles that
need to be developed for PyKMIP to more fully support the symmetric key storage
and generation capabilities.  A list of operations necessary for these profiles
are also included.

The PyKMIP software-based KMIP server is intended for use only in testing and
demonstration environments. Note that the PyKMIP server is NOT intended to be
a substitute for secured, hardware-based KMIP appliances.  The PyKMIP client
should be used for operational purposes only with a hardware-based KMIP server.

Version
=======
Earlier versions of PyKMIP are not intended to support KMIP profiles.  Work
to further mature PyKMIP to add support for basic profiles is underway (see
below.) For more information on KMIP profiles, see the OASIS documentation
in the reference section.

Note that development of the PyKMIP client and server should take place in
parallel to facilitate testing of each operation as it is developed.


Platform
========
PyKMIP has been tested and runs on Ubuntu 12.04 LTS.


KMIP Profile Support
====================
The KMIP standard includes various profiles that tailor the standard for
specific use cases, such as for symmetric key storage with TLS1.2 specified.
These profiles specify conformance to certain operations and attributes. The
operations listed directly below are needed to support symmetric key profiles
also listed below.  We would appreciate help in the development of these
operations, and have listed our recommended order of development prioritization
to consider.  This list is in order of decending priority.  Since development
is already underway, and code will be merged, please check the code base to
assess the status of operations prior to development. Note that these operations
support KMIP Profiles that are listed at the end of this document.

KMIP Operations to add to PyKMIP, in our recommended order of priority:
- Discover Versions
- Locate
- Check
- Revoke
- Get Attributes
- Get Attribute List
- Add Attribute
- Modify Attribute
- Delete Attribute
- Activate
- Query

Note that Create, Register, Get, and Destroy operations were completed with the
initial version of PyKMIP to allow very basic KMIP symmetric key operations.


Profiles that support KMIP symmetric key opererations (see link in references
section):

4.2* "Basic Baseline Server KMIP Profile" (includes TLS 1.0+)
Client to Server Operations needed for this (See 5.2*):
Required operations include Locate, Check, Get, Get Attributes, Get Attribute
List, Add Attribute, Modify Attribute, Delete Attribute, Activate, Revoke,
Destroy, Query, and Discover Versions (but not Register or Create)

4.14* "Symmetric Key Store and Server TLS 1.2 Authentication KMIP Profile"
Client to Server Operations needed for this (See 5.4*)
- All operations from *4.2 and also Register operation

4.15* "Symmetric Key Foundry and Server TLS 1.2 Authentication KMIP profile"
Client to Server Operations needed for this (See 5.5*)
- All operations from *4.2 and also Create operation

4.22* "Basic Baseline Client KMIP Profile" (includes TLS 1.0+)
Client to Server Operations needed for this (See 5.12*):
Required operations include Locate, Check, Get, Get Attributes, Get Attribute
List, Add Attribute, Modify Attribute, Delete Attribute, Activate, Revoke,
Destroy, Query, and Discover Versions (but not Register or Create)

4.34* "Symmetric Key Store Client TLS 1.2 Authentication KMIP Profile"
Client to Server Operations needed for this (See 5.14*)
- All operations from *4.22 and also Register operation

4.35* "Symmetric Key Foundry Client TLS 1.2 Authentication KMIP profile"
Client to Server Operations needed for this (See 5.15*)
- All operations from *4.22 and also Create operation

4.42* "Storage Client TLS 1.2 Authentication KMIP Profile"
Client to Server Operations needed for this (See 5.21*)
- All operations from *4.22, Register from *4.34, and Create from *4.35


* This designator points to a section in the Key Management Interoperability
Profiles Version 1.1.  The link to this document is in the references section
below.

References
==========

For more information on the KMIP specification, see the `OASIS documentation
for KMIP
<http://docs.oasis-open.org/kmip/spec/v1.1/os/kmip-spec-v1.1-os.html>`_.
<http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html>`_.


Contributors
============

Many thanks to the developers who created PyKMIP:

Nathan Reller <nathan.reller@jhuapl.edu>
Peter Hamilton <peter.hamilton@jhuapl.edu>
Kaitlin Farr <kaitlin.farr@jhuapl.edu>
