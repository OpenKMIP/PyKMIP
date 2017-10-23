Frequently Asked Questions
==========================

.. contents:: Table of Contents

What algorithms are available for creating symmetric encryption keys? For asymmetric encryption keys (i.e., key pairs)?
-----------------------------------------------------------------------------------------------------------------------
The KMIP specification supports a wide variety of symmetric and asymmetric
key algorithms. Support for these algorithms, including corresponding key
lengths, will vary across different KMIP-compliant devices, so check with
your KMIP vendor or with your appliance documentation to determine which
ones are available.

For a full list of the cryptographic algorithms supported by the KMIP
specification, see :term:`cryptographic_algorithm`. The following algorithms
are supported by the PyKMIP server.

Symmetric Key Algorithms
~~~~~~~~~~~~~~~~~~~~~~~~
* `3DES`_
* `AES`_
* `Blowfish`_
* `Camellia`_
* `CAST5`_
* `IDEA`_
* `RC4`_

Asymmetric Key Algorithms
~~~~~~~~~~~~~~~~~~~~~~~~~
* `RSA`_

How does the PyKMIP server handle client identity and authentication?
---------------------------------------------------------------------
Client authentication for the PyKMIP server is currently enforced by the
validation of the client certificate used to establish the client/server
TLS connection. If the client connects to the server with a certificate
that has been signed by a certificate authority recognized by the server,
the connection is allowed. If the server cannot validate the client's
certificate, the connection is blocked and the client cannot access any
objects stored on the server.

If client authentication succeeds, the identity of the client is obtained
from the client's certificate. The server will extract the common name from
the certificate's subject distinguished name and use the common name as the
identity of the client. If the ``enable_tls_client_auth`` configuration
setting is set to ``True``, the server will check the client's certificate
for the extended key usage extension (see `RFC 5280`_). In this case the
certificate must have the extension marked for client authentication, which
indicates that the certificate can be used to derive client identity. If
the extension is not present or is marked incorrectly, the server will not
be able to derive the client's identity and will close the connection. If
the ``enable_tls_client_auth`` configuration setting is set to ``False``,
the certificate extension check is omitted.

Once the client's identity is obtained, the client's request is processed. Any
objects created or registered by the client will be marked as owned by the
client identity. This identity is then used in conjunction with KMIP operation
policies to enforce object access control (see the next question for more
information).

How does the PyKMIP server manage access control for the keys and objects it stores?
------------------------------------------------------------------------------------
Access control for server objects is managed through KMIP operation policies.
An operation policy is a set of permissions, indexed by object type and
operation. For any KMIP object type and operation pair, the policy defines
who is allowed to conduct the operation on the object type.

There are three basic permissions currently supported by KMIP: Allow All,
Allow Owner, and Disallow All. An object type/operation pair mapped to the
Allow All permission indicates that any client authenticated with the server
can conduct the corresponding operation on any object of the corresponding
type. The Allow Owner permission restricts the operation to any client
authenticated and identified as the owner of the object. The Disallow All
permission blocks any client from conducting the operation on the object and
is usually reserved for static public objects or tasks that only the server
itself is allowed to perform.

For example, let's examine a simple use case where a client wants to retrieve
a symmetric key from the server. The client submits a Get request to the
server, including the UUID of the symmetric key it wants to retrieve. The
server will derive the client's identity and then lookup the object with the
corresponding UUID. If the object is located, the server will check the
object's operation policy attribute for the name of the operation policy
associated with the object. The server will then use the operation policy, the
client's identity, the object's type, the object's owner, and the operation to
determine if the client can retrieve the symmetric key. If the operation
policy has symmetric keys and the Get operation mapped to Allow All, the
operation is allowed for the client regardless of the client's identity and
the symmetric key is returned to the client. If the permission is set to Allow
Owner, the server will return the symmetric key only if the client's identity
matches the object's owner. If the permission is set to Disallow All, the
server will refuse to return the symmetric key, regardless of the client's
identity.

While an operation policy can cover every possible combination of object type
and operation, it does not have to. If a policy does not cover a specific
object type or operation, the server defaults to the safest option and acts
as if the permission was set to Disallow All.

Each KMIP object is assigned an operation policy and owner upon creation. If
no operation policy is included in the creation request, the server
automatically assigns it the ``default`` operation policy. The ``default``
operation policy is defined in the KMIP specification and is built-in to the
PyKMIP server; it cannot be redefined or overridden by the user or server
administrator (see the next question for details on built-in operation
policies).

In addition to the built-in operation policies, the PyKMIP server does allow
users to define their own operation policies. An example policy file,
``policy.json``, is included in the ``examples`` directory of the PyKMIP
repository. Let's take a look at the first few lines from the policy:

.. code-block:: json

    {
        "example": {
            "CERTIFICATE": {
                "LOCATE": "ALLOW_ALL",
                "CHECK":  "ALLOW_ALL",
            }
        }
    }

The first piece of information in the policy file is the name of the policy,
in this case ``example``. The name maps to a set of object types, which in
turn are mapped to a set of operations with associated permissions. In the
snippet above, the first object type supported is ``CERTIFICATE`` followed by
two supported operations, ``LOCATE`` and ``CHECK``. Both operations are mapped
to the ``ALLOW_ALL`` permission. Putting this all together, for the ``example``
policy certificate objects used with the ``Locate`` or ``Check`` operations are
allowed for all clients, regardless of who owns the certificate being accessed.
If you examine the full example file, you will see more operations listed,
along with additional object types.

In general, a policy file is a basic JSON file that links a name for the policy
to a table of object type/operation pairs that each map to one of the
permissions defined above. Users can copy this policy file and edit it to
create their own policies. Once the policy is ready, the server administrator
can place it in the server's policy directory and restart the server to load
in the new policy. The server administrator can configure which directory
should act as the server's policy directory by setting the ``policy_path``
configuration option in the server's ``server.conf`` file. Note that it is up
to the server administrator to ensure that user-defined policies do not
overwrite each other by using identical policy names.

What built-in operation policies does the PyKMIP server support?
----------------------------------------------------------------
The PyKMIP server defines two built-in operation policies: ``default`` and
``public``. Both of these policies are defined in the KMIP specification and
each is a reserved policy; neither can be renamed or overridden by
user-defined policies. The ``default`` policy is used for newly created objects
that are not assigned a policy by their creators, though it can be used by
creators intentionally. The ``public`` policy is intended for use with template
objects that are public to the entire user-base of the server.

The following tables define the permissions for each of the built-in policies.

``default`` policy
~~~~~~~~~~~~~~~~~~
=============  ====================  ============
Object Type    Operation             Permission
=============  ====================  ============
Certificate    Locate                Allow All
Certificate    Check                 Allow All
Certificate    Get                   Allow All
Certificate    Get Attributes        Allow All
Certificate    Get Attribute List    Allow All
Certificate    Add Attribute         Allow Owner
Certificate    Modify Attribute      Allow Owner
Certificate    Delete Attribute      Allow Owner
Certificate    Obtain Lease          Allow All
Certificate    Activate              Allow Owner
Certificate    Revoke                Allow Owner
Certificate    Destroy               Allow Owner
Certificate    Archive               Allow Owner
Certificate    Recover               Allow Owner
Symmetric Key  Rekey                 Allow Owner
Symmetric Key  Rekey Key Pair        Allow Owner
Symmetric Key  Derive Key            Allow Owner
Symmetric Key  Locate                Allow Owner
Symmetric Key  Check                 Allow Owner
Symmetric Key  Get                   Allow Owner
Symmetric Key  Get Attributes        Allow Owner
Symmetric Key  Get Attribute List    Allow Owner
Symmetric Key  Add Attribute         Allow Owner
Symmetric Key  Modify Attribute      Allow Owner
Symmetric Key  Delete Attribute      Allow Owner
Symmetric Key  Obtain Lease          Allow Owner
Symmetric Key  Get Usage Allocation  Allow Owner
Symmetric Key  Activate              Allow Owner
Symmetric Key  Revoke                Allow Owner
Symmetric Key  Destroy               Allow Owner
Symmetric Key  Archive               Allow Owner
Symmetric Key  Recover               Allow Owner
Public Key 	   Locate                Allow All
Public Key     Check                 Allow All
Public Key     Get                   Allow All
Public Key 	   Get Attributes        Allow All
Public Key     Get Attribute List    Allow All
Public Key     Add Attribute         Allow Owner
Public Key     Modify Attribute      Allow Owner
Public Key     Delete Attribute      Allow Owner
Public Key     Obtain Lease          Allow All
Public Key     Activate              Allow Owner
Public Key     Revoke                Allow Owner
Public Key     Destroy               Allow Owner
Public Key     Archive               Allow Owner
Public Key     Recover               Allow Owner
Private Key    Rekey                 Allow Owner
Private Key    Rekey Key Pair        Allow Owner
Private Key    Derive Key            Allow Owner
Private Key    Locate                Allow Owner
Private Key    Check                 Allow Owner
Private Key    Get                   Allow Owner
Private Key    Get Attributes        Allow Owner
Private Key    Get Attribute List    Allow Owner
Private Key    Add Attribute         Allow Owner
Private Key    Modify Attribute      Allow Owner
Private Key    Delete Attribute      Allow Owner
Private Key    Obtain Lease          Allow Owner
Private Key    Get Usage Allocation  Allow Owner
Private Key    Activate              Allow Owner
Private Key    Revoke                Allow Owner
Private Key    Destroy               Allow Owner
Private Key    Archive               Allow Owner
Private Key    Recover               Allow Owner
Split Key      Rekey                 Allow Owner
Split Key      Rekey Key Pair        Allow Owner
Split Key      Derive Key            Allow Owner
Split Key      Locate                Allow Owner
Split Key      Check                 Allow Owner
Split Key      Get                   Allow Owner
Split Key      Get Attributes        Allow Owner
Split Key      Get Attribute List    Allow Owner
Split Key      Add Attribute         Allow Owner
Split Key      Modify Attribute      Allow Owner
Split Key      Delete Attribute      Allow Owner
Split Key      Obtain Lease          Allow Owner
Split Key      Get Usage Allocation  Allow Owner
Split Key      Activate              Allow Owner
Split Key      Revoke                Allow Owner
Split Key      Destroy               Allow Owner
Split Key      Archive               Allow Owner
Split Key      Recover               Allow Owner
Template       Locate                Allow Owner
Template       Get                   Allow Owner
Template       Get Attributes        Allow Owner
Template       Get Attribute List    Allow Owner
Template       Add Attribute         Allow Owner
Template       Modify Attribute      Allow Owner
Template       Delete Attribute      Allow Owner
Template       Destroy               Allow Owner
Secret Data    Rekey                 Allow Owner
Secret Data    Rekey Key Pair        Allow Owner
Secret Data    Derive Key            Allow Owner
Secret Data    Locate                Allow Owner
Secret Data    Check                 Allow Owner
Secret Data    Get                   Allow Owner
Secret Data    Get Attributes        Allow Owner
Secret Data    Get Attribute List    Allow Owner
Secret Data    Add Attribute         Allow Owner
Secret Data    Modify                Allow Owner
Secret Data    Delete Attribute      Allow Owner
Secret Data    Obtain Lease          Allow Owner
Secret Data    Get Usage Allocation  Allow Owner
Secret Data    Activate              Allow Owner
Secret Data    Revoke                Allow Owner
Secret Data    Destroy               Allow Owner
Secret Data    Archive               Allow Owner
Secret Data    Recover               Allow Owner
Opaque Data    Rekey                 Allow Owner
Opaque Data    Rekey Key Pair        Allow Owner
Opaque Data    Derive Key            Allow Owner
Opaque Data    Locate                Allow Owner
Opaque Data    Check                 Allow Owner
Opaque Data    Get                   Allow Owner
Opaque Data    Get Attributes        Allow Owner
Opaque Data    Get Attribute List    Allow Owner
Opaque Data    Add Attribute         Allow Owner
Opaque Data    Modify Attribute      Allow Owner
Opaque Data    Delete Attribute      Allow Owner
Opaque Data    Obtain Lease          Allow Owner
Opaque Data    Get Usage Allocation  Allow Owner
Opaque Data    Activate              Allow Owner
Opaque Data    Revoke                Allow Owner
Opaque Data    Destroy               Allow Owner
Opaque Data    Archive               Allow Owner
Opaque Data    Recover               Allow Owner
PGP Key        Rekey                 Allow Owner
PGP Key        Rekey Key Pair        Allow Owner
PGP Key        Derive Key            Allow Owner
PGP Key        Locate                Allow Owner
PGP Key        Check                 Allow Owner
PGP Key        Get                   Allow Owner
PGP Key        Get Attributes        Allow Owner
PGP Key        Get Attribute List    Allow Owner
PGP Key        Add Attribute         Allow Owner
PGP Key        Modify Attribute      Allow Owner
PGP Key        Delete Attribute      Allow Owner
PGP Key        Obtain Lease          Allow Owner
PGP Key        Get Usage Allocation  Allow Owner
PGP Key        Activate              Allow Owner
PGP Key        Revoke                Allow Owner
PGP Key        Destroy               Allow Owner
PGP Key        Archive               Allow Owner
PGP Key        Recover               Allow Owner
=============  ====================  ============

``public`` policy
~~~~~~~~~~~~~~~~~
===========  ==================  ============
Object Type  Operation           Permission
===========  ==================  ============
Template     Locate              Allow All
Template     Get                 Allow All
Template     Get Attributes      Allow All
Template     Get Attribute List  Allow All
Template     Add Attribute       Disallow All
Template     Modify Attribute    Disallow All
Template     Delete Attribute    Disallow All
Template     Destroy             Disallow All
===========  ==================  ============


.. |check| unicode:: U+2713
.. _`3DES`: https://en.wikipedia.org/wiki/Triple_DES
.. _`AES`: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
.. _`Blowfish`: https://en.wikipedia.org/wiki/Blowfish_%28cipher%29
.. _`Camellia`: https://en.wikipedia.org/wiki/Camellia_%28cipher%29
.. _`CAST5`: https://en.wikipedia.org/wiki/CAST-128
.. _`IDEA`: https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm
.. _`RC4`: https://en.wikipedia.org/wiki/RC4
.. _`RSA`: https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29
.. _`RFC 5280`: https://www.ietf.org/rfc/rfc5280.txt