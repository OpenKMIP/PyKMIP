Server
======

.. warning::
   The PyKMIP server is intended for testing and demonstration purposes only.
   It is **not** a replacement for a secure, hardened, hardware-based key
   management appliance. It should **not** be used in a production-level
   environment, nor for critical operations.

The PyKMIP server is a software implementation of a KMIP-compliant key
management appliance. It supports over a dozen key management operations,
including key lifecycle management, object metadata access, and cryptographic
functions like encrypting and signing data.

The server is used to test the functionality of the PyKMIP client and library
and is primarily intended as a testing and demonstration tool.

Configuration
-------------
The server settings can be managed by a configuration file, by default located
at ``/etc/pykmip/server.conf``. An example server configuration settings block,
as found in the configuration file, is shown below:

.. code-block:: console

    [server]
    hostname=127.0.0.1
    port=5696
    certificate_path=/path/to/certificate/file
    key_path=/path/to/certificate/key/file
    ca_path=/path/to/ca/certificate/file
    auth_suite=Basic
    policy_path=/path/to/policy/file
    enable_tls_client_auth=True
    tls_cipher_suites=
        TLS_RSA_WITH_AES_128_CBC_SHA256
        TLS_RSA_WITH_AES_256_CBC_SHA256
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    logging_level=DEBUG
    database_path=/tmp/pykmip.db

The server can also be configured manually via Python. The following example
shows how to create the ``KmipServer`` in Python code, directly specifying the
different configuration values:

.. code-block:: python

    >>> from kmip.services.server import KmipServer
    >>> server = KmipServer(
    ...     hostname='127.0.0.1',
    ...     port=5696,
    ...     certificate_path='/path/to/certificate/file/',
    ...     key_path='/path/to/certificate/key/file/',
    ...     ca_path='/path/to/ca/certificate/file/',
    ...     auth_suite='Basic',
    ...     config_path='/etc/pykmip/server.conf',
    ...     log_path='/var/log/pykmip/server.log',
    ...     policy_path='/etc/pykmip/policies',
    ...     enable_tls_client_auth=True,
    ...     tls_cipher_suites=[
    ...         'TLS_RSA_WITH_AES_128_CBC_SHA256',
    ...         'TLS_RSA_WITH_AES_256_CBC_SHA256',
    ...         'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384'
    ...     ],
    ...     logging_level='DEBUG',
    ...     database_path='/tmp/pykmip.db'
    ... )

The different configuration options are defined below:

* ``hostname``
    A string representing either a hostname in Internet domain notation or an
    IPv4 address.
* ``port``
    An integer representing a port number. Recommended to be ``5696``
    according to the KMIP specification.
* ``certificate_path``
    A string representing a path to a PEM-encoded server certificate file. For
    more information, see the `ssl`_ documentation.
* ``key_path``
    A string representing a path to a PEM-encoded server certificate key file.
    The private key contained in the file must correspond to the certificate
    pointed to by ``certificate_path``. For more information, see the `ssl`_
    documentation.
* ``ca_path``
    A string representing a path to a PEM-encoded certificate authority
    certificate file. If using a self-signed certificate, the ``ca_path`` and
    the ``certificate_path`` should be identical. For more information, see
    the `ssl`_ documentation.
* ``auth_suite``
    A string representing the type of authentication suite to use when
    establishing TLS connections. Acceptable values are ``Basic`` and
    ``TLS1.2``.

    .. note::
       ``TLS1.2`` can only be used with versions of Python that support
       TLS 1.2 (e.g,. Python 2.7.9+ or Python 3.4+). If you are running on an
       older version of Python, you will only be able to use basic TLS 1.0
       authentication. For more information, see the `ssl`_ documentation.
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
* ``enable_tls_client_auth``
    A boolean indicating whether or not extension checks should be performed
    on client certificates to verify that they can be used to derive client
    identity. This setting is enabled by default for backwards compatibility
    and must be explicitly disabled if this behavior is not desired.
* ``tls_cipher_suites``
    A list of strings representing the set of cipher suites to use when
    establishing TLS connections with new clients. Enable debug logging for
    more information on the cipher suites used by the client and server.
* ``logging_level``
    A string indicating what the base logging level should be for the server.
    Options include: DEBUG, INFO, WARNING, ERROR, and CRITICAL. The DEBUG
    log level logs the most information, the CRITICAL log level logs the
    least.
* ``database_path``
    A string representing a path to a SQLite database file. The server will
    store all managed objects (e.g., keys, certificates) in this file.

.. note::
   When installing PyKMIP and deploying the server, you must manually set up
   the server configuration file. It **will not** be placed in ``/etc/pykmip``
   automatically. See ``/examples`` in the PyKMIP repository for a boilerplate
   configuration file to get started.

.. _`third-party-auth-config`:

Third-Party Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~

To configure third-party authentication plugins, separate configuration blocks
must be specified in the server configuration file.

.. note::
    Third-party authentication settings can only be set in the server
    configuration file. There is no way to set them using the ``KmipServer``
    constructor in Python code.

An example authentication plugin configuration settings block is shown below:

.. code-block:: console

    [auth:slugs]
    enabled=False
    url=http://127.0.0.1:8080/slugs/

All authentication plugin configuration settings blocks must begin with the
string ``auth:``. For more information on third-party authentication
integration, see :ref:`third-party-auth-integration`.

Usage
-----
The software server can be run using the ``bin/run_server.py`` startup script.
If you are currently in the PyKMIP root directory, use the following command:

.. code-block:: console

   $ python bin/run_server.py

If you need more information about running the startup script, pass ``-h``
to it:

.. code-block: console

   $ python bin/run_server.py -h

.. note::
   You may need to run the server as root, depending on the permissions of the
   configuration, log, and certificate file directories.

If PyKMIP is installed and you are able to ``import kmip`` in Python, you can
copy the startup script and run it from any directory you choose.

PyKMIP also defines a system-wide entry point that can be used to run the
PyKMIP server once PyKMIP is installed. You can use the entry point like this:

.. code-block:: console

    $ pykmip-server

Storage
-------
All data storage for the server is managed via `SQLAlchemy`_. The current
backend leverages `SQLite`_, storing managed objects in a flat file. The file
location can be configured using the ``database_path`` configuration setting.
By default this file will be located at ``/tmp/pykmip.database``. If this
database file is deleted, the stored objects will be gone for good. If this
file is preserved across server restarts, object access will be maintained.

.. note::
   Updates to the server data model will generate errors if the server is
   run with a ``pykmip.database`` file adhering to an older data model. There
   is no upgrade path.

Long term, the intent is to add support for more robust database and storage
backends available through ``SQLAlchemy``. If you are interested in this work,
please see :doc:`Development <development>` for more information.

.. _authentication:

Authentication
--------------
Client authentication for the PyKMIP server is currently enforced by the
validation of the client certificate used to establish the client/server
TLS connection. If the client connects to the server with a certificate
that has been signed by a certificate authority recognized by the server,
the initial connection is allowed. If the server cannot validate the client's
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
policies to enforce object access control (see :ref:`access-control`).

.. _third-party-auth-integration:

Third-Party Integration
~~~~~~~~~~~~~~~~~~~~~~~

Beyond validating the client's certificate and extracting the client identity
from the certificate's subject distinguished name, the server also supports
a configurable framework for third-party authentication. This allows the
server to integrate with existing authentication systems.

For each enabled third-party authentication plugin, the server will query the
associated third-party service to verify that the user identified by the
client certificate is a valid user. If validation succeeds, the server will
also query the service for information pertaining to any groups the user may
belong to. This information is leveraged for fine-grained access control
(see :ref:`access-control`). No other plugins are queried once a validation
success has occurred. If validation fails, the server will attempt to
authenticate with the next enabled plugin. If validation fails for all enabled
plugins, the server will reject the client's request and close the connection.
Validation only needs to succeed for one authentication plugin for client
authentication to succeed.

If no third-party authentication plugins are enabled, the server will skip
third-party authentication and will rely solely on client certificate
validation for client authentication. Note that in this case, no user group
information is available for fine-grained access control.

For more information on configuring third-party authentication plugins, see
:ref:`third-party-auth-config`.

Supported third-party authentication plugins are discussed below.

SLUGS
*****
The Simple, Lightweight User Group Services (SLUGS) library is an open-source
web service that serves user/group membership data over a basic REST
interface. It is intended as an easy-to-use stopgap for developers and
deployers interested in leveraging third-party authentication with the PyKMIP
server.

All SLUGS plugin configuration settings blocks must begin with the string
``auth:slugs``. Multiple SLUGS plugins can be configured at once; simply add
a unique suffix to the block name to distinguish it from other blocks (e.g.,
``auth:slugs:primary``, ``auth:slugs:secondary``).

The different configuration options supported by the SLUGS plugin are defined
below:

* ``enabled``
    A boolean indicating whether or not the authentication plugin should be
    used for authentication.
* ``url``
    A string representing the URL at which to access a SLUGS REST interface.

For more information on SLUGS, see `SLUGS`_.

.. _access-control:

Access Control
--------------

Access control for server objects is managed through KMIP operation policies.
An operation policy is a set of permissions, indexed by object type and
operation. For any KMIP object type and operation pair, the policy defines
who is allowed to conduct the operation on the object type.

There are three basic permissions currently supported by KMIP:

* ``Allow All``
    This permission indicates that any client authenticated with the server
    can conduct the corresponding operation on any object of the corresponding
    type.
* ``Allow Owner``
    This permission restricts the operation to any client authenticated and
    identified as the owner of the object.
* ``Disallow All``
    This permission blocks any client from conducting the operation on the
    object and is usually reserved for static public objects or tasks that
    only the server itself is allowed to perform.

For example, let's examine a simple use case where a client wants to retrieve
a symmetric key from the server.

1. The client submits a ``Get`` request to the server (see :ref:`get`),
   including the UUID of the symmetric key it wants to retrieve.
2. The server will derive the client's identity and then lookup the object
   with the corresponding UUID.
3. If the object is located, the server will check the object's operation
   policy attribute for the name of the operation policy associated with the
   object.
4. The server will then use the operation policy, the client's identity,
   the object's type, the object's owner, and the operation to determine if
   the client can retrieve the symmetric key.
5. If the operation policy has symmetric keys and the ``Get`` operation
   mapped to ``Allow All``, the operation is allowed for the client regardless
   of the client's identity and the symmetric key is returned to the client.
   If the permission is set to ``Allow Owner``, the server will return the
   symmetric key only if the client's identity matches the object's owner.
   If the permission is set to ``Disallow All``, the server will refuse to
   return the symmetric key, regardless of the client's identity.

While an operation policy can cover every possible combination of object type
and operation, it does not have to. If a policy does not cover a specific
object type or operation, the server defaults to the safest option and acts
as if the permission was set to ``Disallow All``.

Each KMIP object is assigned an operation policy and owner upon creation. If
no operation policy is included in the creation request, the server
automatically assigns it the ``default`` operation policy. The ``default``
operation policy is defined in the KMIP specification and is built into the
PyKMIP server; it cannot be redefined or overridden by the user or server
administrator. For more information on reserved policies, see
:ref:`reserved-policies`.

Policy Files
~~~~~~~~~~~~

In addition to the built-in operation policies, the PyKMIP server allows
users to define their own operation policies via policy files. A policy file
is a basic JSON file that maps names for policies to tables of access
controls. The server dynamically loads policy files from the policy directory,
which is defined by the ``policy_path`` configuration setting. The server
tracks any changes made to the policy directory, supporting the addition,
modification, and/or removal of policy files and/or policies within those
files. This allows users and administrators to modify and update their
policies while the server is running, without any downtime. Note that it is up
to the server administrator to ensure that user-defined policies do not
overwrite each other by using identical policy names. Should this occur, the
server will cache older policies, dynamically restoring them should the naming
collision be corrected.

An example policy file, ``policy.json``, is included in the ``examples``
directory of the PyKMIP repository. Let's take a look at the first few lines
from the policy:

.. code-block:: console

    {
        "example": {
            "preset": {
                "CERTIFICATE": {
                    "LOCATE": "ALLOW_ALL",
                    "CHECK":  "ALLOW_ALL",
    ...

The first piece of information in the policy file is the name of the policy,
in this case ``example``. The name maps to collections of operation policies,
grouped into two sets. The first set, shown here, is the ``preset``
collection. The ``preset`` collection contains rules that are used when user
group information is unavailable; this is usually the case when third-party
authentication is disabled. The ``preset`` collection rules consist of a set
of object types, which in turn are mapped to a set of operations with
associated permissions. In the snippet above, the first object type supported
is ``CERTIFICATE`` followed by two supported operations, ``LOCATE`` and
``CHECK``. Both operations are mapped to the ``ALLOW_ALL`` permission. Putting
this all together, all clients are allowed to use the ``LOCATE`` and ``CHECK``
operations with certificate objects under the ``example`` policy, regardless
of who owns the certificate being accessed. If you examine the full example
file, you will see more operations listed, along with additional object types.

The second collection of operation policies that can be found in an operation
policy file is the ``groups`` collection. This collection is used to provide
group-based access control to objects. The following snippet is similar to the
above snippet, reworked to use ``groups`` instead of ``preset``:

.. code-block:: console

    {
        "example": {
            "groups": {
                "group_A": {
                    "CERTIFICATE": {
                        "GET": "ALLOW_ALL",
                        "DESTROY": "ALLOW_ALL",
                        ...
                },
                "group_B": {
                    "CERTIFICATE": {
                        "GET": "ALLOW_ALL",
                        "DESTROY": "DISALLOW_ALL",
                        ...

Like the prior snippet, the policy name is ``example``. However, unlike the
``preset`` collection shown before, the ``groups`` collection first maps to a
series of group names, in this case ``group_A`` and ``group_B``. Each group
maps to a set of object types and then access controls, following the same
structure used by ``preset``. The controls mapped under each group are
distinct. This allows the policy to provide segregated access controls for
groups of users, making it easy to share objects managed by the server while
retaining fine-grained access control. In this case, any user belonging to
``group_A`` will be able to retrieve and destroy certificates using the
``example`` policy. Users in ``group_B`` will also be able to retrieve these
certificates, but they will be unable to destroy them. Users belonging to both
groups will receive the most permissive permissions available across the set
of controls, meaning these users will be able to retrieve and destroy
certificates since the controls under ``group_A`` are the most permissive.

The ``preset`` and ``groups`` collections can be included in the same policy.
For example:

.. code-block:: console

    {
        "example": {
            "preset": {
                "CERTIFICATE": {
                    "DESTROY": "DISALLOW_ALL",
                    ...
            },
            "groups": {
                "group_A": {
                    "CERTIFICATE": {
                        "DESTROY": "ALLOW_ALL",
                    ...
                },
                "group_B": {
                    "CERTIFICATE": {
                        "DESTROY": "DISALLOW_ALL",
                        ...
                }
            }
        }
    }

As stated above, the controls belonging to the ``groups`` collection are only
enforced if user group information is available after client authentication.
If client authentication succeeds but no group information is available, the
controls belonging to the ``preset`` collection are enforced. This allows
users to effectively enable/disable group-level access controls if applicable
to their use case. If group information is provided but only ``preset``
controls are defined, the ``preset`` controls will be enforced. If group
information is not provided but only ``groups`` controls are defined,
``Disallow All`` will be the only enforced control for the policy. This
ensures that the policy behaves according to user expectations.

Finally, a single policy file can contain multiple policies:

.. code-block:: console

    {
        "example_1": {
            "preset": {
                "CERTIFICATE": {
                    "DESTROY": "DISALLOW_ALL",
                    ...
            }
        },
        "example_2": {
            "groups": {
                "group_A": {
                    "CERTIFICATE": {
                        "DESTROY": "ALLOW_ALL",
                    ...
                },
                "group_B": {
                    "CERTIFICATE": {
                        "DESTROY": "DISALLOW_ALL",
                        ...
                }
            }
        }
    }

The above snippet shows two policies, ``example_1`` and ``example_2``. Each
contains a different set of rules, one leveraging a ``preset`` collection and
the other using the ``groups`` collection. While defined in the same JSON
block, these policies are distinct from one another and are treated as
separate entities. All of the previously defined rules and conventions for
policies still apply.

.. _reserved-policies:

Reserved Operation Policies
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The PyKMIP server defines two reserved, built-in operation policies:
``default`` and ``public``. Both of these policies are defined in the KMIP
specification. Neither can be renamed or overridden by user-defined policies.
The ``default`` policy is used for newly created objects that are not assigned
a policy by their creators, though it can be used by creators intentionally.
The ``public`` policy is intended for use with template objects that are
public to the entire user-base of the server.

The following tables define the permissions for each of the built-in policies.

``default`` policy
******************

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
*****************

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

.. _objects:

Objects
-------
The following is a list of KMIP managed object types supported by the server.

Symmetric Keys
~~~~~~~~~~~~~~
A symmetric key is an encryption key that can be used to both encrypt plain
text data and decrypt cipher text.

Creating a symmetric key object would look like this:

.. code-block:: python

    >>> from kmip import enums
    >>> from kmip.pie.objects import SymmetricKey
    >>> key = SymmetricKey(
    ...     enums.CryptographicAlgorithm.AES,
    ...     128,
    ...     (
    ...         b'\x00\x01\x02\x03\x04\x05\x06\x07'
    ...         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
    ...     ),
    ...     [
    ...         enums.CryptographicUsageMask.ENCRYPT,
    ...         enums.CryptographicUsageMask.DECRYPT
    ...     ],
    ...     "Example Symmetric Key"
    ... )

Public Keys
~~~~~~~~~~~
A public key is a cryptographic key that contains the public components of an
asymmetric key pair. It is often used to decrypt data encrypted with, or to
verify signatures produced by, the corresponding private key.

Creating a public key object would look like this:

.. code-block:: python

    >>> from kmip import enums
    >>> from kmip.pie.objects import PublicKey
    >>> key = PublicKey(
    ...     enums.CryptographicAlgorithm.RSA,
    ...     2048,
    ...     (
    ...         b'\x30\x82\x01\x0A\x02\x82\x01\x01...'
    ...     ),
    ...     enums.KeyFormatType.X_509,
    ...     [
    ...         enums.CryptographicUsageMask.VERIFY
    ...     ],
    ...     "Example Public Key"
    ... )

Private Keys
~~~~~~~~~~~~
A private key is a cryptographic key that contains the private components of
an asymmetric key pair. It is often used to encrypt data that may be decrypted
by, or generate signatures that may be verified by, the corresponding public
key.

Creating a private key object would look like this:

.. code-block:: python

    >>> from kmip import enums
    >>> from kmip.pie.objects import PrivateKey
    >>> key = PrivateKey(
    ...     enums.CryptographicAlgorithm.RSA,
    ...     2048,
    ...     (
    ...         b'\x30\x82\x04\xA5\x02\x01\x00\x02...'
    ...     ),
    ...     enums.KeyFormatType.PKCS_8,
    ...     [
    ...         enums.CryptographicUsageMask.SIGN
    ...     ],
    ...     "Example Private Key"
    ... )

Split Keys
~~~~~~~~~~
A split key is a secret value representing a key composed of multiple parts.
The parts of the key can be recombined cryptographically to reconstitute the
original key.

Creating a split key object would look like this:

.. code-block:: python

    >>> from kmip import enums
    >>> from kmip.pie.objects import SplitKey
    >>> key = SplitKey(
    ...     cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
    ...     cryptographic_length=128,
    ...     key_value=b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF',
    ...     name="Split Key",
    ...     split_key_parts=3,
    ...     key_part_identifier=1,
    ...     split_key_threshold=3,
    ...     split_key_method=enums.SplitKeyMethod.XOR
    ... )

Certificates
~~~~~~~~~~~~
A certificate is a cryptographic object that contains a public key along with
additional identifying information. It is often used to secure communication
channels or to verify data signatures produced by the corresponding private
key.

Creating a certificate object would look like this:

.. code-block:: python

    >>> from kmip import enums
    >>> from kmip.pie.objects import X509Certificate
    >>> cert = X509Certificate(
    ...     (
    ...         b'\x30\x82\x03\x12\x30\x82\x01\xFA...'
    ...     ),
    ...     [
    ...         enums.CryptographicUsageMask.VERIFY
    ...     ],
    ...     "Example X.509 Certificate"
    ... )

Secret Data
~~~~~~~~~~~
A secret data object is a cryptographic object that represents a shared secret
value that is not a key or certificate (e.g., a password or passphrase).

Creating a secret data object would look like this:

.. code-block:: python

    >>> from kmip import enums
    >>> from kmip.pie.objects import SecretData
    >>> data = SecretData(
    ...     (
    ...         b'\x53\x65\x63\x72\x65\x74\x50\x61'
    ...         b'\x73\x73\x77\x6F\x72\x64'
    ...     ),
    ...     enums.SecretDataType.PASSWORD,
    ...     [
    ...         enums.CryptographicUsageMask.DERIVE_KEY
    ...     ],
    ...     "Example Secret Data Object"
    ... )

Opaque Objects
~~~~~~~~~~~~~~
An opaque data object is a binary blob that the server is unable to interpret
into another well-defined object type. It can be used to store any arbitrary
data.

Creating an opaque object would look like this:

.. code-block:: python

    >>> from kmip import enums
    >>> from kmip.pie.objects import OpaqueObject
    >>> oo = OpaqueObject(
    ...     (
    ...         b'\x53\x65\x63\x72\x65\x74\x50\x61'
    ...         b'\x73\x73\x77\x6F\x72\x64'
    ...     ),
    ...     enums.OpaqueDataType.NONE,
    ...     "Example Opaque Object"
    ... )

Operations
----------
The following is a list of KMIP operations supported by the server. All
supported cryptographic functions are currently implemented using the
`pyca/cryptography`_ library, which in turn leverages `OpenSSL`_. If the
underlying backend does not support a specific feature, algorithm, or
operation, the PyKMIP server will not be able to support it either.

If you are interested in adding a new cryptographic backend to the PyKMIP
server, see :doc:`Development <development>` for more information.

Activate
~~~~~~~~
The Activate operation updates the state of a managed object, allowing it to
be used for cryptographic operations. Specifically, the object transitions
from the pre-active state to the active state (see :term:`state`).

Errors may be generated during the activation of a managed object. These
may occur in the following cases:

* the managed object is not activatable (e.g., opaque data object)
* the managed object is not in the pre-active state

Create
~~~~~~
The Create operation is used to create symmetric keys for a variety of
cryptographic algorithms.

==========  =======================
Algorithm          Key Sizes
==========  =======================
3DES        64, 128, 192
AES         128, 256, 192
Blowfish    128, 256, 384, and more
Camellia    128, 256, 192
CAST5       64, 96, 128, and more
IDEA        128
ARC4        128, 256, 192, and more
==========  =======================

All users are allowed to create symmetric keys. There are no quotas currently
enforced by the server.

Various KMIP-defined attributes are set when a symmetric key is created.
These include:

* :term:`cryptographic_algorithm`
* :term:`cryptographic_length`
* :term:`cryptographic_usage_mask`
* :term:`initial_date`
* :term:`key_format_type`
* :term:`name`
* :term:`object_type`
* :term:`operation_policy_name`
* :term:`state`
* :term:`unique_identifier`

Errors may be generated during the creation of a symmetric key. These may
occur in the following cases:

* the cryptographic algorithm, length, and/or usage mask are not provided
* an unsupported symmetric algorithm is requested
* an invalid cryptographic length is provided for a specific cryptographic
  algorithm

CreateKeyPair
~~~~~~~~~~~~~
The CreateKeyPair operation is used to create asymmetric key pairs.

==========  ===============
Algorithm   Key Sizes
==========  ===============
RSA         512, 1024, 2048
==========  ===============

All users are allowed to create asymmetric keys. There are no quotas currently
enforced by the server.

Various KMIP-defined attributes are set when an asymmetric key pair is
created. For both public and private keys, the following attributes are
identical:

* :term:`cryptographic_algorithm`
* :term:`cryptographic_length`
* :term:`initial_date`
* :term:`operation_policy_name`
* :term:`state`

Other attributes will differ between public and private keys. These include:

* :term:`cryptographic_usage_mask`
* :term:`key_format_type`
* :term:`name`
* :term:`object_type`
* :term:`unique_identifier`

Errors may be generated during the creation of an asymmetric key pair. These
may occur in the following cases:

* the cryptographic algorithm, length, and/or usage mask are not provided
* an unsupported asymmetric algorithm is requested
* an invalid cryptographic length is provided for a specific cryptographic
  algorithm

Decrypt
~~~~~~~
The Decrypt operations allows the client to decrypt data with an existing
managed object stored by the server. Both symmetric and asymmetric decryption
are supported. See :ref:`encrypt` above for information on supported algorithms
and the types of errors to expect from the server.

DeleteAttribute
~~~~~~~~~~~~~~~
The DeleteAttribute operation allows the client to delete an attribute from an
existing managed object.

Errors may be generated during the attribute deletion process. These may occur
in the following cases:

* the specified managed object does not exist
* the specified attribute may not be applicable to the specified managed object
* the specified attribute is not supported by the server
* the specified attribute cannot be deleted by the client
* the specified attribute could not be located for deletion on the specified managed object

DeriveKey
~~~~~~~~~
The DeriveKey operation is used to create a new symmetric key or secret data
object from an existing managed object stored on the server. The derivation
method and the desired length of the new cryptographic object must be
specified with the request. If the generated cryptographic object is longer
than the requested length, it will be truncated to match the request length.

Various KMIP-defined attributes are set when a new cryptographic object is
derived. These include:

* :term:`cryptographic_algorithm`
* :term:`cryptographic_length`
* :term:`cryptographic_usage_mask`
* :term:`initial_date`
* :term:`key_format_type`
* :term:`name`
* :term:`object_type`
* :term:`operation_policy_name`
* :term:`state`
* :term:`unique_identifier`

Errors may be generated during the key derivation process. These may occur
in the following cases:

* the base object is not accessible to the user
* the base object is not an object type usable for key derivation
* the base object does not have the DeriveKey bit set in its usage mask
* the cryptographic length is not provided with the request
* the requested cryptographic length is longer than the generated key

Destroy
~~~~~~~
The Destroy operation deletes a managed object from the server. Once destroyed,
the object can no longer be retrieved or used for cryptographic operations.
An object can only be destroyed if it is in the pre-active or deactivated
states.

Errors may be generated during the destruction of a managed object. These
may occur in the following cases:

* the managed object is not destroyable (e.g., the object does not exist)
* the managed object is in the active state

DiscoverVersions
~~~~~~~~~~~~~~~~
The DiscoverVersions operation allows the client to determine which versions
of the KMIP specification are supported by the server.

.. _encrypt:

Encrypt
~~~~~~~
The Encrypt operation allows the client to encrypt data with an existing
managed object stored by the server. Both symmetric and asymmetric encryption
are supported:

Symmetric Key Algorithms
************************
* `3DES`_
* `AES`_
* `Blowfish`_
* `Camellia`_
* `CAST5`_
* `IDEA`_
* `RC4`_

Asymmetric Key Algorithms
*************************
* `RSA`_

Errors may be generated during the encryption. These may occur in the
following cases:

* the encryption key is not accessible to the user
* the encryption key is not in the active state and must be activated
* the encryption key does not have the Encrypt bit set in its usage mask
* the requested encryption algorithm is not supported
* the specified encryption key is not compatible with the requested algorithm
* the requested encryption algorithm requires a block cipher mode
* the requested block cipher mode is not supported

.. _get:

Get
~~~
The Get attribute is used to retrieve a managed object stored on the server.
The :term:`unique_identifier` of the object is used to retrieve it.

It is possible to request that the managed object be cryptographically
wrapped before it is returned to the client. Right now only encryption-based
wrapping is supported.

Errors may be generated during the retrieval of a managed object. These
may occur in the following cases:

* the managed object is not accessible to the user
* a desired key format was specified that cannot be converted by the server
* key compression was specified and the server cannot compress objects
* the wrapping key specified is not accessible to the user
* the wrapping key is not applicable to key wrapping
* the wrapping key does not have the WrapKey bit set in its usage mask
* wrapped attributes were specified and the server cannot wrap attributes
* a wrapping encoding was specified and the server does not support it
* incomplete wrapping specifications were provided with the request

GetAttributes
~~~~~~~~~~~~~
The GetAttributes operation is used to retrieve specific attributes for a
specified managed object. Multiple attribute names can be specified in a
single request.

The following names should be used to access the corresponding attributes:

========================  ================================
Attribute Name            Attribute
========================  ================================
Cryptographic Algorithm   :term:`cryptographic_algorithm`
Cryptographic Length      :term:`cryptographic_length`
Cryptographic Usage Mask  :term:`cryptographic_usage_mask`
Initial Date              :term:`initial_date`
Object Type               :term:`object_type`
Operation Policy Name     :term:`operation_policy_name`
State                     :term:`state`
Unique Identifier         :term:`unique_identifier`
========================  ================================

GetAttributeList
~~~~~~~~~~~~~~~~
The GetAttributeList operation is used to identify the attributes currently
available for a specific managed object. Given the :term:`unique_identifier`
of a managed object, the server will return a list of attribute names for
attributes that can be accessed using the GetAttributes operation.

Locate
~~~~~~
The Locate operation is used to identify managed objects that the user has
access to, according to specific filtering criteria. Currently, the server
only support object filtering based on the object :term:`name` attribute.

If no filtering values are provided, the server will return a list of
:term:`unique_identifier` values corresponding to all of the managed objects
the user has access to.

MAC
~~~
The MAC operation allows the client to compute a message authentication code
on data using an existing managed object stored by the server. Both `HMAC`_
and `CMAC`_ algorithms are supported:

HMAC Hashing Algorithms
***********************
* `MD5`_
* `SHA1`_
* `SHA224`_
* `SHA256`_
* `SHA384`_
* `SHA512`_

CMAC Symmetric Algorithms
*************************
* `3DES`_
* `AES`_
* `Blowfish`_
* `Camellia`_
* `CAST5`_
* `IDEA`_
* `RC4`_

Errors may be generated during the authentication code creation process. These
may occur in the following cases:

* the managed object to use is not accessible to the user
* the managed object to use is not in the active state and must be activated
* the managed object does not have the Generate bit set in its usage mask
* the requested algorithm is not supported for HMAC/CMAC generation

ModifyAttribute
~~~~~~~~~~~~~~~
The ModifyAttribute operation allows the client to modify an existing attribute
on an existing managed object.

Errors may be generated during the attribute modification process. These may
occur in the following cases:

* the specified managed object does not exist
* the specified attribute may not be applicable to the specified managed object
* the specified attribute is not supported by the server
* the specified attribute cannot be modified by the client
* the specified attribute is not set on the specified managed object
* the specified attribute is multivalued and the current attribute field must be specified
* the specified attribute index does not correspond to an existing attribute

Query
~~~~~
The Query operation allows the client to determine what KMIP capabilities are
supported by the server. This set of information may include the following
types of information, depending upon which items the client requests:

* :term:`operation`
* :term:`object_type`
* :term:`vendor_identification`
* :term:`server_information`
* :term:`application_namespace`
* :term:`extension_information`
* :term:`attestation_type`
* :term:`rng_parameters`
* :term:`profile_information`
* :term:`validation_information`
* :term:`capability_information`
* :term:`client_registration_method`

The PyKMIP server currently only includes the supported operations and the
server information in Query responses.

Register
~~~~~~~~
The Register operation is used to store an existing KMIP object with the
server. For examples of the objects that can be stored, see :ref:`objects`.

All users are allowed to register objects. There are no quotas currently
enforced by the server.

Various KMIP-defined attributes may be set when an object is registered.
These may include:

* :term:`cryptographic_algorithm`
* :term:`cryptographic_length`
* :term:`cryptographic_usage_mask`
* :term:`initial_date`
* :term:`key_format_type`
* :term:`name`
* :term:`object_type`
* :term:`operation_policy_name`
* :term:`state`
* :term:`unique_identifier`

Revoke
~~~~~~
The Revoke operation updates the state of a managed object, effectively
deactivating but not destroying it. The client provides a specific
:term:`revocation_reason_code` indicating why revocation is occurring.

If revocation is due to a key or CA compromise, the managed object is moved
to the compromised state if it is in the pre-active, active, or deactivated
states. If the object has already been destroyed, it will be moved to the
destroyed compromised state. Otherwise, if revocation is due to any other
reason, the managed object is moved to the deactivated state if it is in
the active state.

Errors may be generated during the revocation of a managed object. These
may occur in the following cases:

* the managed object is not revokable (e.g., opaque data object)
* the managed object is not active when revoked for a non-compromise

SetAttribute
~~~~~~~~~~~~
The SetAttribute operation allows the client to set the value of an attribute
on an existing managed object.

Errors may be generated during the attribute setting process. These may occur
in the following cases:

* the specified managed object does not exist
* the specified attribute may not be applicable to the specified managed object
* the specified attribute is not supported by the server
* the specified attribute cannot be set by the client
* the specified attribute is multivalued and cannot be set with this operation

.. _sign:

Sign
~~~~
The Sign operation allows the client to sign data with an existing private key
stored by the server. The following hashing algorithms are supported with
`RSA`_ for signing support.

Hashing Algorithms
******************
* `MD5`_
* `SHA1`_
* `SHA224`_
* `SHA256`_
* `SHA384`_
* `SHA512`_

Errors may be generated during the encryption. These may occur in the
following cases:

* the signing key is not accessible to the user
* the signing key is not a private key
* the signing key is not in the active state and must be activated
* the signing key does not have the Sign bit set in its usage mask
* the requested signing algorithm is not supported
* the signing key is not compatible with the requested signing algorithm
* a padding method is required for the algorithm and was not specified

SignatureVerify
~~~~~~~~~~~~~~~
The SignatureVerify operation allows the client to verify a data signature
with an existing public key stored by the server. See :ref:`sign` above for
information on supported algorithms and the types of errors to expect from
the server.

.. _`ssl`: https://docs.python.org/dev/library/ssl.html#socket-creation
.. _`SQLAlchemy`: https://www.sqlalchemy.org/
.. _`SQLite`: http://docs.sqlalchemy.org/en/latest/dialects/sqlite.html
.. _`pyca/cryptography`: https://cryptography.io/en/latest/
.. _`OpenSSL`: https://www.openssl.org/
.. _`3DES`: https://en.wikipedia.org/wiki/Triple_DES
.. _`AES`: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
.. _`Blowfish`: https://en.wikipedia.org/wiki/Blowfish_%28cipher%29
.. _`Camellia`: https://en.wikipedia.org/wiki/Camellia_%28cipher%29
.. _`CAST5`: https://en.wikipedia.org/wiki/CAST-128
.. _`IDEA`: https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm
.. _`RC4`: https://en.wikipedia.org/wiki/RC4
.. _`RSA`: https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29
.. _`MD5`: https://en.wikipedia.org/wiki/MD5
.. _`SHA1`: https://en.wikipedia.org/wiki/SHA-1
.. _`SHA224`: https://en.wikipedia.org/wiki/SHA-2
.. _`SHA256`: https://en.wikipedia.org/wiki/SHA-2
.. _`SHA384`: https://en.wikipedia.org/wiki/SHA-2
.. _`SHA512`: https://en.wikipedia.org/wiki/SHA-2
.. _`HMAC`: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
.. _`CMAC`: https://en.wikipedia.org/wiki/One-key_MAC
.. _`RFC 5280`: https://www.ietf.org/rfc/rfc5280.txt
.. _`SLUGS`: https://github.com/OpenKMIP/SLUGS
