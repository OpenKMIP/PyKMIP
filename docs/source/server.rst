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
    ...     logging_level='DEBUG'
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

.. note::
   When installing PyKMIP and deploying the server, you must manually set up
   the server configuration file. It **will not** be placed in ``/etc/pykmip``
   automatically. See ``/examples`` in the PyKMIP repository for a boilerplate
   configuration file to get started.

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

Storage
-------
All data storage for the server is managed via `sqlalchemy`_. The current
backend leverages `SQLite`_, storing managed objects in a flat file located
at ``/tmp/pykmip.database``. If this file is deleted, the stored objects will
be gone for good. If this file is preserved across server restarts, object
access will be maintained.

.. note::
   Updates to the server data model will generate errors if the server is
   run with a ``pykmip.database`` file adhering to an older data model. There
   is no upgrade path.

Long term, the intent is to add support for more robust database and storage
backends available through ``sqlalchemy``. If you are interested in this work,
please see :doc:`Development <development>` for more information.

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

==========  ==========
Algorithm   Key Sizes
==========  ==========
RSA         1024, 2048
==========  ==========

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

Locate
~~~~~~
The Locate operation is used to identify managed objects that the user has
access to, according to specific filtering criteria. Currently, the server
only support object filtering based on the object :term:`name` attribute.

If no filtering values are provided, the server will return a list of
:term:`unique_identifier` values corresponding to all of the managed objects
the user has access to.

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

Activate
~~~~~~~~
The Activate operation updates the state of a managed object, allowing it to
be used for cryptographic operations. Specifically, the object transitions
from the pre-active state to the active state (see :term:`state`).

Errors may be generated during the activation of a managed object. These
may occur in the following cases:

* the managed object is not activatable (e.g., opaque data object)
* the managed object is not in the pre-active state

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

Decrypt
~~~~~~~
The Decrypt operations allows the client to decrypt data with an existing
managed object stored by the server. Both symmetric and asymmetric decryption
are supported. See :ref:`encrypt` above for information on supported algorithms
and the types of errors to expect from the server.

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

.. Miscellaneous
.. -------------
..
.. Object State
.. ~~~~~~~~~~~~
.. TBD
..
.. Object Operation Policy
.. ~~~~~~~~~~~~~~~~~~~~~~~
.. TBD
..
.. Object Ownership
.. ~~~~~~~~~~~~~~~~
.. TBD
..
.. Object Usage
.. ~~~~~~~~~~~~
.. TBD

.. _`ssl`: https://docs.python.org/dev/library/ssl.html#socket-creation
.. _`sqlalchemy`: https://www.sqlalchemy.org/
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
