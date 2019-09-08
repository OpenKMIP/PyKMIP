Client
======
The PyKMIP client allows developers to connect to a KMIP-compliant key
management server and conduct key management operations.

Configuration
-------------
The client settings can be managed by a configuration file, by default
located at ``/etc/pykmip/pykmip.conf``. An example client configuration
settings block, as found in the configuration file, is shown below:

.. code-block:: console

    [client]
    host=127.0.0.1
    port=5696
    certfile=/path/to/certificate/file
    keyfile=/path/to/certificate/key/file
    ca_certs=/path/to/ca/certificate/file
    cert_reqs=CERT_REQUIRED
    ssl_version=PROTOCOL_SSLv23
    do_handshake_on_connect=True
    suppress_ragged_eofs=True
    username=example_username
    password=example_password

The configuration file can contain multiple settings blocks. Only one,
``[client]``, is shown above. You can swap between different settings
blocks by simply providing the name of the block as the ``config``
parameter (see below).

The different configuration options are defined below:

* ``host``
    A string representing either a hostname in Internet domain notation or an
    IPv4 address.
* ``port``
    An integer representing a port number. Recommended to be ``5696``
    according to the KMIP specification.
* ``certfile``
    A string representing a path to a PEM-encoded client certificate file. For
    more information, see the `ssl`_ documentation.
* ``keyfile``
    A string representing a path to a PEM-encoded client certificate key file.
    The private key contained in the file must correspond to the certificate
    pointed to by ``certfile``. For more information, see the `ssl`_
    documentation.
* ``ca_certs``
    A string representing a path to a PEM-encoded certificate authority
    certificate file. This certificate will be used to verify the server's
    certificate when establishing a TLS connection. For more information, see
    the `ssl`_ documentation.
* ``cert_reqs``
    A flag indicating the enforcement level to use when validating the
    certificate received from the server. Options include: ``CERT_NONE``,
    ``CERT_OPTIONAL``, and ``CERT_REQUIRED``. ``CERT_REQUIRED`` is the most
    secure option and should be used at all times. The other options can be
    helpful when debugging TLS connections. For more information, see the
    `ssl`_ documentation.
* ``ssl_version``
    A flag indicating the SSL/TLS version to use when establishing a TLS
    connection with a server. Options are derived from the `ssl`_ module.
    The recommended value is ``PROTOCOL_SSLv23`` or ``PROTOCOL_TLS``, which
    automatically allows the client to pick the most secure option provided
    by the server. For more information, see the `ssl`_ documentation.
* ``do_handshake_on_connect``
    A boolean flag indicating when the client should perform the TLS handshake
    when establishing the TLS connection. The recommended value is ``True``.
    For more information, see the `ssl`_ documentation.

    .. note::
       This configuration option is deprecated and will be removed in a future
       version of PyKMIP.
* ``suppress_ragged_eofs``
    A boolean flag indicating how the client should handle unexpected EOF from
    the TLS connection. The recommended value is ``True``. For more
    information, see the `ssl`_ documentation.

    .. note::
       This configuration option is deprecated and will be removed in a future
       version of PyKMIP.
* ``username``
    A string representing the username to use for KMIP requests. Optional
    depending on server access policies. Leave blank if not needed.
* ``password``
    A string representing the password to use for KMIP requests. Optional
    depending on server access policies. Leave blank if not needed.

The client can also be configured manually via Python. The following example
shows how to create the ``ProxyKmipClient`` in Python code, directly
specifying the different configuration values:

.. code-block:: python

    >>> import ssl
    >>> from kmip.pie.client import ProxyKmipClient, enums
    >>> client = ProxyKmipClient(
    ...     hostname='127.0.0.1',
    ...     port=5696,
    ...     cert='/path/to/certificate/file',
    ...     key='/path/to/certificate/key/file',
    ...     ca='/path/to/ca/certificate/file',
    ...     ssl_version=ssl.PROTOCOL_SSLv23,
    ...     username='example_username',
    ...     password='example_password',
    ...     config='client',
    ...     config_file='/etc/pykmip/pykmip.conf',
    ...     kmip_version=enums.KMIPVersion.KMIP_1_2
    ... )

Settings specified at runtime, as in the above example, will take precedence
over the default values found in the configuration file.

Usage
-----

The following class documentation provides numerous examples detailing how to
use the client. For additional examples, demo scripts for different operations
are available in the ``kmip/demos/pie`` directory.

Class Documentation
-------------------
.. py:module:: kmip.pie.client

.. py:class:: ProxyKmipClient(hostname=None, port=None, cert=None, key=None, ca=None, ssl_version=None, username=None, password=None, config='client', config_file=None, kmip_version=None)

    A simplified KMIP client for conducting KMIP operations.

    The ProxyKmipClient is a simpler KMIP client supporting various KMIP
    operations. It wraps the original KMIPProxy, reducing the boilerplate
    needed to deploy PyKMIP in client applications. The underlying proxy
    client is responsible for setting up the underlying socket connection
    and for writing/reading data to/from the socket.

    Like the KMIPProxy, the ProxyKmipClient is not thread-safe.

    :param string hostname: The host or IP address of a KMIP appliance.
        Optional, defaults to None.
    :param int port: The port number used to establish a connection to a
        KMIP appliance. Usually 5696 for KMIP applications. Optional,
        defaults to None.
    :param string cert: The path to the client's certificate. Optional,
        defaults to None.
    :param string key: The path to the key for the client's certificate.
        Optional, defaults to None.
    :param string ca: The path to the CA certificate used to verify the
        server's certificate. Optional, defaults to None.
    :param string ssl_version: The name of the ssl version to use for the
        connection. Example: 'PROTOCOL_SSLv23'. Optional, defaults to None.
    :param string username: The username of the KMIP appliance account to
        use for operations. Optional, defaults to None.
    :param string password: The password of the KMIP appliance account to
        use for operations. Optional, defaults to None.
    :param string config: The name of a section in the PyKMIP configuration
        file. Use to load a specific set of configuration settings from the
        configuration file, instead of specifying them manually. Optional,
        defaults to the default client section, 'client'.
    :param string config_file: The path to the PyKMIP client configuration
        file. Optional, defaults to None.
    :param enum kmip_version: A KMIPVersion enumeration specifying which KMIP
        version should be used to encode/decode request/response messages.
        Optional, defaults to None. If no value is specified, at request
        encoding time the client will default to KMIP 1.2.

    .. py:attribute:: kmip_version

        The KMIP version that should be used to encode/decode request/response
        messages. Must be a KMIPVersion enumeration. Can be accessed and
        modified at any time.

    .. py:method:: open()

        Open the client connection.

        :raises kmip.pie.exceptions.ClientConnectionFailure: This is raised if
            the client connection is already open.
        :raises Exception: This is raised if an error occurs while trying to
            open the connection.

    .. py:method:: close()

        Close the client connection.

        :raises Exception: This is raised if an error occurs while trying to
            close the connection.

    .. py:method:: create(algorithm, length, operation_policy_name=None, name=None, cryptographic_usage_mask=None)

        Create a symmetric key on a KMIP appliance.

        :param algorithm: A :class:`kmip.core.enums.CryptographicAlgorithm`
            enumeration defining the algorithm to use to generate the symmetric
            key. See :term:`cryptographic_algorithm` for more information.
        :param int length: The length in bits for the symmetric key.
        :param string operation_policy_name: The name of the operation policy
            to use for the new symmetric key. Optional, defaults to None
        :param string name: The name to give the key. Optional, defaults to
            None.
        :param list cryptographic_usage_mask: A list of
            :class:`kmip.core.enums.CryptographicUsageMask` enumerations
            defining how the created key should be used. Optional, defaults to
            None. See :term:`cryptographic_usage_mask` for more information.

        :return: The string uid of the newly created symmetric key.

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure.
        :raises TypeError: This is raised if the input arguments are invalid.

        Creating an 256-bit AES key used for encryption and decryption would
        look like this:

        .. code-block:: python

            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> with c:
            ...     key_id = c.create(
            ...         enums.CryptographicAlgorithm.AES,
            ...         256,
            ...         operation_policy_name='default',
            ...         name='Test_256_AES_Symmetric_Key',
            ...         cryptographic_usage_mask=[
            ...             enums.CryptographicUsageMask.ENCRYPT,
            ...             enums.CryptographicUsageMask.DECRYPT
            ...         ]
            ...     )
            '449'

    .. py:method:: create_key_pair(algorithm, length, operation_policy_name=None, public_name=None, public_usage_mask=None, private_name=None, private_usage_mask=None)

        Create an asymmetric key pair on a KMIP appliance.

        :param algorithm: A :class:`kmip.core.enums.CryptographicAlgorithm`
            enumeration defining the algorithm to use to generate the key pair.
            See :term:`cryptographic_algorithm` for more information.
        :param int length: The length in bits for the key pair.
        :param string operation_policy_name: The name of the operation policy
            to use for the new key pair. Optional, defaults to None.
        :param string public_name: The name to give the public key. Optional,
            defaults to None.
        :param list public_usage_mask: A list of
            :class:`kmip.core.enums.CryptographicUsageMask` enumerations
            indicating how the public key should be used. Optional, defaults to
            None. See :term:`cryptographic_usage_mask` for more information.
        :param string private_name: The name to give the public key. Optional,
            defaults to None.
        :param list private_usage_mask: A list of
            :class:`kmip.core.enums.CryptographicUsageMask` enumerations
            indicating how the private key should be used. Optional, defaults
            to None. See :term:`cryptographic_usage_mask` for more information.

        :return: The string uid of the newly created public key.
        :return: The string uid of the newly created private key.

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure
        :raises TypeError: This is raised if the input arguments are invalid.

        Creating an 2048-bit RSA key pair to be used for signing and signature
        verification would look like this:

        .. code-block:: python

            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> with c:
            ...     key_id = c.create_key_pair(
            ...         enums.CryptographicAlgorithm.RSA,
            ...         2048,
            ...         operation_policy_name='default',
            ...         public_name='Test_2048_RSA_Public_Key',
            ...         public_usage_mask=[
            ...             enums.CryptographicUsageMask.VERIFY
            ...         ],
            ...         private_name='Test_2048_RSA_Private_Key',
            ...         private_usage_mask=[
            ...             enums.CryptographicUsageMask.SIGN
            ...         ]
            ...     )
            ('450', '451')

    .. py:method:: register(managed_object)

        Register a managed object with a KMIP appliance.

        :param managed_object: A :class:`kmip.pie.objects.ManagedObject`
            instance to register with the server.

        :return: The string uid of the newly registered managed object.

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure.
        :raises TypeError: This is raised if the input argument is invalid.

        Registering an existing 128-bit AES symmetric key would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> symmetric_key = objects.SymmetricKey(
            ...     enums.CryptographicAlgorithm.AES,
            ...     128,
            ...     (
            ...         b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ...         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ...     )
            ... )
            >>> with c:
            ...     c.register(symmetric_key)
            ...
            '452'

    .. py:method:: derive_key(object_type, unique_identifiers, derivation_method, derivation_parameters, **kwargs)

        Derive a new key or secret data from existing managed objects.

        :param object_type: A :class:`kmip.core.enums.ObjectType` enumeration
            specifying what type of object to derive. Only SymmetricKeys and
            SecretData can be specified. Required. See :term:`object_type` for
            more information.
        :param list unique_identifiers: A list of strings specifying the
            unique IDs of the existing managed objects to use for derivation.
            Multiple objects can be specified to fit the requirements of the
            given derivation method. Required.
        :param derivation_method: A :class:`kmip.core.enums.DerivationMethod`
            enumeration specifying how key derivation should be done. Required.
            See :term:`derivation_method` for more information.
        :param dict `derivation_parameters`: A dictionary containing various
            settings for the key derivation process. Required. See
            :term:`derivation_parameters` for more information.
        :param `**kwargs`: A placeholder for object attributes that should be set
            on the newly derived object. See the examples below for more
            information.

        :return: The unique string ID of the newly derived object.

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure.
        :raises TypeError: This is raised if the input arguments are invalid.

        Deriving a new key using PBKDF2 would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> secret_data = objects.SecretData(
            ...     b'password',
            ...     enums.SecretDataType.PASSWORD,
            ...     masks=[
            ...         enums.CryptographicUsageMask.DERIVE_KEY
            ...     ]
            ... )
            >>> with c:
            ...     password_id = c.register(secret_data)
            ...     c.activate(password_id)
            ...     c.derive_key(
            ...         enums.ObjectType.SYMMETRIC_KEY,
            ...         [password_id],
            ...         enums.DerivationMethod.PBKDF2,
            ...         {
            ...             'cryptographic_parameters': {
            ...                 'hashing_algorithm':
            ...                     enums.HashingAlgorithm.SHA_1
            ...             },
            ...             'salt': b'salt',
            ...             'iteration_count': 4096
            ...         },
            ...         cryptographic_length=128,
            ...         cryptographic_algorithm=enums.CryptographicAlgorithm.AES
            ...     )
            ...
            '454'

        Deriving a new secret using encryption would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> key = objects.SymmetricKey(
            ...     enums.CryptographicAlgorithm.BLOWFISH,
            ...     128,
            ...     (
            ...         b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
            ...         b'\xF0\xE1\xD2\xC3\xB4\xA5\x96\x87'
            ...     ),
            ...     masks=[
            ...         enums.CryptographicUsageMask.DERIVE_KEY
            ...     ]
            ... )
            >>> with c:
            ...     key_id = c.register(key)
            ...     c.activate(key_id)
            ...     c.derive_key(
            ...         enums.ObjectType.SECRET_DATA,
            ...         [key_id],
            ...         enums.DerivationMethod.ENCRYPT,
            ...         {
            ...             'cryptographic_parameters': {
            ...                 'block_cipher_mode': enums.BlockCipherMode.CBC,
            ...                 'padding_method': enums.PaddingMethod.PKCS5,
            ...                 'cryptographic_algorithm':
            ...                     enums.CryptographicAlgorithm.BLOWFISH
            ...             },
            ...             'initialization_vector': (
            ...                 b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'
            ...             ),
            ...             'derivation_data': (
            ...                 b'\x37\x36\x35\x34\x33\x32\x31\x20'
            ...                 b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
            ...                 b'\x68\x65\x20\x74\x69\x6D\x65\x20'
            ...                 b'\x66\x6F\x72\x20\x00'
            ...             )
            ...         },
            ...         cryptographic_length=256
            ...     )
            ...
            '456'

        Deriving a new key using NIST 800 108-C would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> key = objects.SymmetricKey(
            ...     enums.CryptographicAlgorithm.AES,
            ...     512,
            ...     (
            ...         b'\xdd\x5d\xbd\x45\x59\x3e\xe2\xac'
            ...         b'\x13\x97\x48\xe7\x64\x5b\x45\x0f'
            ...         b'\x22\x3d\x2f\xf2\x97\xb7\x3f\xd7'
            ...         b'\x1c\xbc\xeb\xe7\x1d\x41\x65\x3c'
            ...         b'\x95\x0b\x88\x50\x0d\xe5\x32\x2d'
            ...         b'\x99\xef\x18\xdf\xdd\x30\x42\x82'
            ...         b'\x94\xc4\xb3\x09\x4f\x4c\x95\x43'
            ...         b'\x34\xe5\x93\xbd\x98\x2e\xc6\x14'
            ...     ),
            ...     masks=[
            ...         enums.CryptographicUsageMask.DERIVE_KEY
            ...     ]
            ... )
            >>> with c:
            ...     key_id = c.register(key)
            ...     c.activate(key_id)
            ...     c.derive_key(
            ...         enums.ObjectType.SYMMETRIC_KEY,
            ...         [key_id],
            ...         enums.DerivationMethod.NIST800_108_C,
            ...         {
            ...             'cryptographic_parameters': {
            ...                 'hashing_algorithm':
            ...                     enums.HashingAlgorithm.SHA_512
            ...             },
            ...             'derivation_data': (
            ...                 b'\xb5\x0b\x0c\x96\x3c\x6b\x30\x34'
            ...                 b'\xb8\xcf\x19\xcd\x3f\x5c\x4e\xbe'
            ...                 b'\x4f\x49\x85\xaf\x0c\x03\xe5\x75'
            ...                 b'\xdb\x62\xe6\xfd\xf1\xec\xfe\x4f'
            ...                 b'\x28\xb9\x5d\x7c\xe1\x6d\xf8\x58'
            ...                 b'\x43\x24\x6e\x15\x57\xce\x95\xbb'
            ...                 b'\x26\xcc\x9a\x21\x97\x4b\xbd\x2e'
            ...                 b'\xb6\x9e\x83\x55'
            ...             )
            ...         },
            ...         cryptographic_length=128,
            ...         cryptographic_algorithm=enums.CryptographicAlgorithm.AES
            ...     )
            ...
            '458'

        Deriving a new secret using HMAC would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> secret = objects.SecretData(
            ...     (
            ...         b'\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
            ...         b'\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
            ...         b'\x0c\x0c\x0c\x0c\x0c\x0c'
            ...     ),
            ...     enums.SecretDataType.SEED,
            ...     masks=[
            ...         enums.CryptographicUsageMask.DERIVE_KEY
            ...     ]
            ... )
            >>> with c:
            ...     secret_id = c.register(secret)
            ...     c.activate(secret_id)
            ...     c.derive_key(
            ...         enums.ObjectType.SECRET_DATA,
            ...         [secret_id],
            ...         enums.DerivationMethod.HMAC,
            ...         {
            ...             'cryptographic_parameters': {
            ...                 'hashing_algorithm':
            ...                     enums.HashingAlgorithm.SHA_1
            ...             },
            ...             'derivation_data': b'',
            ...             'salt': b''
            ...         },
            ...         cryptographic_length=336
            ...     )
            ...
            '460'

    .. py:method:: locate(maximum_items=None, storage_status_mask=None, object_group_member=None, attributes=None)

        Documentation coming soon.

    .. py:method:: get(uid=None, key_wrapping_specification=None)

        Get a managed object from a KMIP appliance.

        :param string uid: The unique ID of the managed object to retrieve.
        :param dict key_wrapping_specification: A dictionary containing the
            settings to use to wrap the object before retrieval. Optional,
            defaults to None. See :term:`key_wrapping_specification` for
            more information.

        :return: An :class:`kmip.pie.objects.ManagedObject` instance.

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure.
        :raises TypeError: This is raised if the input argument is invalid.

        Getting a symmetric key would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> symmetric_key = objects.SymmetricKey(
            ...     enums.CryptographicAlgorithm.AES,
            ...     128,
            ...     (
            ...         b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ...         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ...     )
            ... )
            >>> with c:
            ...     key_id = c.register(symmetric_key)
            ...     c.get(key_id)
            SymmetricKey(...)

        Getting a wrapped symmetric key would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> symmetric_key = objects.SymmetricKey(
            ...     enums.CryptographicAlgorithm.AES,
            ...     128,
            ...     (
            ...         b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ...         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ...     )
            ... )
            >>> wrapping_key = objects.SymmetricKey(
            ...     enums.CryptographicAlgorithm.AES,
            ...     128,
            ...     (
            ...         b'\x00\x11\x22\x33\x44\x55\x66\x77'
            ...         b'\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
            ...     ),
            ...     [
            ...         enums.CryptographicUsageMask.WRAP_KEY
            ...     ]
            ... )
            >>> with c:
            ...     key_id = c.register(symmetric_key)
            ...     wrapping_key_id = c.register(wrapping_key)
            ...     c.activate(wrapping_key_id)
            ...     c.get(
            ...         key_id,
            ...         key_wrapping_specification={
            ...             'wrapping_method': enums.WrappingMethod.ENCRYPT,
            ...             'encryption_key_information': {
            ...                 'unique_identifier': wrapping_key_id,
            ...                 'cryptographic_parameters': {
            ...                     'block_cipher_mode':
            ...                         enums.BlockCipherMode.NIST_KEY_WRAP
            ...                 }
            ...             },
            ...             'encoding_option': enums.EncodingOption.NO_ENCODING
            ...         }
            ...     )
            SymmetricKey(...)

    .. py:method:: get_attributes(uid=None, attribute_names=None)

        Get the attributes associated with a managed object.

        If the uid is not specified, the appliance will use the ID placeholder
        by default.

        If the attribute_names list is not specified, the appliance will
        return all viable attributes for the managed object.

        :param string uid: The unique ID of the managed object with which the
            retrieved attributes should be associated. Optional, defaults to
            None.
        :param list attribute_names: A list of string attribute names
            indicating which attributes should be retrieved. Optional, defaults
            to None.

        :return: The string ID of the object the attributes belong to.
        :return: A list of :class:`kmip.core.objects.Attribute` instances.

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure.
        :raises TypeError: This is raised if the input argument is invalid.

        Retrieving all of the attributes for a managed object would look like
        this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> symmetric_key = objects.SymmetricKey(
            ...     enums.CryptographicAlgorithm.AES,
            ...     128,
            ...     (
            ...         b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ...         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ...     )
            ... )
            >>> with c:
            ...     key_id = c.register(symmetric_key)
            ...     c.get_attributes(key_id)
            ('458', [Attribute(...), Attribute(...), ...])

        Retrieving only a specific attribute for a managed object would look
        like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> symmetric_key = objects.SymmetricKey(
            ...     enums.CryptographicAlgorithm.AES,
            ...     128,
            ...     (
            ...         b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ...         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ...     )
            ... )
            >>> with c:
            ...     key_id = c.register(symmetric_key)
            ...     c.get_attributes(key_id, ['Cryptographic Length'])
            ...
            (
                '458',
                [
                    Attribute(
                        attribute_name=AttributeName(value='Cryptographic Length'),
                        attribute_index=None,
                        attribute_value=CryptographicLength(value=128)
                    )
                ]
            )

    .. py:method:: get_attribute_list(uid=None)

        Get the names of the attributes associated with a managed object.

        If the uid is not specified, the appliance will use the ID placeholder
        by default.

        :param string uid: The unique ID of the managed object with which the
            retrieved attribute names should be associated. Optional, defaults
            to None.

        Retrieving the list of attribute names for a symmetric key would look
        like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> symmetric_key = objects.SymmetricKey(
            ...     enums.CryptographicAlgorithm.AES,
            ...     128,
            ...     (
            ...         b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ...         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ...     )
            ... )
            >>> with c:
            ...     key_id = c.register(symmetric_key)
            ...     c.get_attribute_list(key_id)
            ...
            [
                'Cryptographic Algorithm',
                'Cryptographic Length',
                'Cryptographic Usage Mask',
                'Initial Date',
                'Object Type',
                'Operation Policy Name',
                'State',
                'Unique Identifier'
            ]

    .. py:method:: activate(uid=None)

        Activate a managed object stored by a KMIP appliance.

        :param string uid: The unique ID of the managed object to activate.
            Optional, defaults to None.

        :return: None

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure.
        :raises TypeError: This is raised if the input argument is invalid.

        Activating a symmetric key would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> symmetric_key = objects.SymmetricKey(
            ...     enums.CryptographicAlgorithm.AES,
            ...     128,
            ...     (
            ...         b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ...         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ...     )
            ... )
            >>> with c:
            ...     key_id = c.register(symmetric_key)
            ...     c.activate(key_id)

    .. py:method:: revoke(revocation_reason, uid=None, revocation_message=None, compromise_occurrence_date=None)

        Revoke a managed object stored by a KMIP appliance.

        Activated objects must be revoked before they can be destroyed.

        :param revocation_reason: A
            :class:`kmip.core.enums.RevocationReasonCode` enumeration
            indicating the revocation reason. See
            :term:`revocation_reason_code` for more information.
        :param string uid: The unique ID of the managed object to revoke.
            Optional, defaults to None.
        :param string revocation_message: A message regarding the revocation.
            Optional, defaults to None.
        :param int compromise_occurrence_date: An integer, the number of
            seconds since the epoch, which will be converted to the Datetime
            when the managed object was first believed to be compromised.
            Optional, defaults to None.

        :return: None

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure.
        :raises TypeError: This is raised if the input argument is invalid.

        Revoking an activated symmetric key would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> symmetric_key = objects.SymmetricKey(
            ...     enums.CryptographicAlgorithm.AES,
            ...     128,
            ...     (
            ...         b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ...         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ...     )
            ... )
            >>> with c:
            ...     key_id = c.register(symmetric_key)
            ...     c.activate(key_id)
            ...     c.revoke(
            ...         enums.RevocationReasonCode.CESSATION_OF_OPERATION,
            ...         key_id
            ...     )

    .. py:method:: destroy(uid=None)

        Destroy a managed object stored by a KMIP appliance.

        :param string uid: The unique ID of the managed object to destroy.

        :return: None

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure.
        :raises TypeError: This is raised if the input argument is invalid.

        Destroying a symmetric key would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> symmetric_key = objects.SymmetricKey(
            ...     enums.CryptographicAlgorithm.AES,
            ...     128,
            ...     (
            ...         b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ...         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            ...     )
            ... )
            >>> with c:
            ...     key_id = c.register(symmetric_key)
            ...     c.destroy(key_id)

    .. py:method:: encrypt(data, uid=None, cryptographic_parameters=None, iv_counter_nonce=None)

        Encrypt data using the specified encryption key and parameters.

        :param bytes data: The bytes to encrypt. Required.
        :param string uid: The unique ID of the encryption key to use.
            Optional, defaults to None.
        :param dict cryptographic_parameters: A dictionary containing various
            cryptographic settings to be used for the encryption. Optional,
            defaults to None. See :term:`cryptographic_parameters` for more
            information.
        :param bytes iv_counter_nonce: The bytes to use for the IV/counter/
            nonce, if needed by the encryption algorithm and/or cipher mode.
            Optional, defaults to None.

        :return: The encrypted data bytes.
        :return: The IV/counter/nonce bytes used with the encryption algorithm,
            only if it was autogenerated by the server.

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure.
        :raises TypeError: This is raised if the input argument is invalid.

        Encrypting plain text with a symmetric key would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> with c:
            ...     key_id = c.create(
            ...         enums.CryptographicAlgorithm.AES,
            ...         256,
            ...         cryptographic_usage_mask=[
            ...             enums.CryptographicUsageMask.ENCRYPT,
            ...             enums.CryptographicUsageMask.DECRYPT
            ...         ]
            ...     )
            ...     c.activate(key_id)
            ...     c.encrypt(
            ...         b'This is a secret message.',
            ...         uid=key_id,
            ...         cryptographic_parameters={
            ...             'cryptographic_algorithm':
            ...                 enums.CryptographicAlgorithm.AES,
            ...             'block_cipher_mode': enums.BlockCipherMode.CBC,
            ...             'padding_method': enums.PaddingMethod.PKCS5
            ...         },
            ...         iv_counter_nonce=(
            ...             b'\x85\x1e\x87\x64\x77\x6e\x67\x96'
            ...             b'\xaa\xb7\x22\xdb\xb6\x44\xac\xe8'
            ...         )
            ...     )
            ...
            (b'...', None)

    .. py:method:: decrypt(data, uid=None, cryptographic_parameters=None, iv_counter_nonce=None)

        Decrypt data using the specified decryption key and parameters.

        :param bytes data: The bytes to decrypt. Required.
        :param string uid: The unique ID of the decryption key to use.
            Optional, defaults to None.
        :param dict cryptographic_parameters: A dictionary containing various
            cryptographic settings to be used for the decryption. Optional,
            defaults to None. See :term:`cryptographic_parameters` for more
            information.
        :param bytes iv_counter_nonce: The bytes to use for the IV/counter/
            nonce, if needed by the decryption algorithm and/or cipher mode.
            Optional, defaults to None.

        :return: The decrypted data bytes.

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure.
        :raises TypeError: This is raised if the input argument is invalid.

        Decrypting cipher text with a symmetric key would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> with c:
            ...     key_id = c.create(
            ...         enums.CryptographicAlgorithm.AES,
            ...         256,
            ...         cryptographic_usage_mask=[
            ...             enums.CryptographicUsageMask.ENCRYPT,
            ...             enums.CryptographicUsageMask.DECRYPT
            ...         ]
            ...     )
            ...     c.activate(key_id)
            ...     c.decrypt(
            ...         (
            ...             b' \xb6:s0\x16\xea\t\x1b\x16\xed\xb2\x04-\xd6'
            ...             b'\xb6\\\xf3xJ\xfe\xa7[\x1eJ\x08I\xae\x14\xd2'
            ...             b\xdb\xe2'
            ...         ),
            ...         uid=key_id,
            ...         cryptographic_parameters={
            ...             'cryptographic_algorithm':
            ...                 enums.CryptographicAlgorithm.AES,
            ...             'block_cipher_mode': enums.BlockCipherMode.CBC,
            ...             'padding_method': enums.PaddingMethod.PKCS5
            ...         },
            ...         iv_counter_nonce=(
            ...             b'\x85\x1e\x87\x64\x77\x6e\x67\x96'
            ...             b'\xaa\xb7\x22\xdb\xb6\x44\xac\xe8'
            ...         )
            ...     )
            ...
            b'This is a secret message.'

    .. py:method:: sign(data, uid=None, cryptographic_parameters=None)

        Create a digital signature for data using the specified signing key.

        :param bytes data: The bytes of the data to be signed. Required.
        :param string uid: The unique ID of the signing key to use. Optional,
            defaults to None.
        :param dict cryptographic_parameters: A dictionary containing various
            cryptographic settings to be used for creating the signature (e.g.,
            cryptographic algorithm, hashing algorithm, and/or digital
            signature algorithm). Optional, defaults to None. See
            :term:`cryptographic_parameters` for more information.

        :return: Bytes representing the signature of the data.

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure.
        :raises TypeError: This is raised if the input argument is invalid.

        Signing data with a private key would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> with c:
            ...     public_key_id, private_key_id = c.create_key_pair(
            ...         enums.CryptographicAlgorithm.RSA,
            ...         2048,
            ...         public_usage_mask=[
            ...             enums.CryptographicUsageMask.VERIFY
            ...         ],
            ...         private_usage_mask=[
            ...             enums.CryptographicUsageMask.SIGN
            ...         ]
            ...     )
            ...     c.activate(public_key_id)
            ...     c.activate(private_key_id)
            ...     signature = c.sign(
            ...         b'This is a signed message.',
            ...         uid=private_key_id,
            ...         cryptographic_parameters={
            ...             'padding_method': enums.PaddingMethod.PSS,
            ...             'cryptographic_algorithm':
            ...                 enums.CryptographicAlgorithm.RSA,
            ...             'hashing_algorithm': enums.HashingAlgorithm.SHA_256
            ...         }
            ...     )
            ...
            >>> signature
            b'...'

    .. py:method:: signature_verify(message, signature, uid=None, cryptographic_parameters=None)

        Verify a message signature using the specified signing key.

        :param bytes message: The bytes of the signed message. Required.
        :param bytes signature: The bytes of the message signature. Required.
        :param string uid: The unique ID of the signing key to use. Optional,
            defaults to None.
        :param dict cryptographic_parameters: A dictionary containing various
            cryptographic settings to be used for signature verification (e.g.,
            cryptographic algorithm, hashing algorithm, and/or digital
            signature algorithm). Optional, defaults to None. See
            :term:`cryptographic_parameters` for more information.

        :return: A :class:`kmip.core.enums.ValidityIndicator` enumeration
            indicating whether or not the signature was valid.

        :raises kmip.pie.exceptions.ClientConnectionNotOpen: This is raised if
            the client connection is unusable.
        :raises kmip.pie.exceptions.KmipOperationFailure: This is raised if the
            operation result is a failure.
        :raises TypeError: This is raised if the input argument is invalid.

        Verifying a signature with a public key would look like this:

        .. code-block:: python

            >>> from kmip.pie import objects
            >>> from kmip.pie import client
            >>> from kmip import enums
            >>> c = client.ProxyKmipClient()
            >>> with c:
            ...     public_key_id, private_key_id = c.create_key_pair(
            ...         enums.CryptographicAlgorithm.RSA,
            ...         2048,
            ...         public_usage_mask=[
            ...             enums.CryptographicUsageMask.VERIFY
            ...         ],
            ...         private_usage_mask=[
            ...             enums.CryptographicUsageMask.SIGN
            ...         ]
            ...     )
            ...     c.activate(public_key_id)
            ...     c.activate(private_key_id)
            ...     c.signature_verify(
            ...         b'This is a signed message.',
            ...         b'...',
            ...         uid=public_key_id,
            ...         cryptographic_parameters={
            ...             'padding_method': enums.PaddingMethod.PSS,
            ...             'cryptographic_algorithm':
            ...                 enums.CryptographicAlgorithm.RSA,
            ...             'hashing_algorithm': enums.HashingAlgorithm.SHA_256
            ...         }
            ...     )
            ...
            <ValidityIndicator.VALID: 1>

    .. py:method:: mac(data, uid=None, algorithm=None)

        Documentation coming soon.


.. _`ssl`: https://docs.python.org/dev/library/ssl.html#socket-creation
