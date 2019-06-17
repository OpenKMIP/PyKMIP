Glossary
========
.. glossary::
    :sorted:

    alternative_name_type
        (enum) (1.2) An enumeration specifying the type associated with an
        alternate name value. Used often as part of the alternative name
        attribute.

        >>> from kmip import enums
        >>> enums.AlternativeNameType.URI
        <AlternativeNameType.URI: 2>

        =========================  ==========  ============
        Name                       Value       KMIP Version
        =========================  ==========  ============
        UNINTERPRETED_TEXT_STRING  0x00000001  1.2
        URI                        0x00000002  1.2
        OBJECT_SERIAL_NUMBER       0x00000003  1.2
        EMAIL_ADDRESS              0x00000004  1.2
        DNS_NAME                   0x00000005  1.2
        X500_DISTINGUISHED_NAME    0x00000006  1.2
        IP_ADDRESS                 0x00000007  1.2
        =========================  ==========  ============

    application_namespace
        (str) (1.0) A string identifying a specific application namespace
        supported by the key management server. Often returned as part of
        the Query operation.

    attestation_type
        (enum) (1.2) An enumeration specifying the type of attestation
        measurement included in an attestation credential. Used during client
        identification credential processing.

        >>> from kmip import enums
        >>> enums.AttestationType.TPM_QUOTE
        <AttestationType.TPM_QUOTE: 1>

        ====================  ==========  ============
        Name                  Value       KMIP Version
        ====================  ==========  ============
        TPM_QUOTE             0x00000001  1.2
        TCG_INTEGRITY_REPORT  0x00000002  1.2
        SAML_ASSERTION        0x00000003  1.2
        ====================  ==========  ============

    batch_error_continuation_option
        (enum) (1.0) An enumeration used to control operation batch handling.

        >>> from kmip import enums
        >>> enums.BatchErrorContinuationOption.STOP
        <BatchErrorContinuationOption.STOP: 2>

        ========  ==========  ============
        Name      Value       KMIP Version
        ========  ==========  ============
        CONTINUE  0x00000001  1.0
        STOP      0x00000002  1.0
        UNDO      0x00000003  1.0
        ========  ==========  ============

    block_cipher_mode
        (enum) (1.0) An enumeration specifying the block cipher mode to use
        with a cryptographic algorithm. Used often with sets of cryptographic
        parameters.

        >>> from kmip import enums
        >>> enums.BlockCipherMode.CTR
        <BlockCipherMode.CTR: 6>

        ====================  ==========  ============
        Name                  Value       KMIP Version
        ====================  ==========  ============
        CBC                   0x00000001  1.0
        ECB                   0x00000002  1.0
        PCBC                  0x00000003  1.0
        CFB                   0x00000004  1.0
        OFB                   0x00000005  1.0
        CTR                   0x00000006  1.0
        CMAC                  0x00000007  1.0
        CCM                   0x00000008  1.0
        GCM                   0x00000009  1.0
        CBC_MAC               0x0000000A  1.0
        XTS                   0x0000000B  1.0
        AES_KEY_WRAP_PADDING  0x0000000C  1.0
        NIST_KEY_WRAP         0x0000000D  1.0
        X9_102_AESKW          0x0000000E  1.0
        X9_102_TDKW           0x0000000F  1.0
        X9_102_AKW1           0x00000010  1.0
        X9_102_AKW2           0x00000011  1.0
        AEAD                  0x00000012  1.4
        ====================  ==========  ============

    cancellation_result
        (enum) (1.0) An enumeration specifying the result of a cancelled
        operation.

        >>> from kmip import enums
        >>> enums.CancellationResult.FAILED
        <CancellationResult.FAILED: 4>

        ================  ==========  ============
        Name              Value       KMIP Version
        ================  ==========  ============
        CANCELED          0x00000001  1.0
        UNABLE_TO_CANCEL  0x00000002  1.0
        COMPLETED         0x00000003  1.0
        FAILED            0x00000004  1.0
        UNAVAILABLE       0x00000005  1.0
        ================  ==========  ============

    capability_information
        (dict) (1.3) A dictionary containing information about a set of
        KMIP server capabilities. Often obtained from the Query operation
        response.

        >>> from kmip import enums
        >>> capability_information = {
        ...     'streaming_capability': False,
        ...     'asynchronous_capability': False,
        ...     'attestation_capability': False,
        ...     'unwrap_mode': enums.UnwrapMode.PROCESSED,
        ...     'destroy_action': enums.DestroyAction.DELETED,
        ...     'shredding_algorithm': enums.ShreddingAlgorithm.UNSUPPORTED,
        ...     'rng_mode': enums.RNGMode.SHARED_INSTANTIATION,
        ...     'batch_undo_capability': False,
        ...     'batch_continue_capability': False
        ...     'quantum_safe_capability': False
        ... }

        =================================  =======  ============
        Key                                Value    KMIP Version
        =================================  =======  ============
        streaming_capability               bool     1.3
        asynchronous_capability            bool     1.3
        attestation_capability             bool     1.3
        :term:`unwrap_mode`                enum     1.3
        :term:`destroy_action`             enum     1.3
        :term:`shredding_algorithm`        enum     1.3
        :term:`rng_mode`                   enum     1.3
        batch_undo_capability              bool     1.4
        batch_continue_capability          bool     1.4
        quantum_safe_capability            bool     2.0
        =================================  =======  ============

    certificate_request_type
        (enum) (1.0) An enumeration specifying the type of the certificate
        request sent with a certify operation request.

        >>> from kmip import enums
        >>> enums.CertificateRequestType.PEM
        <CertificateRequestType.PEM: 3>

        ======  ==========  ============
        Name    Value       KMIP Version
        ======  ==========  ============
        CRMF    0x00000001  1.0
        PKCS10  0x00000002  1.0
        PEM     0x00000003  1.0
        PGP     0x00000004  1.0
        ======  ==========  ============

    certificate_type
        (enum) (1.0) An enumeration specifying the type of a certificate
        object.

        >>> from kmip import enums
        >>> enums.CertificateTypeEnum.X_509
        <CertificateTypeEnum.X_509: 1>

        =====  ==========  ============
        Name   Value       KMIP Version
        =====  ==========  ============
        X_509  0x00000001  1.0
        PGP    0x00000002  1.0
        =====  ==========  ============

    client_registration_method
        (enum) (1.3) An enumeration specifying a type of registration method
        utilized by the client or server. Used often as part of the response
        to a Query request.

        >>> from kmip import enums
        >>> enums.ClientRegistrationMethod.CLIENT_REGISTERED
        <ClientRegistrationMethod.CLIENT_REGISTERED: 5>

        ===================  ==========  ============
        Name                 Value       KMIP Version
        ===================  ==========  ============
        UNSPECIFIED          0x00000001  1.3
        SERVER_PREGENERATED  0x00000002  1.3
        SERVER_ON_DEMAND     0x00000003  1.3
        CLIENT_GENERATED     0x00000004  1.3
        CLIENT_REGISTERED    0x00000005  1.3
        ===================  ==========  ============

    credential_type
        (enum) (1.0) An enumeration specifying the type of a credential object.
        Used often as part of a credential structure.

        >>> from kmip import enums
        >>> enums.CredentialType.USERNAME_AND_PASSWORD
        <CredentialType.USERNAME_AND_PASSWORD: 1>

        =====================  ==========  ============
        Name                   Value       KMIP Version
        =====================  ==========  ============
        USERNAME_AND_PASSWORD  0x00000001  1.0
        DEVICE                 0x00000002  1.1
        ATTESTATION            0x00000003  1.2
        ONE_TIME_PASSWORD      0x00000004  2.0
        HASHED_PASSWORD        0x00000005  2.0
        TICKET                 0x00000006  2.0
        =====================  ==========  ============

    cryptographic_algorithm
        (enum) (1.0) An enumeration specifying the cryptographic algorithm to
        use for a cryptographic operation. Used often with sets of
        cryptographic parameters.

        >>> from kmip import enums
        >>> enums.CryptographicAlgorithm.RSA
        <CryptographicAlgorithm.RSA: 4>

        =================  ==========  ============
        Name               Value       KMIP Version
        =================  ==========  ============
        DES                0x00000001  1.0
        TRIPLE_DES         0x00000002  1.0
        AES                0x00000003  1.0
        RSA                0x00000004  1.0
        DSA                0x00000005  1.0
        ECDSA              0x00000006  1.0
        HMAC_SHA1          0x00000007  1.0
        HMAC_SHA224        0x00000008  1.0
        HMAC_SHA256        0x00000009  1.0
        HMAC_SHA384        0x0000000A  1.0
        HMAC_SHA512        0x0000000B  1.0
        HMAC_MD5           0x0000000C  1.0
        DH                 0x0000000D  1.0
        ECDH               0x0000000E  1.0
        ECMQV              0x0000000F  1.0
        BLOWFISH           0x00000010  1.0
        CAMELLIA           0x00000011  1.0
        CAST5              0x00000012  1.0
        IDEA               0x00000013  1.0
        MARS               0x00000014  1.0
        RC2                0x00000015  1.0
        RC4                0x00000016  1.0
        RC5                0x00000017  1.0
        SKIPJACK           0x00000018  1.0
        TWOFISH            0x00000019  1.0
        EC                 0x0000001A  1.2
        ONE_TIME_PAD       0x0000001B  1.3
        CHACHA20           0x0000001C  1.4
        POLY1305           0x0000001D  1.4
        CHACHA20_POLY1305  0x0000001E  1.4
        SHA3_224           0x0000001F  1.4
        SHA3_256           0x00000020  1.4
        SHA3_384           0x00000021  1.4
        SHA3_512           0x00000022  1.4
        HMAC_SHA3_224      0x00000023  1.4
        HMAC_SHA3_256      0x00000024  1.4
        HMAC_SHA3_384      0x00000025  1.4
        HMAC_SHA3_512      0x00000026  1.4
        SHAKE_128          0x00000027  1.4
        SHAKE_256          0x00000028  1.4
        ARIA               0x00000029  2.0
        SEED               0x0000002A  2.0
        SM2                0x0000002B  2.0
        SM3                0x0000002C  2.0
        SM4                0x0000002D  2.0
        GOST_R_34_10_2012  0x0000002E  2.0
        GOST_R_34_11_2012  0x0000002F  2.0
        GOST_R_34_13_2015  0x00000030  2.0
        GOST_28147_89      0x00000031  2.0
        XMSS               0x00000032  2.0
        SPHINCS_256        0x00000033  2.0
        MCELIECE           0x00000034  2.0
        MCELIECE_6960119   0x00000035  2.0
        MCELIECE_8192128   0x00000036  2.0
        ED25519            0x00000037  2.0
        ED448              0x00000038  2.0
        =================  ==========  ============

    cryptographic_length
        (int) (1.0) A integer specifying the length of a cryptographic object
        in bits. Used as a parameter for creating encryption keys of various
        types and as an object attribute for cryptographic objects.

    cryptographic_parameters
        (dict) (1.0) A dictionary containing key/value pairs representing
        settings to be used when performing cryptographic operations. Used as
        a parameter to various KMIP operations but can also be set as an
        attribute on a KMIP object.

        >>> from kmip import enums
        >>> cryptographic_parameters = {
        ...     'block_cipher_mode': enums.BlockCipherMode.CTR,
        ...     'padding_method': enums.PaddingMethod.PKCS5,
        ...     'random_iv': False,
        ...     'initial_counter_value': 0
        ... }

        ========================================  =======  ============
        Key                                       Value    KMIP Version
        ========================================  =======  ============
        :term:`block_cipher_mode`                 enum     1.0
        :term:`padding_method`                    enum     1.0
        :term:`hashing_algorithm`                 enum     1.0
        :term:`key_role_type`                     enum     1.0
        :term:`digital_signature_algorithm`       enum     1.2
        :term:`cryptographic_algorithm`           enum     1.2
        random_iv                                 bool     1.2
        iv_length                                 int      1.2
        tag_length                                int      1.2
        fixed_field_length                        int      1.2
        invocation_field_length                   int      1.2
        counter_length                            int      1.2
        initial_counter_value                     int      1.2
        salt_length                               int      1.4
        :term:`mask_generator`                    enum     1.4
        :term:`mask_generator_hashing_algorithm`  enum     1.4
        p_source                                  bytes    1.4
        trailer_field                             int      1.4
        ========================================  =======  ============

    cryptographic_usage_mask
        (enum) (1.0) An enumeration specifying a cryptographic capability,
        usually associated with a managed object. Often used in list form
        (e.g., [CryptographicUsageMask.SIGN, CryptographicUsageMask.VERIFY]).

        >>> from kmip import enums
        >>> enums.CryptographicUsageMask.ENCRYPT
        <CryptographicUsageMask.ENCRYPT: 4>

        ===================  ==========  ============
        Name                 Value       KMIP Version
        ===================  ==========  ============
        SIGN                 0x00000001  1.0
        VERIFY               0x00000002  1.0
        ENCRYPT              0x00000004  1.0
        DECRYPT              0x00000008  1.0
        WRAP_KEY             0x00000010  1.0
        UNWRAP_KEY           0x00000020  1.0
        EXPORT               0x00000040  1.0
        MAC_GENERATE         0x00000080  1.0
        MAC_VERIFY           0x00000100  1.0
        DERIVE_KEY           0x00000200  1.0
        CONTENT_COMMITMENT   0x00000400  1.0
        KEY_AGREEMENT        0x00000800  1.0
        CERTIFICATE_SIGN     0x00001000  1.0
        CRL_SIGN             0x00002000  1.0
        GENERATE_CRYPTOGRAM  0x00004000  1.0
        VALIDATE_CRYPTOGRAM  0x00008000  1.0
        TRANSLATE_ENCRYPT    0x00010000  1.0
        TRANSLATE_DECRYPT    0x00020000  1.0
        TRANSLATE_WRAP       0x00040000  1.0
        TRANSLATE_UNWRAP     0x00080000  1.0
        AUTHENTICATE         0x00100000  2.0
        UNRESTRICTED         0x00200000  2.0
        FPE_ENCRYPT          0x00400000  2.0
        FPE_DECRYPT          0x00800000  2.0
        ===================  ==========  ============

    derivation_parameters
        (dict) (1.0) A dictionary containing key/value pairs representing
        settings to be used when performing key derivation operations. Used
        as a parameter to the DeriveKey operation.

        >>> from kmip import enums
        >>> derivation_parameters = {
        ...     'cryptographic_parameters': {...},
        ...     'initialization_vector': b'\x01\x02\x03\x04',
        ...     'derivation_data': b'\xFF\xFF\xFF\xFF',
        ...     'salt': b'\x00\x00\xFF\xFF',
        ...     'iteration_count': 1000
        ... }

        ========================  =======  ============
        Key                       Value    KMIP Version
        ========================  =======  ============
        cryptographic_parameters  dict     1.0
        initialization_vector     bytes    1.0
        derivation_data           bytes    1.0
        salt                      bytes    1.0
        iteration_count           int      1.0
        ========================  =======  ============

    derivation_method
        (enum) (1.0) An enumeration specifying a key derivation method to be
        used to derive a new key. Used as a parameter to the DeriveKey
        operation.

        >>> from kmip import enums
        >>> enums.DerivationMethod.PBKDF2
        <DerivationMethod.PBKDF2: 1>

        =======================  ==========  ============
        Name                     Value       KMIP Version
        =======================  ==========  ============
        PBKDF2                   0x00000001  1.0
        HASH                     0x00000002  1.0
        HMAC                     0x00000003  1.0
        ENCRYPT                  0x00000004  1.0
        NIST800_108_C            0x00000005  1.0
        NIST800_108_F            0x00000006  1.0
        NIST800_108_DPI          0x00000007  1.0
        ASYMMETRIC_KEY           0x00000008  1.4
        AWS_SIGNATURE_VERSION_4  0x00000009  2.0
        HKDF                     0x0000000A  2.0
        =======================  ==========  ============

    destroy_action
        (enum) (1.3) An enumeration specifying methods of data disposal used
        by a KMIP server. Used often as part of the response to a Query
        request.

        >>> from kmip import enums
        >>> enums.DestroyAction.SHREDDED
        <DestroyAction.SHREDDED: 7>

        =====================  ==========  ============
        Name                   Value       KMIP Version
        =====================  ==========  ============
        UNSPECIFIED            0x00000001  1.3
        KEY_MATERIAL_DELETED   0x00000002  1.3
        KEY_MATERIAL_SHREDDED  0x00000003  1.3
        METADATA_DELETED       0x00000004  1.3
        METADATA_SHREDDED      0x00000005  1.3
        DELETED                0x00000006  1.3
        SHREDDED               0x00000007  1.3
        =====================  ==========  ============

    digital_signature_algorithm
        (enum) (1.1) An enumeration specifying a digital signature algorithm,
        usually associated with a signed object. Used often with sets of
        cryptographic parameters.

        >>> from kmip import enums
        >>> enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION
        <DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION: 5>

        ============================  ==========  ============
        Name                          Value       KMIP Version
        ============================  ==========  ============
        MD2_WITH_RSA_ENCRYPTION       0x00000001  1.1
        MD5_WITH_RSA_ENCRYPTION       0x00000002  1.1
        SHA1_WITH_RSA_ENCRYPTION      0x00000003  1.1
        SHA224_WITH_RSA_ENCRYPTION    0x00000004  1.1
        SHA256_WITH_RSA_ENCRYPTION    0x00000005  1.1
        SHA384_WITH_RSA_ENCRYPTION    0x00000006  1.1
        SHA512_WITH_RSA_ENCRYPTION    0x00000007  1.1
        RSASSA_PSS                    0x00000008  1.1
        DSA_WITH_SHA1                 0x00000009  1.1
        DSA_WITH_SHA224               0x0000000A  1.1
        DSA_WITH_SHA256               0x0000000B  1.1
        ECDSA_WITH_SHA1               0x0000000C  1.1
        ECDSA_WITH_SHA224             0x0000000D  1.1
        ECDSA_WITH_SHA256             0x0000000E  1.1
        ECDSA_WITH_SHA384             0x0000000F  1.1
        ECDSA_WITH_SHA512             0x00000010  1.1
        SHA3_256_WITH_RSA_ENCRYPTION  0x00000011  1.4
        SHA3_384_WITH_RSA_ENCRYPTION  0x00000012  1.4
        SHA3_512_WITH_RSA_ENCRYPTION  0x00000013  1.4
        ============================  ==========  ============

    drbg_algorithm
        (enum) (1.3) An enumeration specifying a deterministic random bit
        generator. Used often to describe a random number generator.

        >>> from kmip import enums
        >>> enums.DRBGAlgorithm.DUAL_EC
        <DRBGAlgorithm.DUAL_EC: 2>

        ===========  ==========  ============
        Name         Value       KMIP Version
        ===========  ==========  ============
        UNSPECIFIED  0x00000001  1.3
        DUAL_EC      0x00000002  1.3
        HASH         0x00000003  1.3
        HMAC         0x00000004  1.3
        CTR          0x00000005  1.3
        ===========  ==========  ============

    encoding_option
        (enum) (1.1) An enumeration specifying the encoding of an object
        before it is cryptographically wrapped. Used in various key wrapping
        metadata structures.

        >>> from kmip import enums
        >>> enums.EncodingOption.NO_ENCODING
        <EncodingOption.NO_ENCODING: 1>

        =============  ==========  ============
        Name           Value       KMIP Version
        =============  ==========  ============
        NO_ENCODING    0x00000001  1.1
        TTLV_ENCODING  0x00000002  1.1
        =============  ==========  ============

    encryption_key_information
        (dict) (1.0) A dictionary containing information on the encryption key
        used for key wrapping.

        >>> from kmip import enums
        >>> encryption_key_information = {
        ...     'unique_identifier': '123e4567-e89b-12d3-a456-426655440000',
        ...     'cryptographic_parameters': {...}
        ... }

        ================================  =======  ============
        Key                               Value    KMIP Version
        ================================  =======  ============
        unique_identifier                 string   1.0
        :term:`cryptographic_parameters`  dict     1.0
        ================================  =======  ============

    extension_information
        (dict) (1.1) A dictionary containing information on a specific KMIP
        specification extension supported by a KMIP server. Often returned as
        part of a Query operation response.

        >>> from kmip import enums
        >>> extension_information = {
        ...     'extension_name': 'ACME LOCATION',
        ...     'extension_tag': 0x0054aa01,
        ...     'extension_type': 0x00000007
        ... }
        >>> extension_information = {
        ...     'extension_name': 'ACME LOCATION',
        ...     'extension_tag': 0x0054aa01,
        ...     'extension_type': enums.ItemType.TEXT_STRING,
        ...     'extension_attribute': True,
        ...     'extension_parent_structure_tag': 0x0054aa02,
        ...     'extension_description': 'Example description.'
        ... }

        ==============================  ==========  ============
        Key                             Value       KMIP Version
        ==============================  ==========  ============
        extension_name                  string      1.1
        extension_tag                   int         1.1
        extension_type                  int / enum  1.1 / 2.0
        extension_enumeration           int         2.0
        extension_attribute             bool        2.0
        extension_parent_structure_tag  int         2.0
        extension_description           string      2.0
        ==============================  ==========  ============

    fips186_variation
        (enum) (1.3) An enumeration specifying a FIPS 186 variation. Used
        often to describe a random number generator.

        >>> from kmip import enums
        >>> enums.FIPS186Variation.K_CHANGE_NOTICE
        <FIPS186Variation.K_CHANGE_NOTICE: 7>

        ==================  ==========  ============
        Name                Value       KMIP Version
        ==================  ==========  ============
        UNSPECIFIED         0x00000001  1.3
        GP_X_ORIGINAL       0x00000002  1.3
        GP_X_CHANGE_NOTICE  0x00000003  1.3
        X_ORIGINAL          0x00000004  1.3
        X_CHANGE_NOTICE     0x00000005  1.3
        K_ORIGINAL          0x00000006  1.3
        K_CHANGE_NOTICE     0x00000007  1.3
        ==================  ==========  ============

    hashing_algorithm
        (enum) (1.0) An enumeration specifying the hashing method to use with
        a cryptographic algorithm. Used often with sets of cryptographic
        parameters.

        >>> from kmip import enums
        >>> enums.HashingAlgorithm.MD5
        <HashingAlgorithm.MD5: 3>

        ===========  ==========  ============
        Name         Value       KMIP Version
        ===========  ==========  ============
        MD2          0x00000001  1.0
        MD4          0x00000002  1.0
        MD5          0x00000003  1.0
        SHA_1        0x00000004  1.0
        SHA_224      0x00000005  1.0
        SHA_256      0x00000006  1.0
        SHA_384      0x00000007  1.0
        SHA_512      0x00000008  1.0
        RIPEMD_160   0x00000009  1.0
        TIGER        0x0000000A  1.0
        WHIRLPOOL    0x0000000B  1.0
        SHA_512_224  0x0000000C  1.2
        SHA_512_256  0x0000000D  1.2
        SHA3_224     0x0000000E  1.4
        SHA3_256     0x0000000F  1.4
        SHA3_384     0x00000010  1.4
        SHA3_512     0x00000011  1.4
        ===========  ==========  ============

    initial_date
        (int) (1.0) An integer specifying, in seconds since the Epoch, the
        date and time when a managed object first entered the pre-active
        state. This occurs when the object is first created or registered
        with the key management appliance. This value is set by the server
        on every managed object and cannot be changed.

    item_type
        (enum) (2.0) An enumeration specifying the type of an object. Only
        the least significant byte of the enumeration value is used in KMIP
        object encodings.

        >>> from kmip import enums
        >>> enums.ItemType.STRUCTURE
        <ItemType.STRUCTURE: 1>

        ==================  ==========  ============
        Name                Value       KMIP Version
        ==================  ==========  ============
        STRUCTURE           0x00000001  2.0
        INTEGER             0x00000002  2.0
        LONG_INTEGER        0x00000003  2.0
        BIG_INTEGER         0x00000004  2.0
        ENUMERATION         0x00000005  2.0
        BOOLEAN             0x00000006  2.0
        TEXT_STRING         0x00000007  2.0
        BYTE_STRING         0x00000008  2.0
        DATE_TIME           0x00000009  2.0
        INTERVAL            0x0000000A  2.0
        DATE_TIME_EXTENDED  0x0000000B  2.0
        ==================  ==========  ============

    key_compression_type
        (enum) (1.0) An enumeration specifying the key compression used for
        an elliptic curve public key. Used as a key value attribute and as a
        parameter for the Get operation.

        >>> from kmip import enums
        >>> enums.KeyCompressionType.EC_PUBLIC_KEY_TYPE_UNCOMPRESSED
        <KeyCompressionType.EC_PUBLIC_KEY_TYPE_UNCOMPRESSED: 1>

        =========================================  ==========  ============
        Name                                       Value       KMIP Version
        =========================================  ==========  ============
        EC_PUBLIC_KEY_TYPE_UNCOMPRESSED            0x00000001  1.0
        EC_PUBLIC_KEY_TYPE_X9_62_COMPRESSED_PRIME  0x00000002  1.0
        EC_PUBLIC_KEY_TYPE_X9_62_COMPRESSED_CHAR2  0x00000003  1.0
        EC_PUBLIC_KEY_TYPE_X9_62_HYBRID            0x00000004  1.0
        =========================================  ==========  ============

    key_format_type
        (enum) (1.0) An enumeration specifying the format of key material.
        Used in various ways as a key value attribute, as well as a
        parameter to the Get operation.

        >>> from kmip import enums
        >>> enums.KeyFormatType.RAW
        <KeyFormatType.RAW: 1>

        =============================  ==========  ============
        Name                           Value       KMIP Version
        =============================  ==========  ============
        RAW                            0x00000001  1.0
        OPAQUE                         0x00000002  1.0
        PKCS_1                         0x00000003  1.0
        PKCS_8                         0x00000004  1.0
        X_509                          0x00000005  1.0
        EC_PRIVATE_KEY                 0x00000006  1.0
        TRANSPARENT_SYMMETRIC_KEY      0x00000007  1.0
        TRANSPARENT_DSA_PRIVATE_KEY    0x00000008  1.0
        TRANSPARENT_DSA_PUBLIC_KEY     0x00000009  1.0
        TRANSPARENT_RSA_PRIVATE_KEY    0x0000000a  1.0
        TRANSPARENT_RSA_PUBLIC_KEY     0x0000000b  1.0
        TRANSPARENT_DH_PRIVATE_KEY     0x0000000c  1.0
        TRANSPARENT_DH_PUBLIC_KEY      0x0000000d  1.0
        TRANSPARENT_ECDSA_PRIVATE_KEY  0x0000000e  1.0
        TRANSPARENT_ECDSA_PUBLIC_KEY   0x0000000f  1.0
        TRANSPARENT_ECDH_PRIVATE_KEY   0x00000010  1.0
        TRANSPARENT_ECDH_PUBLIC_KEY    0x00000011  1.0
        TRANSPARENT_ECMQV_PRIVATE_KEY  0x00000012  1.0
        TRANSPARENT_ECMQV_PUBLIC_KEY   0x00000013  1.0
        TRANSPARENT_EC_PRIVATE_KEY     0x00000014  1.3
        TRANSPARENT_EC_PUBLIC_KEY      0x00000015  1.3
        PKCS_12                        0x00000016  1.4
        =============================  ==========  ============

    key_role_type
        (enum) (1.0) An enumeration specifying the key role type of the
        associated cryptographic key. Used often with sets of cryptographic
        parameters.

        >>> from kmip import enums
        >>> enums.KeyRoleType.KEK
        <KeyRoleType.KEK: 11>

        =========  ==========  ============
        Name       Value       KMIP Version
        =========  ==========  ============
        BDK        0x00000001  1.0
        CVK        0x00000002  1.0
        DEK        0x00000003  1.0
        MKAC       0x00000004  1.0
        MKSMC      0x00000005  1.0
        MKSMI      0x00000006  1.0
        MKDAC      0x00000007  1.0
        MKDN       0x00000008  1.0
        MKCP       0x00000009  1.0
        MKOTH      0x0000000A  1.0
        KEK        0x0000000B  1.0
        MAC_16609  0x0000000C  1.0
        MAC_97971  0x0000000D  1.0
        MAC_97972  0x0000000E  1.0
        MAC_97973  0x0000000F  1.0
        MAC_97974  0x00000010  1.0
        MAC_97975  0x00000011  1.0
        ZPK        0x00000012  1.0
        PVKIBM     0x00000013  1.0
        PVKPVV     0x00000014  1.0
        PVKOTH     0x00000015  1.0
        DUKPT      0x00000016  1.4
        IV         0x00000017  1.4
        TRKBK      0x00000018  1.4
        =========  ==========  ============

    key_value_location_type
        (enum) (1.2) An enumeration specifying the type of key value location
        identifier. Used in cases where a key value is stored outside a key
        server.

        >>> from kmip import enums
        >>> enums.KeyValueLocationType.URI
        <KeyValueLocationType.URI: 2>

        =========================  ==========  ============
        Name                       Value       KMIP Version
        =========================  ==========  ============
        UNINTERPRETED_TEXT_STRING  0x00000001  1.2
        URI                        0x00000002  1.2
        =========================  ==========  ============

    key_wrap_type
        (enum) (1.4) An enumeration specifying the type of key wrap used to
        access a managed object. Used to specify key wrapping in Get and
        Export operations.

        >>> from kmip import enums
        >>> enums.KeyWrapType.NOT_WRAPPED
        <KeyWrapType.NOT_WRAPPED: 1>

        =============  ==========  ============
        Name           Value       KMIP Version
        =============  ==========  ============
        NOT_WRAPPED    0x00000001  1.4
        AS_REGISTERED  0x00000002  1.4
        =============  ==========  ============

    key_wrapping_data
        (dict) (1.0) A dictionary containing information on a cryptographic
        key wrapping mechanism used to wrap a key value.

        >>> from kmip import enums
        >>> key_wrapping_data = {
        ...     'wrapping_method': enums.WrappingMethod.ENCRYPT,
        ...     'encryption_key_information': {...},
        ...     'iv_counter_nonce': b'\x01\x02\x03\x04',
        ...     'encoding_option': enums.EncodingOption.NO_ENCODING
        ... }

        =============================  =======  ============
        Key                            Value    KMIP Version
        =============================  =======  ============
        :term:`wrapping_method`        enum     1.0
        encryption_key_information     dict     1.0
        mac_signature_key_information  dict     1.0
        mac_signature                  bytes    1.0
        iv_counter_nonce               bytes    1.0
        :term:`encoding_option`        enum     1.1
        =============================  =======  ============

    key_wrapping_specification
        (dict) (1.0) A dictionary containing settings defining how an object
        should be cryptographically wrapped. Used as a parameter for the Get
        operation to retrieve cryptographically wrapped objects.

        >>> from kmip import enums
        >>> key_wrapping_specification = {
        ...     'wrapping_method': enums.WrappingMethod.ENCRYPT,
        ...     'encryption_key_information': {...},
        ...     'attribute_names': [
        ...         'Cryptographic Algorithm',
        ...         'Cryptographic Length'
        ...     ]
        ... }

        =============================  =======  ============
        Key                            Value    KMIP Version
        =============================  =======  ============
        :term:`wrapping_method`        enum     1.0
        encryption_key_information     dict     1.0
        mac_signature_key_information  dict     1.0
        attribute_names                list     1.0
        :term:`encoding_option`        enum     1.1
        =============================  =======  ============

    kmip_version
        (enum) (-) An enumeration specifying the KMIP version to use for the
        client and/or server. Defined independently of any individual KMIP
        specification version.

        >>> from kmip import enums
        >>> enums.KMIPVersion.KMIP_1_1
        <KMIPVersion.KMIP_1_1: 1.1>

        ========  ==========
        Name      Value
        ========  ==========
        KMIP_1_0  1.0
        KMIP_1_1  1.1
        KMIP_1_2  1.2
        KMIP_1_3  1.3
        KMIP_1_4  1.4
        KMIP_2_0  2.0
        ========  ==========

    link_type
        (enum) (1.0) An enumeration specifying the type of link connecting two
        managed objects. Used often as an object attribute.

        >>> from kmip import enums
        >>> enums.LinkType.PUBLIC_KEY_LINK
        <LinkType.PUBLIC_KEY_LINK: 258>

        ===========================  ==========  ============
        Name                         Value       KMIP Version
        ===========================  ==========  ============
        CERTIFICATE_LINK             0x00000101  1.0
        PUBLIC_KEY_LINK              0x00000102  1.0
        PRIVATE_KEY_LINK             0x00000103  1.0
        DERIVATION_BASE_OBJECT_LINK  0x00000104  1.0
        DERIVED_KEY_LINK             0x00000105  1.0
        REPLACEMENT_OBJECT_LINK      0x00000106  1.0
        REPLACED_OBJECT_LINK         0x00000107  1.0
        PARENT_LINK                  0x00000108  1.2
        CHILD_LINK                   0x00000109  1.2
        PREVIOUS_LINK                0x0000010a  1.2
        NEXT_LINK                    0x0000010b  1.2
        PKCS12_CERTIFICATE_LINK      0x0000010c  1.4
        PKCS12_PASSWORD_LINK         0x0000010d  1.4
        WRAPPING_KEY_LINK            0x0000010E  2.0
        ===========================  ==========  ============

    mac_signature_key_information
        (dict) (1.0) A dictionary containing information on the MAC/signature
        key used for key wrapping.

        >>> from kmip import enums
        >>> mac_signature_key_information = {
        ...     'unique_identifier': '123e4567-e89b-12d3-a456-426655440000',
        ...     'cryptographic_parameters': {...}
        ... }

        ========================  =======  ============
        Key                       Value    KMIP Version
        ========================  =======  ============
        unique_identifier         string   1.0
        cryptographic_parameters  dict     1.0
        ========================  =======  ============

    mask_generator_hashing_algorithm
        (enum) (1.4) Another name for a hash algorithm. See hashing_algorithm.

    mask_generator
        (enum) (1.4) An enumeration specifying the mask generation function to
        use for a cryptographic operation. Used often with sets of
        cryptographic parameters.

        >>> from kmip import enums
        >>> enums.MaskGenerator.MGF1
        <MaskGenerator.MGF1: 1>

        ====  ==========  ============
        Name  Value       KMIP Version
        ====  ==========  ============
        MGF1  0x00000001  1.4
        ====  ==========  ============

    name
        (str) (1.0) A string specifying the name of a managed object stored by
        the server. It can be used in addition to the :term:`unique_identifier`
        to identify an object and can be used as a filter with the Locate
        operation.

    name_type
        (enum) (1.0) An enumeration specifying the type of name value used in
        a name attribute structure.

        >>> from kmip import enums
        >>> enums.NameType.URI
        <NameType.URI: 2>

        =========================  ==========  ============
        Name                       Value       KMIP Version
        =========================  ==========  ============
        UNINTERPRETED_TEXT_STRING  0x00000001  1.0
        URI                        0x00000002  1.0
        =========================  ==========  ============

    object_group_member
        (enum) (1.1) An enumeration specifying whether or not a group object
        has been returned to a client before the current request. Used as a
        filtering flag for the Locate operation.

        >>> from kmip import enums
        >>> enums.ObjectGroupMember.GROUP_MEMBER_FRESH
        <ObjectGroupMember.GROUP_MEMBER_FRESH: 1>

        ====================  ==========  ============
        Name                  Value       KMIP Version
        ====================  ==========  ============
        GROUP_MEMBER_FRESH    0x00000001  1.1
        GROUP_MEMBER_DEFAULT  0x00000002  1.1
        ====================  ==========  ============

    object_type
        (enum) (1.0) An enumeration specifying the type of a managed object.
        Used as an attribute for every managed object on a key server.

        >>> from kmip import enums
        >>> enums.ObjectType.SYMMETRIC_KEY
        <ObjectType.SYMMETRIC_KEY: 2>

        ===================  ==========  ============
        Name                 Value       KMIP Version
        ===================  ==========  ============
        CERTIFICATE          0x00000001  1.0
        SYMMETRIC_KEY        0x00000002  1.0
        PUBLIC_KEY           0x00000003  1.0
        PRIVATE_KEY          0x00000004  1.0
        SPLIT_KEY            0x00000005  1.0
        TEMPLATE             0x00000006  1.0
        SECRET_DATA          0x00000007  1.0
        OPAQUE_DATA          0x00000008  1.0
        PGP_KEY              0x00000009  1.2
        CERTIFICATE_REQUEST  0x0000000A  2.0
        ===================  ==========  ============

    opaque_data_type
        (enum) (1.0) An enumeration specifying the type of the associated
        opaque data object. Note that no values have ever been specified by
        the KMIP specification. A custom NONE value is included in PyKMIP
        as a default. This value will only be recognized by the PyKMIP
        server.

        >>> from kmip import enums
        >>> enums.OpaqueDataType.NONE
        <OpaqueDataType.NONE: 2147483648>

        ====  ==========  ============
        Name  Value       KMIP Version
        ====  ==========  ============
        NONE  0x80000000  --
        ====  ==========  ============

    operation
        (enum) (1.0) An enumeration specifying a KMIP operation. Used in KMIP
        requests.

        >>> from kmip import enums
        >>> enums.Operation.GET
        <Operation.GET: 10>

        ====================  ==========  ============
        Name                  Value       KMIP Version
        ====================  ==========  ============
        CREATE                0x00000001  1.0
        CREATE_KEY_PAIR       0x00000002  1.0
        REGISTER              0x00000003  1.0
        REKEY                 0x00000004  1.0
        DERIVE_KEY            0x00000005  1.0
        CERTIFY               0x00000006  1.0
        RECERTIFY             0x00000007  1.0
        LOCATE                0x00000008  1.0
        CHECK                 0x00000009  1.0
        GET                   0x0000000a  1.0
        GET_ATTRIBUTES        0x0000000b  1.0
        GET_ATTRIBUTE_LIST    0x0000000c  1.0
        ADD_ATTRIBUTE         0x0000000d  1.0
        MODIFY_ATTRIBUTE      0x0000000e  1.0
        DELETE_ATTRIBUTE      0x0000000f  1.0
        OBTAIN_LEASE          0x00000010  1.0
        GET_USAGE_ALLOCATION  0x00000011  1.0
        ACTIVATE              0x00000012  1.0
        REVOKE                0x00000013  1.0
        DESTROY               0x00000014  1.0
        ARCHIVE               0x00000015  1.0
        RECOVER               0x00000016  1.0
        VALIDATE              0x00000017  1.0
        QUERY                 0x00000018  1.0
        CANCEL                0x00000019  1.0
        POLL                  0x0000001a  1.0
        NOTIFY                0x0000001b  1.0
        PUT                   0x0000001c  1.0
        REKEY_KEY_PAIR        0x0000001d  1.1
        DISCOVER_VERSIONS     0x0000001e  1.1
        ENCRYPT               0x0000001f  1.2
        DECRYPT               0x00000020  1.2
        SIGN                  0x00000021  1.2
        SIGNATURE_VERIFY      0x00000022  1.2
        MAC                   0x00000023  1.2
        MAC_VERIFY            0x00000024  1.2
        RNG_RETRIEVE          0x00000025  1.2
        RNG_SEED              0x00000026  1.2
        HASH                  0x00000027  1.2
        CREATE_SPLIT_KEY      0x00000028  1.2
        JOIN_SPLIT_KEY        0x00000029  1.2
        IMPORT                0x0000002a  1.4
        EXPORT                0x0000002b  1.4
        LOG                   0x0000002C  2.0
        LOGIN                 0x0000002D  2.0
        LOGOUT                0x0000002E  2.0
        DELEGATED_LOGIN       0x0000002F  2.0
        ADJUST_ATTRIBUTE      0x00000030  2.0
        SET_ATTRIBUTE         0x00000031  2.0
        SET_ENDPOINT_ROLE     0x00000032  2.0
        PKCS_11               0x00000033  2.0
        INTEROP               0x00000034  2.0
        REPROVISION           0x00000035  2.0
        ====================  ==========  ============

    operation_policy_name
        (str) (1.0) A string specifying the name of the operation policy that
        should be used for access control decisions for a managed object. One
        operation policy name attribute can be set per managed object by the
        server. Once set it cannot be changed by the client.

    padding_method
        (enum) (1.0) An enumeration specifying the padding method to use to
        pad data during cryptographic operations. Used often with sets of
        cryptographic parameters.

        >>> from kmip import enums
        >>> enums.PaddingMethod.PKCS5
        <PaddingMethod.PKCS5: 3>

        =========  ==========  ============
        Name       Value       KMIP Version
        =========  ==========  ============
        NONE       0x00000001  1.0
        OAEP       0x00000002  1.0
        PKCS5      0x00000003  1.0
        SSL3       0x00000004  1.0
        ZEROS      0x00000005  1.0
        ANSI_X923  0x00000006  1.0
        ISO_10126  0x00000007  1.0
        PKCS1v15   0x00000008  1.0
        X931       0x00000009  1.0
        PSS        0x0000000A  1.0
        =========  ==========  ============

    profile_information
        (dict) (1.3) A dictionary containing information about a KMIP profile
        supported by a KMIP server. Often obtained from the Query operation
        response.

        >>> from kmip import enums
        >>> profile_information = {
        ...     'profile_name': enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12,
        ...     'server_uri': 'https://127.0.0.1',
        ...     'server_port': 5696,
        ...     'profile_version': {
        ...         'profile_version_major': 1,
        ...         'profile_version_minor': 0
        ...     }
        ... }

        =======================  =======  ============
        Key                      Value    KMIP Version
        =======================  =======  ============
        :term:`profile_name`     enum     1.3
        server_uri               string   1.3
        server_port              int      1.3
        :term:`profile_version`  dict     2.0
        =======================  =======  ============

    profile_name
        (enum) (1.3) An enumeration specifying a profile supported by the
        client or server. Used often as part of the response to a Query
        request.

        >>> from kmip import enums
        >>> enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
        <ProfileName.BASELINE_SERVER_BASIC_KMIPv12: 1>

        =======================================================  ==========  ============
        Name                                                     Value       KMIP Version
        =======================================================  ==========  ============
        BASELINE_SERVER_BASIC_KMIPv12                            0x00000001  1.3
        BASELINE_SERVER_TLSv12_KMIPv12                           0x00000002  1.3
        BASELINE_CLIENT_BASIC_KMIPv12                            0x00000003  1.3
        BASELINE_CLIENT_TLSv12_KMIPv12                           0x00000004  1.3
        COMPLETE_SERVER_BASIC_KMIPv12                            0x00000005  1.3
        COMPLETE_SERVER_TLSv12_KMIPv12                           0x00000006  1.3
        TAPE_LIBRARY_CLIENT_KMIPv10                              0x00000007  1.3
        TAPE_LIBRARY_CLIENT_KMIPv11                              0x00000008  1.3
        TAPE_LIBRARY_CLIENT_KMIPv12                              0x00000009  1.3
        TAPE_LIBRARY_SERVER_KMIPv10                              0x0000000a  1.3
        TAPE_LIBRARY_SERVER_KMIPv11                              0x0000000b  1.3
        TAPE_LIBRARY_SERVER_KMIPv12                              0x0000000c  1.3
        SYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv10                   0x0000000d  1.3
        SYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv11                   0x0000000e  1.3
        SYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv12                   0x0000000f  1.3
        SYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv10                   0x00000010  1.3
        SYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv11                   0x00000011  1.3
        SYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv12                   0x00000012  1.3
        ASYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv10                  0x00000013  1.3
        ASYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv11                  0x00000014  1.3
        ASYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv12                  0x00000015  1.3
        ASYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv10                  0x00000016  1.3
        ASYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv11                  0x00000017  1.3
        ASYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv12                  0x00000018  1.3
        BASIC_CRYPTOGRAPHIC_CLIENT_KMIPv12                       0x00000019  1.3
        BASIC_CRYPTOGRAPHIC_SERVER_KMIPv12                       0x0000001a  1.3
        ADVANCED_CRYPTOGRAPHIC_CLIENT_KMIPv12                    0x0000001b  1.3
        ADVANCED_CRYPTOGRAPHIC_SERVER_KMIPv12                    0x0000001c  1.3
        RNG_CRYPTOGRAPHIC_CLIENT_KMIPv12                         0x0000001d  1.3
        RNG_CRYPTOGRAPHIC_SERVER_KMIPv12                         0x0000001e  1.3
        BASIC_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv10               0x0000001f  1.3
        INTERMEDIATE_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv10        0x00000020  1.3
        ADVANCED_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv10            0x00000021  1.3
        BASIC_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv11               0x00000022  1.3
        INTERMEDIATE_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv11        0x00000023  1.3
        ADVANCED_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv11            0x00000024  1.3
        BASIC_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv12               0x00000025  1.3
        INTERMEDIATE_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv12        0x00000026  1.3
        ADVANCED_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv12            0x00000027  1.3
        SYMMETRIC_KEY_FOUNDRY_SERVER_KMIPv10                     0x00000028  1.3
        SYMMETRIC_KEY_FOUNDRY_SERVER_KMIPv11                     0x00000029  1.3
        SYMMETRIC_KEY_FOUNDRY_SERVER_KMIPv12                     0x0000002a  1.3
        OPAQUE_MANAGED_OBJECT_STORE_CLIENT_KMIPv10               0x0000002b  1.3
        OPAQUE_MANAGED_OBJECT_STORE_CLIENT_KMIPv11               0x0000002c  1.3
        OPAQUE_MANAGED_OBJECT_STORE_CLIENT_KMIPv12               0x0000002d  1.3
        OPAQUE_MANAGED_OBJECT_STORE_SERVER_KMIPv10               0x0000002e  1.3
        OPAQUE_MANAGED_OBJECT_STORE_SERVER_KMIPv11               0x0000002f  1.3
        OPAQUE_MANAGED_OBJECT_STORE_SERVER_KMIPv12               0x00000030  1.3
        SUITE_B_MINLOS_128_CLIENT_KMIPv10                        0x00000031  1.3
        SUITE_B_MINLOS_128_CLIENT_KMIPv11                        0x00000032  1.3
        SUITE_B_MINLOS_128_CLIENT_KMIPv12                        0x00000033  1.3
        SUITE_B_MINLOS_128_SERVER_KMIPv10                        0x00000034  1.3
        SUITE_B_MINLOS_128_SERVER_KMIPv11                        0x00000035  1.3
        SUITE_B_MINLOS_128_SERVER_KMIPv12                        0x00000036  1.3
        SUITE_B_MINLOS_192_CLIENT_KMIPv10                        0x00000037  1.3
        SUITE_B_MINLOS_192_CLIENT_KMIPv11                        0x00000038  1.3
        SUITE_B_MINLOS_192_CLIENT_KMIPv12                        0x00000039  1.3
        SUITE_B_MINLOS_192_SERVER_KMIPv10                        0x0000003a  1.3
        SUITE_B_MINLOS_192_SERVER_KMIPv11                        0x0000003b  1.3
        SUITE_B_MINLOS_192_SERVER_KMIPv12                        0x0000003c  1.3
        STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_CLIENT_KMIPv10  0x0000003d  1.3
        STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_CLIENT_KMIPv11  0x0000003e  1.3
        STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_CLIENT_KMIPv12  0x0000003f  1.3
        STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_SERVER_KMIPv10  0x00000040  1.3
        STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_SERVER_KMIPv11  0x00000041  1.3
        STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_SERVER_KMIPv12  0x00000042  1.3
        HTTPS_CLIENT_KMIPv10                                     0x00000043  1.3
        HTTPS_CLIENT_KMIPv11                                     0x00000044  1.3
        HTTPS_CLIENT_KMIPv12                                     0x00000045  1.3
        HTTPS_SERVER_KMIPv10                                     0x00000046  1.3
        HTTPS_SERVER_KMIPv11                                     0x00000047  1.3
        HTTPS_SERVER_KMIPv12                                     0x00000048  1.3
        JSON_CLIENT_KMIPv10                                      0x00000049  1.3
        JSON_CLIENT_KMIPv11                                      0x0000004a  1.3
        JSON_CLIENT_KMIPv12                                      0x0000004b  1.3
        JSON_SERVER_KMIPv10                                      0x0000004c  1.3
        JSON_SERVER_KMIPv11                                      0x0000004d  1.3
        JSON_SERVER_KMIPv12                                      0x0000004e  1.3
        XML_CLIENT_KMIPv10                                       0x0000004f  1.3
        XML_CLIENT_KMIPv11                                       0x00000050  1.3
        XML_CLIENT_KMIPv12                                       0x00000051  1.3
        XML_SERVER_KMIPv10                                       0x00000052  1.3
        XML_SERVER_KMIPv11                                       0x00000053  1.3
        XML_SERVER_KMIPv12                                       0x00000054  1.3
        BASELINE_SERVER_BASIC_KMIPv13                            0x00000055  1.3
        BASELINE_SERVER_TLSv12_KMIPv13                           0x00000056  1.3
        BASELINE_CLIENT_BASIC_KMIPv13                            0x00000057  1.3
        BASELINE_CLIENT_TLSv12_KMIPv13                           0x00000058  1.3
        COMPLETE_SERVER_BASIC_KMIPv13                            0x00000059  1.3
        COMPLETE_SERVER_TLSv12_KMIPv13                           0x0000005a  1.3
        TAPE_LIBRARY_CLIENT_KMIPv13                              0x0000005b  1.3
        TAPE_LIBRARY_SERVER_KMIPv13                              0x0000005c  1.3
        SYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv13                   0x0000005d  1.3
        SYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv13                   0x0000005e  1.3
        ASYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv13                  0x0000005f  1.3
        ASYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv13                  0x00000060  1.3
        BASIC_CRYPTOGRAPHIC_CLIENT_KMIPv13                       0x00000061  1.3
        BASIC_CRYPTOGRAPHIC_SERVER_KMIPv13                       0x00000062  1.3
        ADVANCED_CRYPTOGRAPHIC_CLIENT_KMIPv13                    0x00000063  1.3
        ADVANCED_CRYPTOGRAPHIC_SERVER_KMIPv13                    0x00000064  1.3
        RNG_CRYPTOGRAPHIC_CLIENT_KMIPv13                         0x00000065  1.3
        RNG_CRYPTOGRAPHIC_SERVER_KMIPv13                         0x00000066  1.3
        BASIC_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv13               0x00000067  1.3
        INTERMEDIATE_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv13        0x00000068  1.3
        ADVANCED_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv13            0x00000069  1.3
        SYMMETRIC_KEY_FOUNDRY_SERVER_KMIPv13                     0x0000006a  1.3
        OPAQUE_MANAGED_OBJECT_STORE_CLIENT_KMIPv13               0x0000006b  1.3
        OPAQUE_MANAGED_OBJECT_STORE_SERVER_KMIPv13               0x0000006c  1.3
        SUITE_B_MINLOS_128_CLIENT_KMIPv13                        0x0000006d  1.3
        SUITE_B_MINLOS_128_SERVER_KMIPv13                        0x0000006e  1.3
        SUITE_B_MINLOS_192_CLIENT_KMIPv13                        0x0000006f  1.3
        SUITE_B_MINLOS_192_SERVER_KMIPv13                        0x00000070  1.3
        STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_CLIENT_KMIPv13  0x00000071  1.3
        STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_SERVER_KMIPv13  0x00000072  1.3
        HTTPS_CLIENT_KMIPv13                                     0x00000073  1.3
        HTTPS_SERVER_KMIPv13                                     0x00000074  1.3
        JSON_CLIENT_KMIPv13                                      0x00000075  1.3
        JSON_SERVER_KMIPv13                                      0x00000076  1.3
        XML_CLIENT_KMIPv13                                       0x00000077  1.3
        XML_SERVER_KMIPv13                                       0x00000078  1.3
        BASELINE_SERVER_BASIC_KMIPv14                            0x00000079  1.4
        BASELINE_SERVER_TLSv12_KMIPv14                           0x0000007a  1.4
        BASELINE_CLIENT_BASIC_KMIPv14                            0x0000007b  1.4
        BASELINE_CLIENT_TLSv12_KMIPv14                           0x0000007c  1.4
        COMPLETE_SERVER_BASIC_KMIPv14                            0x0000007d  1.4
        COMPLETE_SERVER_TLSv12_KMIPv14                           0x0000007e  1.4
        TAPE_LIBRARY_CLIENT_KMIPv14                              0x0000007f  1.4
        TAPE_LIBRARY_SERVER_KMIPv14                              0x00000080  1.4
        SYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv14                   0x00000081  1.4
        SYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv14                   0x00000082  1.4
        ASYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv14                  0x00000083  1.4
        ASYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv14                  0x00000084  1.4
        BASIC_CRYPTOGRAPHIC_CLIENT_KMIPv14                       0x00000085  1.4
        BASIC_CRYPTOGRAPHIC_SERVER_KMIPv14                       0x00000086  1.4
        ADVANCED_CRYPTOGRAPHIC_CLIENT_KMIPv14                    0x00000087  1.4
        ADVANCED_CRYPTOGRAPHIC_SERVER_KMIPv14                    0x00000088  1.4
        RNG_CRYPTOGRAPHIC_CLIENT_KMIPv14                         0x00000089  1.4
        RNG_CRYPTOGRAPHIC_SERVER_KMIPv14                         0x0000008a  1.4
        BASIC_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv14               0x0000008b  1.4
        INTERMEDIATE_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv14        0x0000008c  1.4
        ADVANCED_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv14            0x0000008d  1.4
        SYMMETRIC_KEY_FOUNDRY_SERVER_KMIPv14                     0x0000008e  1.4
        OPAQUE_MANAGED_OBJECT_STORE_CLIENT_KMIPv14               0x0000008f  1.4
        OPAQUE_MANAGED_OBJECT_STORE_SERVER_KMIPv14               0x00000090  1.4
        SUITE_B_MINLOS_128_CLIENT_KMIPv14                        0x00000091  1.4
        SUITE_B_MINLOS_128_SERVER_KMIPv14                        0x00000092  1.4
        SUITE_B_MINLOS_192_CLIENT_KMIPv14                        0x00000093  1.4
        SUITE_B_MINLOS_192_SERVER_KMIPv14                        0x00000094  1.4
        STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_CLIENT_KMIPv14  0x00000095  1.4
        STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_SERVER_KMIPv14  0x00000096  1.4
        HTTPS_CLIENT_KMIPv14                                     0x00000097  1.4
        HTTPS_SERVER_KMIPv14                                     0x00000098  1.4
        JSON_CLIENT_KMIPv14                                      0x00000099  1.4
        JSON_SERVER_KMIPv14                                      0x0000009a  1.4
        XML_CLIENT_KMIPv14                                       0x0000009b  1.4
        XML_SERVER_KMIPv14                                       0x0000009c  1.4
        COMPLETE_SERVER_BASIC                                    0x00000104  2.0
        COMPLETE_SERVER_TLSv12                                   0x00000105  2.0
        TAPE_LIBRARY_CLIENT                                      0x00000106  2.0
        TAPE_LIBRARY_SERVER                                      0x00000107  2.0
        SYMMETRIC_KEY_LIFECYCLE_CLIENT                           0x00000108  2.0
        SYMMETRIC_KEY_LIFECYCLE_SERVER                           0x00000109  2.0
        ASYMMETRIC_KEY_LIFECYCLE_CLIENT                          0x0000010A  2.0
        ASYMMETRIC_KEY_LIFECYCLE_SERVER                          0x0000010B  2.0
        BASIC_CRYPTOGRAPHIC_CLIENT                               0x0000010C  2.0
        BASIC_CRYPTOGRAPHIC_SERVER                               0x0000010D  2.0
        ADVANCED_CRYPTOGRAPHIC_CLIENT                            0x0000010E  2.0
        ADVANCED_CRYPTOGRAPHIC_SERVER                            0x0000010F  2.0
        RNG_CRYPTOGRAPHIC_CLIENT                                 0x00000110  2.0
        RNG_CRYPTOGRAPHIC_SERVER                                 0x00000111  2.0
        BASIC_SYMMETRIC_KEY_FOUNDRY_CLIENT                       0x00000112  2.0
        INTERMEDIATE_SYMMETRIC_KEY_FOUNDRY_CLIENT                0x00000113  2.0
        ADVANCED_SYMMETRIC_KEY_FOUNDRY_CLIENT                    0x00000114  2.0
        SYMMETRIC_KEY_FOUNDRY_SERVER                             0x00000115  2.0
        OPAQUE_MANAGED_OBJECT_STORE_CLIENT                       0x00000116  2.0
        OPAQUE_MANAGED_OBJECT_STORE_SERVER                       0x00000117  2.0
        SUITE_B_MINLOS_128_CLIENT                                0x00000118  2.0
        SUITE_B_MINLOS_128_SERVER                                0x00000119  2.0
        SUITE_B_MINLOS_192_CLIENT                                0x0000011A  2.0
        SUITE_B_MINLOS_192_SERVER                                0x0000011B  2.0
        STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_CLIENT          0x0000011C  2.0
        STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_SERVER          0x0000011D  2.0
        HTTPS_CLIENT                                             0x0000011E  2.0
        HTTPS_SERVER                                             0x0000011F  2.0
        JSON_CLIENT                                              0x00000120  2.0
        JSON_SERVER                                              0x00000121  2.0
        XML_CLIENT                                               0x00000122  2.0
        XML_SERVER                                               0x00000123  2.0
        AES_XTS_CLIENT                                           0x00000124  2.0
        AES_XTS_SERVER                                           0x00000125  2.0
        QUANTUM_SAFE_CLIENT                                      0x00000126  2.0
        QUANTUM_SAFE_SERVER                                      0x00000127  2.0
        PKCS11_CLIENT                                            0x00000128  2.0
        PKCS11_SERVER                                            0x00000129  2.0
        BASELINE_CLIENT                                          0x0000012A  2.0
        BASELINE_SERVER                                          0x0000012B  2.0
        COMPLETE_SERVER                                          0x0000012C  2.0
        =======================================================  ==========  ============

    profile_version
        (dict) (2.0) A dictionary containing the major and minor version
        numbers of a KMIP profile. Often used with the :term:`profile_information`
        structure.

        >>> profile_version = {
        ...     'profile_version_major': 1,
        ...     'profile_version_minor': 0
        ... }

        =====================  =======  ============
        Key                    Value    KMIP Version
        =====================  =======  ============
        profile_version_major  int      2.0
        profile_version_minor  int      2.0
        =====================  =======  ============

    put_function
        (enum) (1.0) An enumeration specifying the state of an object being
        pushed by the Put operation.

        >>> from kmip import enums
        >>> enums.PutFunction.NEW
        <PutFunction.NEW: 1>

        =======  ==========  ============
        Name     Value       KMIP Version
        =======  ==========  ============
        NEW      0x00000001  1.0
        REPLACE  0x00000002  1.0
        =======  ==========  ============

    query_function
        (enum) (1.0) An enumeration specifying the information to include in
        a Query operation response.

        >>> from kmip import enums
        >>> enums.QueryFunction.QUERY_OPERATIONS
        <QueryFunction.QUERY_OPERATIONS: 1>

        =================================  ==========  ============
        Name                               Value       KMIP Version
        =================================  ==========  ============
        QUERY_OPERATIONS                   0x00000001  1.0
        QUERY_OBJECTS                      0x00000002  1.0
        QUERY_SERVER_INFORMATION           0x00000003  1.0
        QUERY_APPLICATION_NAMESPACES       0x00000004  1.0
        QUERY_EXTENSION_LIST               0x00000005  1.1
        QUERY_EXTENSION_MAP                0x00000006  1.1
        QUERY_ATTESTATION_TYPES            0x00000007  1.2
        QUERY_RNGS                         0x00000008  1.3
        QUERY_VALIDATIONS                  0x00000009  1.3
        QUERY_PROFILES                     0x0000000a  1.3
        QUERY_CAPABILITIES                 0x0000000b  1.3
        QUERY_CLIENT_REGISTRATION_METHODS  0x0000000c  1.3
        QUERY_DEFAULTS_INFORMATION         0x0000000D  2.0
        QUERY_STORAGE_PROTECTION_MASKS     0x0000000E  2.0
        =================================  ==========  ============

    recommended_curve
        (enum) (1.0) An enumeration specifying a recommended curve for an
        elliptic curve algorithm. Used often as an asymmetric key value
        attribute.

        >>> from kmip import enums
        >>> enums.RecommendedCurve.P_192
        <RecommendedCurve.P_192: 1>

        ================  ==========  ============
        Name              Value       KMIP Version
        ================  ==========  ============
        P_192             0x00000001  1.0
        K_163             0x00000002  1.0
        B_163             0x00000003  1.0
        P_224             0x00000004  1.0
        K_233             0x00000005  1.0
        B_233             0x00000006  1.0
        P_256             0x00000007  1.0
        K_283             0x00000008  1.0
        B_283             0x00000009  1.0
        P_384             0x0000000a  1.0
        K_409             0x0000000b  1.0
        B_409             0x0000000c  1.0
        P_521             0x0000000d  1.0
        K_571             0x0000000e  1.0
        B_571             0x0000000f  1.0
        SECP112R1         0x00000010  1.2
        SECP112R2         0x00000011  1.2
        SECP128R1         0x00000012  1.2
        SECP128R2         0x00000013  1.2
        SECP160K1         0x00000014  1.2
        SECP160R1         0x00000015  1.2
        SECP160R2         0x00000016  1.2
        SECP191K1         0x00000017  1.2
        SECP224K1         0x00000018  1.2
        SECP256K1         0x00000019  1.2
        SECT113R1         0x0000001a  1.2
        SECT113R2         0x0000001b  1.2
        SECT131R1         0x0000001c  1.2
        SECT131R2         0x0000001d  1.2
        SECT163R1         0x0000001e  1.2
        SECT193R1         0x0000001f  1.2
        SECT193R2         0x00000020  1.2
        SECT239K1         0x00000021  1.2
        ANSIX9P192V2      0x00000022  1.2
        ANSIX9P192V3      0x00000023  1.2
        ANSIX9P239V1      0x00000024  1.2
        ANSIX9P239V2      0x00000025  1.2
        ANSIX9P239V3      0x00000026  1.2
        ANSIX9C2PNB163V1  0x00000027  1.2
        ANSIX9C2PNB163V2  0x00000028  1.2
        ANSIX9C2PNB163V3  0x00000029  1.2
        ANSIX9C2PNB176V1  0x0000002a  1.2
        ANSIX9C2TNB191V1  0x0000002b  1.2
        ANSIX9C2TNB191V2  0x0000002c  1.2
        ANSIX9C2TNB191V3  0x0000002d  1.2
        ANSIX9C2PNB208W1  0x0000002e  1.2
        ANSIX9C2TNB239V1  0x0000002f  1.2
        ANSIX9C2TNB239V2  0x00000030  1.2
        ANSIX9C2TNB239V3  0x00000031  1.2
        ANSIX9C2PNB272W1  0x00000032  1.2
        ANSIX9C2PNB304W1  0x00000033  1.2
        ANSIX9C2TNB359V1  0x00000034  1.2
        ANSIX9C2PNB368W1  0x00000035  1.2
        ANSIX9C2TNB431R1  0x00000036  1.2
        BRAINPOOLP160R1   0x00000037  1.2
        BRAINPOOLP160T1   0x00000038  1.2
        BRAINPOOLP192R1   0x00000039  1.2
        BRAINPOOLP192T1   0x0000003a  1.2
        BRAINPOOLP224R1   0x0000003b  1.2
        BRAINPOOLP224T1   0x0000003c  1.2
        BRAINPOOLP256R1   0x0000003d  1.2
        BRAINPOOLP256T1   0x0000003e  1.2
        BRAINPOOLP320R1   0x0000003f  1.2
        BRAINPOOLP320T1   0x00000040  1.2
        BRAINPOOLP384R1   0x00000041  1.2
        BRAINPOOLP384T1   0x00000042  1.2
        BRAINPOOLP512R1   0x00000043  1.2
        BRAINPOOLP512T1   0x00000044  1.2
        CURVE25519        0x00000045  2.0
        CURVE448          0x00000046  2.0
        ================  ==========  ============

    result_reason
        (enum) (1.0) An enumeration specifying the reason for the result
        status of an operation. Used usually if an operation results in a
        failure.

        >>> from kmip import enums
        >>> enums.ResultReason.ITEM_NOT_FOUND
        <ResultReason.ITEM_NOT_FOUND: 1>

        ======================================  ==========  ============
        Name                                    Value       KMIP Version
        ======================================  ==========  ============
        ITEM_NOT_FOUND                          0x00000001  1.0
        RESPONSE_TOO_LARGE                      0x00000002  1.0
        AUTHENTICATION_NOT_SUCCESSFUL           0x00000003  1.0
        INVALID_MESSAGE                         0x00000004  1.0
        OPERATION_NOT_SUPPORTED                 0x00000005  1.0
        MISSING_DATA                            0x00000006  1.0
        INVALID_FIELD                           0x00000007  1.0
        FEATURE_NOT_SUPPORTED                   0x00000008  1.0
        OPERATION_CANCELED_BY_REQUESTER         0x00000009  1.0
        CRYPTOGRAPHIC_FAILURE                   0x0000000a  1.0
        ILLEGAL_OPERATION                       0x0000000b  1.0
        PERMISSION_DENIED                       0x0000000c  1.0
        OBJECT_ARCHIVED                         0x0000000d  1.0
        INDEX_OUT_OF_BOUNDS                     0x0000000e  1.0
        APPLICATION_NAMESPACE_NOT_SUPPORTED     0x0000000f  1.0
        KEY_FORMAT_TYPE_NOT_SUPPORTED           0x00000010  1.0
        KEY_COMPRESSION_TYPE_NOT_SUPPORTED      0x00000011  1.0
        ENCODING_OPTION_ERROR                   0x00000012  1.1
        KEY_VALUE_NOT_PRESENT                   0x00000013  1.2
        ATTESTATION_REQUIRED                    0x00000014  1.2
        ATTESTATION_FAILED                      0x00000015  1.2
        SENSITIVE                               0x00000016  1.4
        NOT_EXTRACTABLE                         0x00000017  1.4
        OBJECT_ALREADY_EXISTS                   0x00000018  1.4
        INVALID_TICKET                          0x00000019  2.0
        USAGE_LIMIT_EXCEEDED                    0x0000001A  2.0
        NUMERIC_RANGE                           0x0000001B  2.0
        INVALID_DATA_TYPE                       0x0000001C  2.0
        READ_ONLY_ATTRIBUTE                     0x0000001D  2.0
        MULTI_VALUED_ATTRIBUTE                  0x0000001E  2.0
        UNSUPPORTED_ATTRIBUTE                   0x0000001F  2.0
        ATTRIBUTE_INSTANCE_NOT_FOUND            0x00000020  2.0
        ATTRIBUTE_NOT_FOUND                     0x00000021  2.0
        ATTRIBUTE_READ_ONLY                     0x00000022  2.0
        ATTRIBUTE_SINGLE_VALUED                 0x00000023  2.0
        BAD_CRYPTOGRAPHIC_PARAMETERS            0x00000024  2.0
        BAD_PASSWORD                            0x00000025  2.0
        CODEC_ERROR                             0x00000026  2.0
        ILLEGAL_OBJECT_TYPE                     0x00000028  2.0
        INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK   0x00000029  2.0
        INTERNAL_SERVER_ERROR                   0x0000002A  2.0
        INVALID_ASYNCHRONOUS_CORRELATION_VALUE  0x0000002B  2.0
        INVALID_ATTRIBUTE                       0x0000002C  2.0
        INVALID_ATTRIBUTE_VALUE                 0x0000002D  2.0
        INVALID_CORRELATION_VALUE               0x0000002E  2.0
        INVALID_CSR                             0x0000002F  2.0
        INVALID_OBJECT_TYPE                     0x00000030  2.0
        KEY_WRAP_TYPE_NOT_SUPPORTED             0x00000032  2.0
        MISSING_INITIALIZATION_VECTOR           0x00000034  2.0
        NON_UNIQUE_NAME_ATTRIBUTE               0x00000035  2.0
        OBJECT_DESTROYED                        0x00000036  2.0
        OBJECT_NOT_FOUND                        0x00000037  2.0
        NOT_AUTHORISED                          0x00000039  2.0
        SERVER_LIMIT_EXCEEDED                   0x0000003A  2.0
        UNKNOWN_ENUMERATION                     0x0000003B  2.0
        UNKNOWN_MESSAGE_EXTENSION               0x0000003C  2.0
        UNKNOWN_TAG                             0x0000003D  2.0
        UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS    0x0000003E  2.0
        UNSUPPORTED_PROTOCOL_VERSION            0x0000003F  2.0
        WRAPPING_OBJECT_ARCHIVED                0x00000040  2.0
        WRAPPING_OBJECT_DESTROYED               0x00000041  2.0
        WRAPPING_OBJECT_NOT_FOUND               0x00000042  2.0
        WRONG_KEY_LIFECYCLE_STATE               0x00000043  2.0
        PROTECTION_STORAGE_UNAVAILABLE          0x00000044  2.0
        PKCS11_CODEC_ERROR                      0x00000045  2.0
        PKCS11_INVALID_FUNCTION                 0x00000046  2.0
        PKCS11_INVALID_INTERFACE                0x00000047  2.0
        GENERAL_FAILURE                         0x00000100  1.0
        ======================================  ==========  ============

    result_status
        (enum) (1.0) An enumeration specifying the result of an operation.
        Used in every operation response.

        >>> from kmip import enums
        >>> enums.ResultStatus.OPERATION_FAILED
        <ResultStatus.OPERATION_FAILED: 1>

        =================  ==========  ============
        Name               Value       KMIP Version
        =================  ==========  ============
        SUCCESS            0x00000000  1.0
        OPERATION_FAILED   0x00000001  1.0
        OPERATION_PENDING  0x00000002  1.0
        OPERATION_UNDONE   0x00000003  1.0
        =================  ==========  ============

    revocation_reason_code
        (enum) (1.0) An enumeration specifying the reason for the revocation
        of a managed object.

        >>> from kmip import enums
        >>> enums.RevocationReasonCode.KEY_COMPROMISE
        <RevocationReasonCode.KEY_COMPROMISE: 2>

        ======================  ==========  ============
        Name                    Value       KMIP Version
        ======================  ==========  ============
        UNSPECIFIED             0x00000001  1.0
        KEY_COMPROMISE          0x00000002  1.0
        CA_COMPROMISE           0x00000003  1.0
        AFFILIATION_CHANGED     0x00000004  1.0
        SUPERSEDED              0x00000005  1.0
        CESSATION_OF_OPERATION  0x00000006  1.0
        PRIVILEGE_WITHDRAWN     0x00000007  1.0
        ======================  ==========  ============

    rng_algorithm
        (enum) (1.3) An enumeration specifying an algorithm for random number
        generation. Used often to describe a random number generator.

        >>> from kmip import enums
        >>> enums.RNGAlgorithm.DRBG
        <RNGAlgorithm.DRBG: 3>

        ===========  ==========  ============
        Name         Value       KMIP Version
        ===========  ==========  ============
        UNSPECIFIED  0x00000001  1.3
        FIPS186_2    0x00000002  1.3
        DRBG         0x00000003  1.3
        NRBG         0x00000004  1.3
        ANSI_X931    0x00000005  1.3
        ANSI_X962    0x00000006  1.3
        ===========  ==========  ============

    rng_mode
        (enum) (1.3) An enumeration specifying the mode for random number
        generation. Used often to describe a random number generator.

        >>> from kmip import enums
        >>> enums.RNGMode.SHARED_INSTANTIATION
        <RNGMode.SHARED_INSTANTIATION: 2>

        ========================  ==========  ============
        Name                      Value       KMIP Version
        ========================  ==========  ============
        UNSPECIFIED               0x00000001  1.3
        SHARED_INSTANTIATION      0x00000002  1.3
        NON_SHARED_INSTANTIATION  0x00000003  1.3
        ========================  ==========  ============

    rng_parameters
        (dict) (1.3) A dictionary containing information about a random
        number generator supported by a KMIP server. Often obtained from the
        Query operation response.

        >>> from kmip import enums
        >>> rng_parameters = {
        ...     'rng_algorithm': enums.RNGAlgorithm.ANSI_X931,
        ...     'cryptographic_algorithm': enums.CryptographicAlgorithm.AES,
        ...     'cryptographic_length': 256,
        ...     'hashing_algorithm': enums.HashingAlgorithm.SHA_256,
        ...     'drbg_algorithm': enums.DRBGAlgorithm.HASH,
        ...     'recommended_curve': enums.RecommendedCurve.B_163,
        ...     'fips186_variation': enums.FIPS186Variation.X_ORIGINAL,
        ...     'prediction_resistance': True
        ... }

        ===============================  =======  ============
        Key                              Value    KMIP Version
        ===============================  =======  ============
        :term:`rng_algorithm`            enum     1.3
        :term:`cryptographic_algorithm`  enum     1.3
        :term:`cryptographic_length`     int      1.3
        :term:`hashing_algorithm`        enum     1.3
        :term:`drbg_algorithm`           enum     1.3
        :term:`recommended_curve`        enum     1.3
        :term:`fips186_variation`        enum     1.3
        prediction_resistance            bool     1.3
        ===============================  =======  ============

    secret_data_type
        (enum) (1.0) An enumeration specifying the type of a secret data
        object.

        >>> from kmip import enums
        >>> enums.SecretDataType.PASSWORD
        <SecretDataType.PASSWORD: 1>

        ========  ==========  ============
        Name      Value       KMIP Version
        ========  ==========  ============
        PASSWORD  0x00000001  1.0
        SEED      0x00000002  1.0
        ========  ==========  ============

    server_information
        (str) (1.0) A string containing additional information on the vendor
        associated with a KMIP appliance. Often obtained with the Query
        operation.

    shredding_algorithm
        (enum) (1.3) An enumeration specifying the type of shredding
        algorithm supported by a key server. Used often as part of the
        response to a Query request.

        >>> from kmip import enums
        >>> enums.ShreddingAlgorithm.CRYPTOGRAPHIC
        <ShreddingAlgorithm.CRYPTOGRAPHIC: 2>

        =============  ==========  ============
        Name           Value       KMIP Version
        =============  ==========  ============
        UNSPECIFIED    0x00000001  1.3
        CRYPTOGRAPHIC  0x00000002  1.3
        UNSUPPORTED    0x00000003  1.3
        =============  ==========  ============

    split_key_method
        (enum) (1.0) An enumeration specifying the method used to split a key.
        Used as an attribute for split key objects and as a parameter to the
        CreateSplitKey operation.

        >>> from kmip import enums
        >>> enums.SplitKeyMethod.XOR
        <SplitKeyMethod.XOR: 1>

        ==============================  ==========  ============
        Name                            Value       KMIP Version
        ==============================  ==========  ============
        XOR                             0x00000001  1.0
        POLYNOMIAL_SHARING_GF_2_16      0x00000002  1.0
        POLYNOMIAL_SHARING_PRIME_FIELD  0x00000003  1.0
        POLYNOMIAL_SHARING_GF_2_8       0x00000004  1.2
        ==============================  ==========  ============

    state
        (enum) (1.0) An enumeration specifying the state of a managed object.
        Used as an attribute for every managed object on a key server.

        >>> from kmip import enums
        >>> enums.State.ACTIVE
        <State.ACTIVE: 2>

        =====================  ==========  ============
        Name                   Value       KMIP Version
        =====================  ==========  ============
        PRE_ACTIVE             0x00000001  1.0
        ACTIVE                 0x00000002  1.0
        DEACTIVATED            0x00000003  1.0
        COMPROMISED            0x00000004  1.0
        DESTROYED              0x00000005  1.0
        DESTROYED_COMPROMISED  0x00000006  1.0
        =====================  ==========  ============

    storage_status
        (enum) (1.0) An enumeration specifying the state of a stored object.
        Used as a filter for the Locate operation.

        >>> from kmip import enums
        >>> enums.StorageStatus.ARCHIVAL_STORAGE
        <StorageStatus.ARCHIVAL_STORAGE: 2>

        =================  ==========  ============
        Name               Value       KMIP Version
        =================  ==========  ============
        ONLINE_STORAGE     0x00000001  1.0
        ARCHIVAL_STORAGE   0x00000002  1.0
        DESTROYED_STORAGE  0x00000004  2.0
        =================  ==========  ============

    unique_identifier
        (str) (1.0) A string representing a unique, global identifier for a
        managed object created or registered with a key management appliance.
        Each managed object is represented by one unique identifier, which
        can be used in a variety of operations to access the object or the
        object metadata. This identifier is assigned when the object is first
        created or registered and cannot be changed.

    unwrap_mode
        (enum) (1.3) An enumeration specifying an unwrapping mode supported
        by the server. Used often as part of the response to a Query
        request.

        >>> from kmip import enums
        >>> enums.UnwrapMode.PROCESSED
        <UnwrapMode.PROCESSED: 2>

        =============  ==========  ============
        Name           Value       KMIP Version
        =============  ==========  ============
        UNSPECIFIED    0x00000001  1.3
        PROCESSED      0x00000002  1.3
        NOT_PROCESSED  0x00000003  1.3
        =============  ==========  ============

    usage_limits_unit
        (enum) (1.0) An enumeration specifying the units for a usage limit on
        a managed object.

        >>> from kmip import enums
        >>> enums.UsageLimitsUnit.BYTE
        <UsageLimitsUnit.BYTE: 1>

        ======  ==========  ============
        Name    Value       KMIP Version
        ======  ==========  ============
        BYTE    0x00000001  1.0
        OBJECT  0x00000002  1.0
        ======  ==========  ============

    validation_authority_type
        (enum) (1.3) An enumeration specifying a validation authority type
        supported by the server. Used often as part of the response to a
        Query request.

        >>> from kmip import enums
        >>> enums.ValidationAuthorityType.COMMON_CRITERIA
        <ValidationAuthorityType.COMMON_CRITERIA: 3>

        ===============  ==========  ============
        Name             Value       KMIP Version
        ===============  ==========  ============
        UNSPECIFIED      0x00000001  1.3
        NIST_CMVP        0x00000002  1.3
        COMMON_CRITERIA  0x00000003  1.3
        ===============  ==========  ============

    validation_information
        (dict) (1.3) A dictionary containing information about a formal
        validation. Often obtained from the Query operation response.

        >>> from kmip import enums
        >>> validation_information = {
        ...     'validation_authority_type': enums.ValidationAuthorityType.COMMON_CRITERIA,
        ...     'validation_authority_country': 'US',
        ...     'validation_profile': [
        ...         'Example Profile 1',
        ...         'Example Profile 2'
        ...     ]
        ... }

        =================================  =======  ============
        Key                                Value    KMIP Version
        =================================  =======  ============
        :term:`validation_authority_type`  enum     1.3
        validation_authority_country       string   1.3
        validation_authority_uri           string   1.3
        validation_version_major           int      1.3
        validation_version_minor           int      1.3
        :term:`validation_type`            enum     1.3
        validation_level                   int      1.3
        validation_certificate_identifier  string   1.3
        validation_certificate_uri         string   1.3
        validation_vendor_uri              string   1.3
        validation_profile                 list     1.3
        =================================  =======  ============

    validation_type
        (enum) (1.3) An enumeration specifying a validation type supported by
        the server. Used often as part of the response to a Query request.

        >>> from kmip import enums
        >>> enums.ValidationType.HARDWARE
        <ValidationType.HARDWARE: 2>

        ===========  ==========  ============
        Name         Value       KMIP Version
        ===========  ==========  ============
        UNSPECIFIED  0x00000001  1.3
        HARDWARE     0x00000002  1.3
        SOFTWARE     0x00000003  1.3
        FIRMWARE     0x00000004  1.3
        HYBRID       0x00000005  1.3
        ===========  ==========  ============

    validity_indicator
        (enum) (1.0) An enumeration specifying the validity of an operation or
        object. Used as a return value for various operations.

        >>> from kmip import enums
        >>> enums.ValidityIndicator.VALID
        <ValidityIndicator.VALID: 1>

        =======  ==========  ============
        Name     Value       KMIP Version
        =======  ==========  ============
        VALID    0x00000001  1.0
        INVALID  0x00000002  1.0
        UNKNOWN  0x00000003  1.0
        =======  ==========  ============

    vendor_identification
        (str) (1.0) A string containing identification information on the
        vendor associated with a KMIP appliance. Often obtained with the Query
        operation.

    wrapping_method
        (enum) (1.0) An enumeration representing a key wrapping mechanism.
        Used in various key wrapping metadata structures.

        >>> from kmip import enums
        >>> enums.WrappingMethod.ENCRYPT
        <WrappingMethod.ENCRYPT: 1>

        =====================  ==========  ============
        Name                   Value       KMIP Version
        =====================  ==========  ============
        ENCRYPT                0x00000001  1.0
        MAC_SIGN               0x00000002  1.0
        ENCRYPT_THEN_MAC_SIGN  0x00000003  1.0
        MAC_SIGN_THEN_ENCRYPT  0x00000004  1.0
        TR_31                  0x00000005  1.0
        =====================  ==========  ============
