# Copyright (c) 2014 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# In case of new content, remove the following line to enable flake8 tests
# flake8: noqa

import enum


class AttributeType(enum.Enum):
    """
    The name identifier of a managed object attribute.

    The attribute type is the name of a specific attribute that can be
    associated with a managed object. Every attribute contains this name in
    addition to the actual attribute value. This enumeration is primarily used
    to automatically map between attribute object encodings and the actual
    attribute structures that are used to store the attribute data.
    """
    UNIQUE_IDENTIFIER                = 'Unique Identifier'
    NAME                             = 'Name'
    OBJECT_TYPE                      = 'Object Type'
    CRYPTOGRAPHIC_ALGORITHM          = 'Cryptographic Algorithm'
    CRYPTOGRAPHIC_LENGTH             = 'Cryptographic Length'
    CRYPTOGRAPHIC_PARAMETERS         = 'Cryptographic Parameters'
    CRYPTOGRAPHIC_DOMAIN_PARAMETERS  = 'Cryptographic Domain Parameters'
    CERTIFICATE_TYPE                 = 'Certificate Type'
    CERTIFICATE_LENGTH               = 'Certificate Length'
    X_509_CERTIFICATE_IDENTIFIER     = 'X.509 Certificate Identifier'
    X_509_CERTIFICATE_SUBJECT        = 'X.509 Certificate Subject'
    X_509_CERTIFICATE_ISSUER         = 'X.509 Certificate Issuer'
    CERTIFICATE_IDENTIFIER           = 'Certificate Identifier'
    CERTIFICATE_SUBJECT              = 'Certificate Subject'
    CERTIFICATE_ISSUER               = 'Certificate Issuer'
    DIGITAL_SIGNATURE_ALGORITHM      = 'Digital Signature Algorithm'
    DIGEST                           = 'Digest'
    OPERATION_POLICY_NAME            = 'Operation Policy Name'
    CRYPTOGRAPHIC_USAGE_MASK         = 'Cryptographic Usage Mask'
    LEASE_TIME                       = 'Lease Time'
    USAGE_LIMITS                     = 'Usage Limits'
    STATE                            = 'State'
    INITIAL_DATE                     = 'Initial Date'
    ACTIVATION_DATE                  = 'Activation Date'
    PROCESS_START_DATE               = 'Process Start Date'
    PROTECT_STOP_DATE                = 'Protect Stop Date'
    DEACTIVATION_DATE                = 'Deactivation Date'
    DESTROY_DATE                     = 'Destroy Date'
    COMPROMISE_OCCURRENCE_DATE       = 'Compromise Occurrence Date'
    COMPROMISE_DATE                  = 'Compromise Date'
    REVOCATION_REASON                = 'Revocation Reason'
    ARCHIVE_DATE                     = 'Archive Date'
    OBJECT_GROUP                     = 'Object Group'
    FRESH                            = 'Fresh'
    LINK                             = 'Link'
    APPLICATION_SPECIFIC_INFORMATION = 'Application Specific Information'
    CONTACT_INFORMATION              = 'Contact Information'
    LAST_CHANGE_DATE                 = 'Last Change Date'
    CUSTOM_ATTRIBUTE                 = 'Custom Attribute'


class ConformanceClause(enum.Enum):
    """
    The specification of KMIP features supported by KMIP clients and servers.

    The conformance clause defines the KMIP objects and operations that need
    to be supported for a specific feature set. The clause is one of two core
    components that make up a KMIP client/server profile. For more information,
    see Section 5 of the KMIP 1.1 profiles document.
    """
    DISCOVER_VERSIONS                      = 1
    BASELINE                               = 2
    SECRET_DATA                            = 3
    SYMMETRIC_KEY_STORE                    = 4
    SYMMETRIC_KEY_FOUNDRY                  = 5
    ASYMMETRIC_KEY_STORE                   = 6
    ASYMMETRIC_KEY_AND_CERTIFICATE_STORE   = 7
    ASYMMETRIC_KEY_FOUNDRY                 = 8
    CERTIFICATE                            = 9
    ASYMMETRIC_KEY_FOUNDRY_AND_CERTIFICATE = 10
    STORAGE                                = 11


class AuthenticationSuite(enum.Enum):
    """
    The type of authentication suite used by KMIP clients and servers.

    The authentication suite defines the protocol versions and cipher suites
    that should be used to secure KMIP client/server communications. An
    authentication suite is one of two core components that make up a KMIP
    client/server profile. For more information, see Section 3 of the KMIP
    1.1 profiles document.
    """
    BASIC = 1
    TLS12 = 2


class Types(enum.Enum):
    """
    The unique identifier of an entity primitive type.

    The type is a unique identifier for every possible primitive KMIP entity
    defined by the KMIP specification. Every KMIP object is a form of KMIP
    primitive. The type is the second piece of an object that is encoded and
    decoded during serialization.

    While not defined by the specification, the DEFAULT tag is used as a
    default type identifier for testing purposes.
    """
    DEFAULT      = 0x00
    STRUCTURE    = 0x01
    INTEGER      = 0x02
    LONG_INTEGER = 0x03
    BIG_INTEGER  = 0x04
    ENUMERATION  = 0x05
    BOOLEAN      = 0x06
    TEXT_STRING  = 0x07
    BYTE_STRING  = 0x08
    DATE_TIME    = 0x09
    INTERVAL     = 0x0A


class Tags(enum.Enum):
    """
    The unique identifier of an entity type.

    The tag is a unique identifier for every possible KMIP entity defined by
    the KMIP specification. It is the first piece of an object that is encoded
    and decoded during serialization.

    While not defined by the specification, the DEFAULT tag is used as the
    default tag for all KMIP primitives.
    """
    DEFAULT                                = 0x420000
    ACTIVATION_DATE                        = 0x420001
    APPLICATION_DATA                       = 0x420002
    APPLICATION_NAMESPACE                  = 0x420003
    APPLICATION_SPECIFIC_INFORMATION       = 0x420004
    ARCHIVE_DATE                           = 0x420005
    ASYNCHRONOUS_CORRELATION_VALUE         = 0x420006
    ASYNCHRONOUS_INDICATOR                 = 0x420007
    ATTRIBUTE                              = 0x420008
    ATTRIBUTE_INDEX                        = 0x420009
    ATTRIBUTE_NAME                         = 0x42000A
    ATTRIBUTE_VALUE                        = 0x42000B
    AUTHENTICATION                         = 0x42000C
    BATCH_COUNT                            = 0x42000D
    BATCH_ERROR_CONTINUATION_OPTION        = 0x42000E
    BATCH_ITEM                             = 0x42000F
    BATCH_ORDER_OPTION                     = 0x420010
    BLOCK_CIPHER_MODE                      = 0x420011
    CANCELLATION_RESULT                    = 0x420012
    CERTIFICATE                            = 0x420013
    CERTIFICATE_IDENTIFIER                 = 0x420014  # DEPRECATED
    CERTIFICATE_ISSUER                     = 0x420015  # DEPRECATED
    CERTIFICATE_ISSUER_ALTERNATIVE_NAME    = 0x420016  # DEPRECATED
    CERTIFICATE_ISSUER_DISTINGUISHED_NAME  = 0x420017  # DEPRECATED
    CERTIFICATE_REQUEST                    = 0x420018
    CERTIFICATE_REQUEST_TYPE               = 0x420019
    CERTIFICATE_SUBJECT                    = 0x42001A  # DEPRECATED
    CERTIFICATE_SUBJECT_ALTERNATIVE_NAME   = 0x42001B  # DEPRECATED
    CERTIFICATE_SUBJECT_DISTINGUISHED_NAME = 0x42001C  # DEPRECATED
    CERTIFICATE_TYPE                       = 0x42001D
    CERTIFICATE_VALUE                      = 0x42001E
    COMMON_TEMPLATE_ATTRIBUTE              = 0x42001F
    COMPROMISE_DATE                        = 0x420020
    COMPROMISE_OCCURRENCE_DATE             = 0x420021
    CONTACT_INFORMATION                    = 0x420022
    CREDENTIAL                             = 0x420023
    CREDENTIAL_TYPE                        = 0x420024
    CREDENTIAL_VALUE                       = 0x420025
    CRITICALITY_INDICATOR                  = 0x420026
    CRT_COEFFICIENT                        = 0x420027
    CRYPTOGRAPHIC_ALGORITHM                = 0x420028
    CRYPTOGRAPHIC_DOMAIN_PARAMETERS        = 0x420029
    CRYPTOGRAPHIC_LENGTH                   = 0x42002A
    CRYPTOGRAPHIC_PARAMETERS               = 0x42002B
    CRYPTOGRAPHIC_USAGE_MASK               = 0x42002C
    CUSTOM_ATTRIBUTE                       = 0x42002D
    D                                      = 0x42002E
    DEACTIVATION_DATE                      = 0x42002F
    DERIVATION_DATA                        = 0x420030
    DERIVATION_METHOD                      = 0x420031
    DERIVATION_PARAMETERS                  = 0x420032
    DESTROY_DATE                           = 0x420033
    DIGEST                                 = 0x420034
    DIGEST_VALUE                           = 0x420035
    ENCRYPTION_KEY_INFORMATION             = 0x420036
    G                                      = 0x420037
    HASHING_ALGORITHM                      = 0x420038
    INITIAL_DATE                           = 0x420039
    INITIALIZATION_VECTOR                  = 0x42003A
    ISSUER                                 = 0x42003B  # DEPRECATED
    ITERATION_COUNT                        = 0x42003C
    IV_COUNTER_NONCE                       = 0x42003D
    J                                      = 0x42003E
    KEY                                    = 0x42003F
    KEY_BLOCK                              = 0x420040
    KEY_COMPRESSION_TYPE                   = 0x420041
    KEY_FORMAT_TYPE                        = 0x420042
    KEY_MATERIAL                           = 0x420043
    KEY_PART_IDENTIFIER                    = 0x420044
    KEY_VALUE                              = 0x420045
    KEY_WRAPPING_DATA                      = 0x420046
    KEY_WRAPPING_SPECIFICATION             = 0x420047
    LAST_CHANGE_DATE                       = 0x420048
    LEASE_TIME                             = 0x420049
    LINK                                   = 0x42004A
    LINK_TYPE                              = 0x42004B
    LINKED_OBJECT_IDENTIFIER               = 0x42004C
    MAC_SIGNATURE                          = 0x42004D
    MAC_SIGNATURE_KEY_INFORMATION          = 0x42004E
    MAXIMUM_ITEMS                          = 0x42004F
    MAXIMUM_RESPONSE_SIZE                  = 0x420050
    MESSAGE_EXTENSION                      = 0x420051
    MODULUS                                = 0x420052
    NAME                                   = 0x420053
    NAME_TYPE                              = 0x420054
    NAME_VALUE                             = 0x420055
    OBJECT_GROUP                           = 0x420056
    OBJECT_TYPE                            = 0x420057
    OFFSET                                 = 0x420058
    OPAQUE_DATA_TYPE                       = 0x420059
    OPAQUE_DATA_VALUE                      = 0x42005A
    OPAQUE_OBJECT                          = 0x42005B
    OPERATION                              = 0x42005C
    OPERATION_POLICY_NAME                  = 0x42005D
    P                                      = 0x42005E
    PADDING_METHOD                         = 0x42005F
    PRIME_EXPONENT_P                       = 0x420060
    PRIME_EXPONENT_Q                       = 0x420061
    PRIME_FIELD_SIZE                       = 0x420062
    PRIVATE_EXPONENT                       = 0x420063
    PRIVATE_KEY                            = 0x420064
    PRIVATE_KEY_TEMPLATE_ATTRIBUTE         = 0x420065
    PRIVATE_KEY_UNIQUE_IDENTIFIER          = 0x420066
    PROCESS_START_DATE                     = 0x420067
    PROTECT_STOP_DATE                      = 0x420068
    PROTOCOL_VERSION                       = 0x420069
    PROTOCOL_VERSION_MAJOR                 = 0x42006A
    PROTOCOL_VERSION_MINOR                 = 0x42006B
    PUBLIC_EXPONENT                        = 0x42006C
    PUBLIC_KEY                             = 0x42006D
    PUBLIC_KEY_TEMPLATE_ATTRIBUTE          = 0x42006E
    PUBLIC_KEY_UNIQUE_IDENTIFIER           = 0x42006F
    PUT_FUNCTION                           = 0x420070
    Q                                      = 0x420071
    Q_STRING                               = 0x420072
    QLENGTH                                = 0x420073
    QUERY_FUNCTION                         = 0x420074
    RECOMMENDED_CURVE                      = 0x420075
    REPLACED_UNIQUE_IDENTIFIER             = 0x420076
    REQUEST_BATCH_ITEM                     = 0x42000F
    REQUEST_HEADER                         = 0x420077
    REQUEST_MESSAGE                        = 0x420078
    REQUEST_PAYLOAD                        = 0x420079
    RESPONSE_BATCH_ITEM                    = 0x42000F
    RESPONSE_HEADER                        = 0x42007A
    RESPONSE_MESSAGE                       = 0x42007B
    RESPONSE_PAYLOAD                       = 0x42007C
    RESULT_MESSAGE                         = 0x42007D
    RESULT_REASON                          = 0x42007E
    RESULT_STATUS                          = 0x42007F
    REVOCATION_MESSAGE                     = 0x420080
    REVOCATION_REASON                      = 0x420081
    REVOCATION_REASON_CODE                 = 0x420082
    KEY_ROLE_TYPE                          = 0x420083
    SALT                                   = 0x420084
    SECRET_DATA                            = 0x420085
    SECRET_DATA_TYPE                       = 0x420086
    SERIAL_NUMBER                          = 0x420087  # DEPRECATED
    SERVER_INFORMATION                     = 0x420088
    SPLIT_KEY                              = 0x420089
    SPLIT_KEY_METHOD                       = 0x42008A
    SPLIT_KEY_PARTS                        = 0x42008B
    SPLIT_KEY_THRESHOLD                    = 0x42008C
    STATE                                  = 0x42008D
    STORAGE_STATUS_MASK                    = 0x42008E
    SYMMETRIC_KEY                          = 0x42008F
    TEMPLATE                               = 0x420090
    TEMPLATE_ATTRIBUTE                     = 0x420091
    TIME_STAMP                             = 0x420092
    UNIQUE_BATCH_ITEM_ID                   = 0x420093
    UNIQUE_IDENTIFIER                      = 0x420094
    USAGE_LIMITS                           = 0x420095
    USAGE_LIMITS_COUNT                     = 0x420096
    USAGE_LIMITS_TOTAL                     = 0x420097
    USAGE_LIMITS_UNIT                      = 0x420098
    USERNAME                               = 0x420099
    VALIDITY_DATE                          = 0x42009A
    VALIDITY_INDICATOR                     = 0x42009B
    VENDOR_EXTENSION                       = 0x42009C
    VENDOR_IDENTIFICATION                  = 0x42009D
    WRAPPING_METHOD                        = 0x42009E
    X                                      = 0x42009F
    Y                                      = 0x4200A0
    PASSWORD                               = 0x4200A1
    DEVICE_IDENTIFIER                      = 0x4200A2
    ENCODING_OPTION                        = 0x4200A3
    EXTENSION_INFORMATION                  = 0x4200A4
    EXTENSION_NAME                         = 0x4200A5
    EXTENSION_TAG                          = 0x4200A6
    EXTENSION_TYPE                         = 0x4200A7
    FRESH                                  = 0x4200A8
    MACHINE_IDENTIFIER                     = 0x4200A9
    MEDIA_IDENTIFIER                       = 0x4200AA
    NETWORK_IDENTIFIER                     = 0x4200AB
    OBJECT_GROUP_MEMBER                    = 0x4200AC
    CERTIFICATE_LENGTH                     = 0x4200AD
    DIGITAL_SIGNATURE_ALGORITHM            = 0x4200AE
    CERTIFICATE_SERIAL_NUMBER              = 0x4200AF
    DEVICE_SERIAL_NUMBER                   = 0x4200B0
    ISSUER_ALTERNATIVE_NAME                = 0x4200B1
    ISSUER_DISTINGUISHED_NAME              = 0x4200B2
    SUBJECT_ALTERNATIVE_NAME               = 0x4200B3
    SUBJECT_DISTINGUISHED_NAME             = 0x4200B4
    X_509_CERTIFICATE_IDENTIFER            = 0x4200B5
    X_509_CERTIFICATE_ISSUER               = 0x4200B6
    X_509_CERTIFICATE_SUBJECT              = 0x4200B7


class CredentialType(enum.Enum):
    """
    The type of a credential object.

    The credential type is a required attribute of a credential object. It
    identifies the format and structure of the value of the credential.
    """
    USERNAME_AND_PASSWORD = 0x00000001
    DEVICE                = 0x00000002


class KeyCompressionType(enum.Enum):
    """
    The technique used to compress an elliptic curve public key.

    The key compression type is an attribute of a key block structure. If it
    is omitted, it is inferred that the related public key is uncompressed.
    """
    EC_PUBLIC_KEY_TYPE_UNCOMPRESSED           = 0x00000001
    EC_PUBLIC_KEY_TYPE_X9_62_COMPRESSED_PRIME = 0x00000002
    EC_PUBLIC_KEY_TYPE_X9_62_COMPRESSED_CHAR2 = 0x00000003
    EC_PUBLIC_KEY_TYPE_X9_62_HYBRID           = 0x00000004


class KeyFormatType(enum.Enum):
    """
    The format of the key data structure.

    The key format type is a required attribute of a key block structure. It
    is the differentiating feature that describes the structure of different
    types of keys.
    """
    RAW                           = 0x00000001
    OPAQUE                        = 0x00000002
    PKCS_1                        = 0x00000003
    PKCS_8                        = 0x00000004
    X_509                         = 0x00000005
    EC_PRIVATE_KEY                = 0x00000006
    TRANSPARENT_SYMMETRIC_KEY     = 0x00000007
    TRANSPARENT_DSA_PRIVATE_KEY   = 0x00000008
    TRANSPARENT_DSA_PUBLIC_KEY    = 0x00000009
    TRANSPARENT_RSA_PRIVATE_KEY   = 0x0000000A
    TRANSPARENT_RSA_PUBLIC_KEY    = 0x0000000B
    TRANSPARENT_DH_PRIVATE_KEY    = 0x0000000C
    TRANSPARENT_DH_PUBLIC_KEY     = 0x0000000D
    TRANSPARENT_ECDSA_PRIVATE_KEY = 0x0000000E
    TRANSPARENT_ECDSA_PUBLIC_KEY  = 0x0000000F
    TRANSPARENT_ECDH_PRIVATE_KEY  = 0x00000010
    TRANSPARENT_ECDH_PUBLIC_KEY   = 0x00000011
    TRANSPARENT_ECMQV_PRIVATE_KEY = 0x00000012
    TRANSPARENT_ECMQV_PUBLIC_KEY  = 0x00000013


class WrappingMethod(enum.Enum):
    """
    The technique used to wrap a secret object.

    The wrapping method is a required attribute of a key wrapping data
    structure. It indicates how an algorithm is used to conduct the data
    wrapping.
    """
    ENCRYPT               = 0x00000001
    MAC_SIGN              = 0x00000002
    ENCRYPT_THEN_MAC_SIGN = 0x00000003
    MAC_SIGN_THEN_ENCRYPT = 0x00000004
    TR_31                 = 0x00000005


class RecommendedCurve(enum.Enum):
    """
    The type of algorithm for elliptic curve cryptography.

    The recommended curve defines the algorithm associated with specific
    classes of asymmetric keys. It is a required attribute of all transparent
    key structures.
    """
    P_192 = 0x00000001
    K_163 = 0x00000002
    B_163 = 0x00000003
    P_224 = 0x00000004
    K_233 = 0x00000005
    B_233 = 0x00000006
    P_256 = 0x00000007
    K_283 = 0x00000008
    B_283 = 0x00000009
    P_384 = 0x0000000A
    K_409 = 0x0000000B
    B_409 = 0x0000000C
    P_521 = 0x0000000D
    K_571 = 0x0000000E
    B_571 = 0x0000000F


class CertificateTypeEnum(enum.Enum):
    """
    The type of a certificate managed object.

    The certificate type identifies the format of a certificate. It can be
    specified when creating or registering a certificate managed object.
    """
    X_509 = 0x00000001
    PGP   = 0x00000002


class DigitalSignatureAlgorithm(enum.Enum):
    """
    The algorithm used to create a digital signature.

    The digital signature algorithm is an attribute associated with a
    cryptographically signed object, usually a certificate. It can be
    specified when registering a new managed object and is often managed
    directly by the storage backend.
    """
    MD2_WITH_RSA      = 0x00000001
    MD5_WITH_RSA      = 0x00000002
    SHA1_WITH_RSA     = 0x00000003
    SHA224_WITH_RSA   = 0x00000004
    SHA256_WITH_RSA   = 0x00000005
    SHA384_WITH_RSA   = 0x00000006
    SHA512_WITH_RSA   = 0x00000007
    RSASSA_PSS        = 0x00000008
    DSA_WITH_SHA1     = 0x00000009
    DSA_WITH_SHA224   = 0x0000000A
    DSA_WITH_SHA256   = 0x0000000B
    ECDSA_WITH_SHA1   = 0x0000000C
    ECDSA_WITH_SHA224 = 0x0000000D
    ECDSA_WITH_SHA256 = 0x0000000E
    ECDSA_WITH_SHA384 = 0x0000000F
    ECDSA_WITH_SHA512 = 0x00000010


class SplitKeyMethod(enum.Enum):
    """
    The computation used to create a split key managed object.

    The split key method is a required attribute of a split key managed object,
    indicating how the parts of the split key were generated from the original
    source secret. It is only used when working with split keys.
    """
    XOR                            = 0x00000001
    POLYNOMIAL_SHARING_GF          = 0x00000002
    POLYNOMIAL_SHARING_PRIME_FIELD = 0x00000003


class SecretDataType(enum.Enum):
    """
    The type of a secret data value.

    The secret data type indicates how to decode or interpret the value of a
    secret object. It is a required attribute of a secret data managed object.
    """
    PASSWORD = 0x00000001
    SEED     = 0x00000002


class OpaqueDataType(enum.Enum):
    """
    The type of an opaque data value.

    The opaque data type is a custom value indicating how to decode or
    interpret the value of an opaque object. Unlike all other enumerations,
    the KMIP specification does not define any default opaque data types,
    instead leaving the usage and definition up to the extension system
    supported by a KMIP provider.

    While not defined in the standard, the default type NONE is provided so
    that basic opaque objects can still be defined, independent of a specific
    vendor implementation. By definition as an extension, all opaque data type
    enumeration values start with 0x80.
    """
    NONE = 0x80000000


class NameType(enum.Enum):
    """
    The type of a managed object name string.

    The name type defines the format of a given name attribute value. Names
    are common attributes for all managed objects.
    """
    UNINTERPRETED_TEXT_STRING = 0x00000001
    URI                       = 0x00000002


class ObjectType(enum.Enum):
    """
    The type of a managed object.

    The object type is a common attribute to all managed objects. It can be
    set or specified upon object creation but is immutable once finalized. The
    type can be used as a filter to locate sets of managed objects.
    """
    CERTIFICATE   = 0x00000001
    SYMMETRIC_KEY = 0x00000002
    PUBLIC_KEY    = 0x00000003
    PRIVATE_KEY   = 0x00000004
    SPLIT_KEY     = 0x00000005
    TEMPLATE      = 0x00000006
    SECRET_DATA   = 0x00000007
    OPAQUE_DATA   = 0x00000008


class CryptographicAlgorithm(enum.Enum):
    """
    The type of algorithm used for a cryptographic operation.

    The cryptographic algorithm is a common attribute for cryptographic managed
    objects and is used in various cryptographic structures and operations. It
    is commonly specified during creation or registration of a cryptographic
    object.
    """
    DES         = 0x00000001
    TRIPLE_DES  = 0x00000002  # '3DES' is invalid syntax
    AES         = 0x00000003
    RSA         = 0x00000004
    DSA         = 0x00000005
    ECDSA       = 0x00000006
    HMAC_SHA1   = 0x00000007
    HMAC_SHA224 = 0x00000008
    HMAC_SHA256 = 0x00000009
    HMAC_SHA384 = 0x0000000A
    HMAC_SHA512 = 0x0000000B
    HMAC_MD5    = 0x0000000C
    DH          = 0x0000000D
    ECDH        = 0x0000000E
    ECMQV       = 0x0000000F
    BLOWFISH    = 0x00000010
    CAMELLIA    = 0x00000011
    CAST5       = 0x00000012
    IDEA        = 0x00000013
    MARS        = 0x00000014
    RC2         = 0x00000015
    RC4         = 0x00000016
    RC5         = 0x00000017
    SKIPJACK    = 0x00000018
    TWOFISH     = 0x00000019


class BlockCipherMode(enum.Enum):
    """
    The mode dictating block processing in a cryptographic algorithm.

    The block cipher mode is one of several features that make up a set of
    cryptographic parameters, which can be used to describe all cryptographic
    managed objects.
    """
    CBC                  = 0x00000001
    ECB                  = 0x00000002
    PCBC                 = 0x00000003
    CFB                  = 0x00000004
    OFB                  = 0x00000005
    CTR                  = 0x00000006
    CMAC                 = 0x00000007
    CCM                  = 0x00000008
    GCM                  = 0x00000009
    CBC_MAC              = 0x0000000A
    XTS                  = 0x0000000B
    AES_KEY_WRAP_PADDING = 0x0000000C
    NIST_KEY_WRAP        = 0x0000000D
    X9_102_AESKW         = 0x0000000E
    X9_102_TDKW          = 0x0000000F
    X9_102_AKW1          = 0x00000010
    X9_102_AKW2          = 0x00000011


class PaddingMethod(enum.Enum):
    """
    The type of padding technique used with a cryptographic algorithm.

    The padding method is one of several features that make up a set of
    cryptographic parameters, which can be used to describe all cryptographic
    managed objects. 
    """
    NONE      = 0x00000001
    OAEP      = 0x00000002
    PKCS5     = 0x00000003
    SSL3      = 0x00000004
    ZEROS     = 0x00000005
    ANSI_X923 = 0x00000006
    ISO_10126 = 0x00000007
    PKCS1_V15 = 0x00000008
    X9_31     = 0x00000009
    PSS       = 0x0000000A


class HashingAlgorithm(enum.Enum):
    """
    The type of algorithm used to generate a cryptographic hash.

    The hashing algorithm is one of several features that make up a set of
    cryptographic parameters, which can be used to describe all cryptographic
    managed objects. It is also a required digest attribute, defining the
    algorithm used to create the digest value.
    """
    MD2        = 0x00000001
    MD4        = 0x00000002
    MD5        = 0x00000003
    SHA1       = 0x00000004
    SHA224     = 0x00000005
    SHA256     = 0x00000006
    SHA384     = 0x00000007
    SHA512     = 0x00000008
    RIPEMD_160 = 0x00000009
    TIGER      = 0x0000000A
    WHIRLPOOL  = 0x0000000B


class KeyRoleType(enum.Enum):
    """
    The position a cryptographic managed object holds in a cryptosystem.

    The key role type is one of several features that make up a set of
    cryptographic parameters, which can be used to describe all cryptographic
    managed objects. The set of key role types is defined by ANSI X9 TR-31.
    """
    BDK       = 0x00000001
    CVK       = 0x00000002
    DEK       = 0x00000003
    MKAC      = 0x00000004
    MKSMC     = 0x00000005
    MKSMI     = 0x00000006
    MKDAC     = 0x00000007
    MKDN      = 0x00000008
    MKCP      = 0x00000009
    MKOTH     = 0x0000000A
    KEK       = 0x0000000B
    MAC_16609 = 0x0000000C
    MAC_97971 = 0x0000000D
    MAC_97972 = 0x0000000E
    MAC_97973 = 0x0000000F
    MAC_97974 = 0x00000010
    MAC_97975 = 0x00000011
    ZPK       = 0x00000012
    PVKIBM    = 0x00000013
    PVKPVV    = 0x00000014
    PVKOTH    = 0x00000015


class State(enum.Enum):
    """
    The mode a managed object is currently in.

    The state is a common attribute of managed objects. It defines how a
    managed object can be used and can change as different operations are
    enacted upon the object. It is set dynamically by a server and is only
    queryable by a client.
    """
    PRE_ACTIVE            = 0x00000001
    ACTIVE                = 0x00000002
    DEACTIVATED           = 0x00000003
    COMPROMISED           = 0x00000004
    DESTROYED             = 0x00000005
    DESTROYED_COMPROMISED = 0x00000006


class RevocationReasonCode(enum.Enum):
    """
    A code number used to designate why a managed object was revoked.

    The revocation reason code is used, in conjunction with a revocation
    message, to record why revocation occurred for a managed object. Revocation
    involves a state change in the associated managed object and is usually
    carried out explicitly using the revoke operation.
    """
    UNSPECIFIED            = 0x00000001
    KEY_COMPROMISE         = 0x00000002
    CA_COMPROMISE          = 0x00000003
    AFFILIATION_CHANGED    = 0x00000004
    SUPERSEDED             = 0x00000005
    CESSATION_OF_OPERATION = 0x00000006
    PRIVILEGE_WITHDRAWN    = 0x00000007


class LinkType(enum.Enum):
    """
    The type of linkage between two managed objects.

    The link type is a common attribute of managed objects. It is used to show
    relationships between different objects, like between a public/private key
    pair, or between a certificate and its public key. A managed object can
    have multiple links associated with it and links themselves can be created
    dynamically by the server and by the client upon or after  object creation.
    The link type can also be used as a filter to locate sets of managed
    objects.
    """
    CERTIFICATE_LINK            = 0x00000101
    PUBLIC_KEY_LINK             = 0x00000102
    PRIVATE_KEY_LINK            = 0x00000103
    DERIVATION_BASE_OBJECT_LINK = 0x00000104
    DERIVED_KEY_LINK            = 0x00000105
    REPLACEMENT_OBJECT_LINK     = 0x00000106
    REPLACED_OBJECT_LINK        = 0x00000107


class DerivationMethod(enum.Enum):
    """
    The type of computation used to derive a new cryptographic object.

    The derivation method is used to select a specific algorithm that will be
    used, in conjunction with an existing managed object, to generate a new
    key or secret data object. It is used exclusively with the derive key
    operation.
    """
    PBKDF2          = 0x00000001
    HASH            = 0x00000002
    HMAC            = 0x00000003
    ENCRYPT         = 0x00000004
    NIST800_108_C   = 0x00000005
    NIST800_108_F   = 0x00000006
    NIST800_108_DPI = 0x00000007


class CertificateRequestType(enum.Enum):
    """
    The type of a certificate request issued for certification.

    The certificate request type is used when certifying or re-certifying a
    specific certificate request. It can be omitted from the process if the
    type information is included in an associated request template attribute.
    """
    CRMF    = 0x00000001
    PKCS_10 = 0x00000002
    PEM     = 0x00000003
    PGP     = 0x00000004


class ValidityIndicator(enum.Enum):
    """
    The result of validating a chain of certificates.

    The validity indicator is used by a server to indicate if a chain of
    certificate objects and references was correctly validated. It can
    represent success, failure, or an unknown state if the server did not know
    how to validate the certificate chain.
    """
    VALID   = 0x00000001
    INVALID = 0x00000002
    UNKNOWN = 0x00000003


class QueryFunction(enum.Enum):
    """
    A flag representing a specific set of server-specific information.

    The query function is used to uniquely identifying what server-specific
    information should be returned by a query request. A list of these flags
    are used exclusively by the request payload for the query operation.
    """
    QUERY_OPERATIONS             = 0x00000001
    QUERY_OBJECTS                = 0x00000002
    QUERY_SERVER_INFORMATION     = 0x00000003
    QUERY_APPLICATION_NAMESPACES = 0x00000004
    QUERY_EXTENSION_LIST         = 0x00000005
    QUERY_EXTENSION_MAP          = 0x00000006


class CancellationResult(enum.Enum):
    """
    The final result of cancelling an operation.

    The cancellation result is used by a server to indicate how a cancelled
    operation was handled. It is used exclusively in the response payload for
    the cancel operation.
    """
    CANCELED         = 0x00000001
    UNABLE_TO_CANCEL = 0x00000002
    COMPLETED        = 0x00000003
    FAILED           = 0x00000004
    UNAVAILABLE      = 0x00000005


class PutFunction(enum.Enum):
    """
    The flag indicating the context of an object push to the client.

    The put function defines if an object being pushed to a client is a new
    object or if it is a replacement for an object already retrieved by the
    client. It is used exclusively in the put operation message payload.
    """
    NEW     = 0x00000001
    REPLACE = 0x00000002


class Operation(enum.Enum):
    """
    The identifier of an action supported by the KMIP specification.

    The operation defines what actions should be taken with the data provided
    in the operation payload. It is required to decode the data provided in
    each message payload. It is included in each request or response batch
    item.
    """
    CREATE               = 0x00000001
    CREATE_KEY_PAIR      = 0x00000002
    REGISTER             = 0x00000003
    REKEY                = 0x00000004
    DERIVE_KEY           = 0x00000005
    CERTIFY              = 0x00000006
    RECERTIFY            = 0x00000007
    LOCATE               = 0x00000008
    CHECK                = 0x00000009
    GET                  = 0x0000000A
    GET_ATTRIBUTES       = 0x0000000B
    GET_ATTRIBUTE_LIST   = 0x0000000C
    ADD_ATTRIBUTE        = 0x0000000D
    MODIFY_ATTRIBUTE     = 0x0000000E
    DELETE_ATTRIBUTE     = 0x0000000F
    OBTAIN_LEASE         = 0x00000010
    GET_USAGE_ALLOCATION = 0x00000011
    ACTIVATE             = 0x00000012
    REVOKE               = 0x00000013
    DESTROY              = 0x00000014
    ARCHIVE              = 0x00000015
    RECOVER              = 0x00000016
    VALIDATE             = 0x00000017
    QUERY                = 0x00000018
    CANCEL               = 0x00000019
    POLL                 = 0x0000001A
    NOTIFY               = 0x0000001B
    PUT                  = 0x0000001C
    REKEY_KEY_PAIR       = 0x0000001D
    DISCOVER_VERSIONS    = 0x0000001E


class ResultStatus(enum.Enum):
    """
    The final status of an operation.

    The result status is used to indicate whether an operation completed
    successfully or failed during processing. It is included in each response
    batch item for a response.
    """
    SUCCESS           = 0x00000000
    OPERATION_FAILED  = 0x00000001
    OPERATION_PENDING = 0x00000002
    OPERATION_UNDONE  = 0x00000003


class ResultReason(enum.Enum):
    """
    A predefined explanation for a failure or partial success of an operation.

    The result reason is used to provide additional information on the result
    status of an operation. It is most often used upon operation failure but
    may be used with other result states. The reason is included in each
    response batch item for a response.
    """
    ITEM_NOT_FOUND                      = 0x00000001
    RESPONSE_TOO_LARGE                  = 0x00000002
    AUTHENTICATION_NOT_SUCCESSFUL       = 0x00000003
    INVALID_MESSAGE                     = 0x00000004
    OPERATION_NOT_SUPPORTED             = 0x00000005
    MISSING_DATA                        = 0x00000006
    INVALID_FIELD                       = 0x00000007
    FEATURE_NOT_SUPPORTED               = 0x00000008
    OPERATION_CANCELED_BY_REQUESTER     = 0x00000009
    CRYPTOGRAPHIC_FAILURE               = 0x0000000A
    ILLEGAL_OPERATION                   = 0x0000000B
    PERMISSION_DENIED                   = 0x0000000C
    OBJECT_ARCHIVED                     = 0x0000000D
    INDEX_OUT_OF_BOUNDS                 = 0x0000000E
    APPLICATION_NAMESPACE_NOT_SUPPORTED = 0x0000000F
    KEY_FORMAT_TYPE_NOT_SUPPORTED       = 0x00000010
    KEY_COMPRESSION_TYPE_NOT_SUPPORTED  = 0x00000011
    ENCODING_OPTION_ERROR               = 0x00000012
    GENERAL_FAILURE                     = 0x00000100


class BatchErrorContinuationOption(enum.Enum):
    """
    An error setting used to control the processing of batch items.

    The batch error continuation option defines how the client wants the
    server to handle batch item processing in the event of an operation
    failure. The option is set in the request header of a request.
    """
    CONTINUE = 0x00000001
    STOP     = 0x00000002
    UNDO     = 0x00000003


class UsageLimitsUnit(enum.Enum):
    """
    A unit of measure for a usage limit on a cryptographic managed object.

    The usage limits unit defines what type of data to which a usage limit
    applies. It is used primarily in a usage limit attribute and is typically
    set during object creation or registration.
    """
    BYTE   = 0x00000001
    OBJECT = 0x00000002


class EncodingOption(enum.Enum):
    """
    The type of encoding used for a wrapped managed object.

    The encoding option is used in both key wrapping specifications and key
    wrapping data. It defines how the wrapped object was encoded so that it
    can be correctly parsed once unwrapped.
    """
    NO_ENCODING   = 0x00000001
    TTLV_ENCODING = 0x00000002


class ObjectGroupMember(enum.Enum):
    """
    The group member state of a managed object.

    The object group member reflects the freshness of a managed object. If a
    managed object has never left the appliance, it is considered fresh. The
    object group member can be used as a filter to locate sets of managed
    objects.
    """
    GROUP_MEMBER_FRESH   = 0x00000001
    GROUP_MEMBER_DEFAULT = 0x00000002


class CryptographicUsageMask(enum.Enum):
    """
    A mask identifying a usage case for a cryptographic managed object.

    The cryptographic usage mask is an attribute associated with cryptographic
    managed objects. It is a bit mask made from one or more of the enumeration
    values, combined via logical-or. The mask is often specified during object
    creation or registration and can also be used as a filter to locate sets
    of managed objects.
    """
    SIGN                = 0x00000001
    VERIFY              = 0x00000002
    ENCRYPT             = 0x00000004
    DECRYPT             = 0x00000008
    WRAP_KEY            = 0x00000010
    UNWRAP_KEY          = 0x00000020
    EXPORT              = 0x00000040
    MAC_GENERATE        = 0x00000080
    MAC_VERIFY          = 0x00000100
    DERIVE_KEY          = 0x00000200
    CONTENT_COMMITMENT  = 0x00000400
    KEY_AGREEMENT       = 0x00000800
    CERTIFICATE_SIGN    = 0x00001000
    CRL_SIGN            = 0x00002000
    GENERATE_CRYPTOGRAM = 0x00004000
    VALIDATE_CRYPTOGRAM = 0x00008000
    TRANSLATE_ENCRYPT   = 0x00010000
    TRANSLATE_DECRYPT   = 0x00020000
    TRANSLATE_WRAP      = 0x00040000
    TRANSLATE_UNWRAP    = 0x00080000


class StorageStatusMask(enum.Enum):
    """
    A mask identifying a possible storage state for a managed object.

    The storage state mask is a filter option used to locate sets of managed
    objects. It is a bit mask made from one or more of the enumeration values,
    combined via logical-or.
    """
    ONLINE_STORAGE      = 0x00000001
    ARCHIVAL_STORAGE    = 0x00000002
