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


class AlternativeNameType(enum.Enum):
    UNINTERPRETED_TEXT_STRING = 0x00000001
    URI                       = 0x00000002
    OBJECT_SERIAL_NUMBER      = 0x00000003
    EMAIL_ADDRESS             = 0x00000004
    DNS_NAME                  = 0x00000005
    X500_DISTINGUISHED_NAME   = 0x00000006
    IP_ADDRESS                = 0x00000007


class AttestationType(enum.Enum):
    TPM_QUOTE            = 0x00000001
    TCG_INTEGRITY_REPORT = 0x00000002
    SAML_ASSERTION       = 0x00000003


class AttributeType(enum.Enum):
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
    ALTERNATIVE_NAME                 = 'Alternative Name'
    KEY_VALUE_PRESENT                = 'Key Value Present'
    KEY_VALUE_LOCATION               = 'Key Value Location'
    ORIGINAL_CREATION_DATE           = 'Original Creation Date'


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


class BatchErrorContinuationOption(enum.Enum):
    CONTINUE = 0x00000001
    STOP     = 0x00000002
    UNDO     = 0x00000003


class BlockCipherMode(enum.Enum):
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
    AEAD                 = 0x00000012


class CancellationResult(enum.Enum):
    CANCELED         = 0x00000001
    UNABLE_TO_CANCEL = 0x00000002
    COMPLETED        = 0x00000003
    FAILED           = 0x00000004
    UNAVAILABLE      = 0x00000005


class CertificateRequestType(enum.Enum):
    CRMF   = 0x00000001
    PKCS10 = 0x00000002
    PEM    = 0x00000003
    PGP    = 0x00000004  # DEPRECATED


class CertificateType(enum.Enum):
    X_509 = 0x00000001
    PGP   = 0x00000002  # Deprecated as of KMIP 1.4


class ClientRegistrationMethod(enum.Enum):
    UNSPECIFIED         = 0x00000001
    SERVER_PREGENERATED = 0x00000002
    SERVER_ON_DEMAND    = 0x00000003
    CLIENT_GENERATED    = 0x00000004
    CLIENT_REGISTERED   = 0x00000005


class ConformanceClause(enum.Enum):
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


class CredentialType(enum.Enum):
    USERNAME_AND_PASSWORD = 0x00000001
    DEVICE                = 0x00000002
    ATTESTATION           = 0x00000003


class CryptographicAlgorithm(enum.Enum):
    DES               = 0x00000001
    TRIPLE_DES        = 0x00000002  # '3DES' is invalid syntax
    AES               = 0x00000003
    RSA               = 0x00000004
    DSA               = 0x00000005
    ECDSA             = 0x00000006
    HMAC_SHA1         = 0x00000007
    HMAC_SHA224       = 0x00000008
    HMAC_SHA256       = 0x00000009
    HMAC_SHA384       = 0x0000000A
    HMAC_SHA512       = 0x0000000B
    HMAC_MD5          = 0x0000000C
    DH                = 0x0000000D
    ECDH              = 0x0000000E
    ECMQV             = 0x0000000F
    BLOWFISH          = 0x00000010
    CAMELLIA          = 0x00000011
    CAST5             = 0x00000012
    IDEA              = 0x00000013
    MARS              = 0x00000014
    RC2               = 0x00000015
    RC4               = 0x00000016
    RC5               = 0x00000017
    SKIPJACK          = 0x00000018
    TWOFISH           = 0x00000019
    EC                = 0x0000001A
    ONE_TIME_PAD      = 0x0000001B
    CHACHA20          = 0x0000001C
    POLY1305          = 0x0000001D
    CHACHA20_POLY1305 = 0x0000001E
    SHA3_224          = 0x0000001F
    SHA3_256          = 0x00000020
    SHA3_384          = 0x00000021
    SHA3_512          = 0x00000022
    HMAC_SHA3_224     = 0x00000023
    HMAC_SHA3_256     = 0x00000024
    HMAC_SHA3_384     = 0x00000025
    HMAC_SHA3_512     = 0x00000026
    SHAKE_128         = 0x00000027
    SHAKE_256         = 0x00000028


class CryptographicUsageMask(enum.Enum):
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


class DerivationMethod(enum.Enum):
    PBKDF2          = 0x00000001
    HASH            = 0x00000002
    HMAC            = 0x00000003
    ENCRYPT         = 0x00000004
    NIST800_108_C   = 0x00000005
    NIST800_108_F   = 0x00000006
    NIST800_108_DPI = 0x00000007
    ASYMMETRIC_KEY  = 0x00000008


class DestroyAction(enum.Enum):
    UNSPECIFIED           = 0x00000001
    KEY_MATERIAL_DELETED  = 0x00000002
    KEY_MATERIAL_SHREDDED = 0x00000003
    METADATA_DELETED      = 0x00000004
    METADATA_SHREDDED     = 0x00000005
    DELETED               = 0x00000006
    SHREDDED              = 0x00000007


class DigitalSignatureAlgorithm(enum.Enum):
    MD2_WITH_RSA_ENCRYPTION      = 0x00000001
    MD5_WITH_RSA_ENCRYPTION      = 0x00000002
    SHA1_WITH_RSA_ENCRYPTION     = 0x00000003
    SHA224_WITH_RSA_ENCRYPTION   = 0x00000004
    SHA256_WITH_RSA_ENCRYPTION   = 0x00000005
    SHA384_WITH_RSA_ENCRYPTION   = 0x00000006
    SHA512_WITH_RSA_ENCRYPTION   = 0x00000007
    RSASSA_PSS                   = 0x00000008
    DSA_WITH_SHA1                = 0x00000009
    DSA_WITH_SHA224              = 0x0000000A
    DSA_WITH_SHA256              = 0x0000000B
    ECDSA_WITH_SHA1              = 0x0000000C
    ECDSA_WITH_SHA224            = 0x0000000D
    ECDSA_WITH_SHA256            = 0x0000000E
    ECDSA_WITH_SHA384            = 0x0000000F
    ECDSA_WITH_SHA512            = 0x00000010
    SHA3_256_WITH_RSA_ENCRYPTION = 0x00000011
    SHA3_384_WITH_RSA_ENCRYPTION = 0x00000012
    SHA3_512_WITH_RSA_ENCRYPTION = 0x00000013


class DRBGAlgorithm(enum.Enum):
    UNSPECIFIED = 0x00000001
    DUAL_EC     = 0x00000002
    HASH        = 0x00000003
    HMAC        = 0x00000004
    CTR         = 0x00000005


class EncodingOption(enum.Enum):
    NO_ENCODING   = 0x00000001
    TTLV_ENCODING = 0x00000002


class FIPS186Variation(enum.Enum):
    UNSPECIFIED        = 0x00000001
    GP_X_ORIGINAL      = 0x00000002
    GP_X_CHANGE_NOTICE = 0x00000003
    X_ORIGINAL         = 0x00000004
    X_CHANGE_NOTICE    = 0x00000005
    K_ORIGINAL         = 0x00000006
    K_CHANGE_NOTICE    = 0x00000007


class HashingAlgorithm(enum.Enum):
    MD2         = 0x00000001
    MD4         = 0x00000002
    MD5         = 0x00000003
    SHA_1       = 0x00000004
    SHA_224     = 0x00000005
    SHA_256     = 0x00000006
    SHA_384     = 0x00000007
    SHA_512     = 0x00000008
    RIPEMD_160  = 0x00000009
    TIGER       = 0x0000000A
    WHIRLPOOL   = 0x0000000B
    SHA_512_224 = 0x0000000C
    SHA_512_256 = 0x0000000D
    SHA3_224    = 0x0000000E
    SHA3_256    = 0x0000000F
    SHA3_384    = 0x00000010
    SHA3_512    = 0x00000011


class KeyCompressionType(enum.Enum):
    EC_PUBLIC_KEY_TYPE_UNCOMPRESSED           = 0x00000001
    EC_PUBLIC_KEY_TYPE_X9_62_COMPRESSED_PRIME = 0x00000002
    EC_PUBLIC_KEY_TYPE_X9_62_COMPRESSED_CHAR2 = 0x00000003
    EC_PUBLIC_KEY_TYPE_X9_62_HYBRID           = 0x00000004


class KeyFormatType(enum.Enum):
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
    TRANSPARENT_ECDSA_PRIVATE_KEY = 0x0000000E  # Deprecated as of KMIP 1.4
    TRANSPARENT_ECDSA_PUBLIC_KEY  = 0x0000000F  # Deprecated as of KMIP 1.4
    TRANSPARENT_ECDH_PRIVATE_KEY  = 0x00000010  # Deprecated as of KMIP 1.4
    TRANSPARENT_ECDH_PUBLIC_KEY   = 0x00000011  # Deprecated as of KMIP 1.4
    TRANSPARENT_ECMQV_PRIVATE_KEY = 0x00000012  # Deprecated as of KMIP 1.4
    TRANSPARENT_ECMQV_PUBLIC_KEY  = 0x00000013  # Deprecated as of KMIP 1.4
    TRANSPARENT_EC_PRIVATE_KEY    = 0x00000014
    TRANSPARENT_EC_PUBLIC_KEY     = 0x00000015
    PKCS_12                       = 0x00000016


class KeyRoleType(enum.Enum):
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
    DUKPT     = 0x00000016
    IV        = 0x00000017
    TRKBK     = 0x00000018


class KeyValueLocationType(enum.Enum):
    UNINTERPRETED_TEXT_STRING = 0x00000001
    URI                       = 0x00000002


class KeyWrapType(enum.Enum):
    NOT_WRAPPED   = 0x00000001
    AS_REGISTERED = 0x00000002


class KMIPVersion(enum.Enum):
    KMIP_1_0 = "KMIP 1.0"
    KMIP_1_1 = "KMIP 1.1"
    KMIP_1_2 = "KMIP 1.2"
    KMIP_1_3 = "KMIP 1.3"
    KMIP_1_4 = "KMIP 1.4"


class LinkType(enum.Enum):
    CERTIFICATE_LINK            = 0x00000101
    PUBLIC_KEY_LINK             = 0x00000102
    PRIVATE_KEY_LINK            = 0x00000103
    DERIVATION_BASE_OBJECT_LINK = 0x00000104
    DERIVED_KEY_LINK            = 0x00000105
    REPLACEMENT_OBJECT_LINK     = 0x00000106
    REPLACED_OBJECT_LINK        = 0x00000107
    PARENT_LINK                 = 0x00000108
    CHILD_LINK                  = 0x00000109
    PREVIOUS_LINK               = 0x0000010A
    NEXT_LINK                   = 0x0000010B
    PKCS12_CERTIFICATE_LINK     = 0x0000010C
    PKCS12_PASSWORD_LINK        = 0x0000010D


class MaskGenerator(enum.Enum):
    MGF1 = 0x00000001


class NameType(enum.Enum):
    UNINTERPRETED_TEXT_STRING = 0x00000001
    URI                       = 0x00000002


class ObjectGroupMember(enum.Enum):
    GROUP_MEMBER_FRESH   = 0x00000001
    GROUP_MEMBER_DEFAULT = 0x00000002


class ObjectType(enum.Enum):
    CERTIFICATE   = 0x00000001
    SYMMETRIC_KEY = 0x00000002
    PUBLIC_KEY    = 0x00000003
    PRIVATE_KEY   = 0x00000004
    SPLIT_KEY     = 0x00000005
    TEMPLATE      = 0x00000006  # Deprecated as of KMIP 1.3
    SECRET_DATA   = 0x00000007
    OPAQUE_DATA   = 0x00000008
    PGP_KEY       = 0x00000009


class OpaqueDataType(enum.Enum):
    NONE = 0x80000000 # Not defined by the standard, but we need something.
                      # The standard does say that values starting 0x8xxxxxx
                      # are considered extensions


class Operation(enum.Enum):
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
    ENCRYPT              = 0x0000001F
    DECRYPT              = 0x00000020
    SIGN                 = 0x00000021
    SIGNATURE_VERIFY     = 0x00000022
    MAC                  = 0x00000023
    MAC_VERIFY           = 0x00000024
    RNG_RETRIEVE         = 0x00000025
    RNG_SEED             = 0x00000026
    HASH                 = 0x00000027
    CREATE_SPLIT_KEY     = 0x00000028
    JOIN_SPLIT_KEY       = 0x00000029
    IMPORT               = 0x0000002A
    EXPORT               = 0x0000002B


class PaddingMethod(enum.Enum):
    NONE      = 0x00000001
    OAEP      = 0x00000002
    PKCS5     = 0x00000003
    SSL3      = 0x00000004
    ZEROS     = 0x00000005
    ANSI_X923 = 0x00000006
    ISO_10126 = 0x00000007
    PKCS1v15  = 0x00000008
    X931      = 0x00000009
    PSS       = 0x0000000A


class Policy(enum.Enum):
    ALLOW_ALL    = "Allow All"
    ALLOW_OWNER  = "Allow Owner"
    DISALLOW_ALL = "Disallow All"


class ProfileName(enum.Enum):
    BASELINE_SERVER_BASIC_KMIPv12                           = 0x00000001
    BASELINE_SERVER_TLSv12_KMIPv12                          = 0x00000002
    BASELINE_CLIENT_BASIC_KMIPv12                           = 0x00000003
    BASELINE_CLIENT_TLSv12_KMIPv12                          = 0x00000004
    COMPLETE_SERVER_BASIC_KMIPv12                           = 0x00000005
    COMPLETE_SERVER_TLSv12_KMIPv12                          = 0x00000006
    TAPE_LIBRARY_CLIENT_KMIPv10                             = 0x00000007
    TAPE_LIBRARY_CLIENT_KMIPv11                             = 0x00000008
    TAPE_LIBRARY_CLIENT_KMIPv12                             = 0x00000009
    TAPE_LIBRARY_SERVER_KMIPv10                             = 0x0000000A
    TAPE_LIBRARY_SERVER_KMIPv11                             = 0x0000000B
    TAPE_LIBRARY_SERVER_KMIPv12                             = 0x0000000C
    SYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv10                  = 0x0000000D
    SYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv11                  = 0x0000000E
    SYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv12                  = 0x0000000F
    SYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv10                  = 0x00000010
    SYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv11                  = 0x00000011
    SYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv12                  = 0x00000012
    ASYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv10                 = 0x00000013
    ASYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv11                 = 0x00000014
    ASYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv12                 = 0x00000015
    ASYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv10                 = 0x00000016
    ASYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv11                 = 0x00000017
    ASYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv12                 = 0x00000018
    BASIC_CRYPTOGRAPHIC_CLIENT_KMIPv12                      = 0x00000019
    BASIC_CRYPTOGRAPHIC_SERVER_KMIPv12                      = 0x0000001A
    ADVANCED_CRYPTOGRAPHIC_CLIENT_KMIPv12                   = 0x0000001B
    ADVANCED_CRYPTOGRAPHIC_SERVER_KMIPv12                   = 0x0000001C
    RNG_CRYPTOGRAPHIC_CLIENT_KMIPv12                        = 0x0000001D
    RNG_CRYPTOGRAPHIC_SERVER_KMIPv12                        = 0x0000001E
    BASIC_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv10              = 0x0000001F
    INTERMEDIATE_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv10       = 0x00000020
    ADVANCED_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv10           = 0x00000021
    BASIC_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv11              = 0x00000022
    INTERMEDIATE_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv11       = 0x00000023
    ADVANCED_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv11           = 0x00000024
    BASIC_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv12              = 0x00000025
    INTERMEDIATE_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv12       = 0x00000026
    ADVANCED_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv12           = 0x00000027
    SYMMETRIC_KEY_FOUNDRY_SERVER_KMIPv10                    = 0x00000028
    SYMMETRIC_KEY_FOUNDRY_SERVER_KMIPv11                    = 0x00000029
    SYMMETRIC_KEY_FOUNDRY_SERVER_KMIPv12                    = 0x0000002A
    OPAQUE_MANAGED_OBJECT_STORE_CLIENT_KMIPv10              = 0x0000002B
    OPAQUE_MANAGED_OBJECT_STORE_CLIENT_KMIPv11              = 0x0000002C
    OPAQUE_MANAGED_OBJECT_STORE_CLIENT_KMIPv12              = 0x0000002D
    OPAQUE_MANAGED_OBJECT_STORE_SERVER_KMIPv10              = 0x0000002E
    OPAQUE_MANAGED_OBJECT_STORE_SERVER_KMIPv11              = 0x0000002F
    OPAQUE_MANAGED_OBJECT_STORE_SERVER_KMIPv12              = 0x00000030
    SUITE_B_MINLOS_128_CLIENT_KMIPv10                       = 0x00000031
    SUITE_B_MINLOS_128_CLIENT_KMIPv11                       = 0x00000032
    SUITE_B_MINLOS_128_CLIENT_KMIPv12                       = 0x00000033
    SUITE_B_MINLOS_128_SERVER_KMIPv10                       = 0x00000034
    SUITE_B_MINLOS_128_SERVER_KMIPv11                       = 0x00000035
    SUITE_B_MINLOS_128_SERVER_KMIPv12                       = 0x00000036
    SUITE_B_MINLOS_192_CLIENT_KMIPv10                       = 0x00000037
    SUITE_B_MINLOS_192_CLIENT_KMIPv11                       = 0x00000038
    SUITE_B_MINLOS_192_CLIENT_KMIPv12                       = 0x00000039
    SUITE_B_MINLOS_192_SERVER_KMIPv10                       = 0x0000003A
    SUITE_B_MINLOS_192_SERVER_KMIPv11                       = 0x0000003B
    SUITE_B_MINLOS_192_SERVER_KMIPv12                       = 0x0000003C
    STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_CLIENT_KMIPv10 = 0x0000003D
    STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_CLIENT_KMIPv11 = 0x0000003E
    STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_CLIENT_KMIPv12 = 0x0000003F
    STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_SERVER_KMIPv10 = 0x00000040
    STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_SERVER_KMIPv11 = 0x00000041
    STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_SERVER_KMIPv12 = 0x00000042
    HTTPS_CLIENT_KMIPv10                                    = 0x00000043
    HTTPS_CLIENT_KMIPv11                                    = 0x00000044
    HTTPS_CLIENT_KMIPv12                                    = 0x00000045
    HTTPS_SERVER_KMIPv10                                    = 0x00000046
    HTTPS_SERVER_KMIPv11                                    = 0x00000047
    HTTPS_SERVER_KMIPv12                                    = 0x00000048
    JSON_CLIENT_KMIPv10                                     = 0x00000049
    JSON_CLIENT_KMIPv11                                     = 0x0000004A
    JSON_CLIENT_KMIPv12                                     = 0x0000004B
    JSON_SERVER_KMIPv10                                     = 0x0000004C
    JSON_SERVER_KMIPv11                                     = 0x0000004D
    JSON_SERVER_KMIPv12                                     = 0x0000004E
    XML_CLIENT_KMIPv10                                      = 0x0000004F
    XML_CLIENT_KMIPv11                                      = 0x00000050
    XML_CLIENT_KMIPv12                                      = 0x00000051
    XML_SERVER_KMIPv10                                      = 0x00000052
    XML_SERVER_KMIPv11                                      = 0x00000053
    XML_SERVER_KMIPv12                                      = 0x00000054
    BASELINE_SERVER_BASIC_KMIPv13                           = 0x00000055
    BASELINE_SERVER_TLSv12_KMIPv13                          = 0x00000056
    BASELINE_CLIENT_BASIC_KMIPv13                           = 0x00000057
    BASELINE_CLIENT_TLSv12_KMIPv13                          = 0x00000058
    COMPLETE_SERVER_BASIC_KMIPv13                           = 0x00000059
    COMPLETE_SERVER_TLSv12_KMIPv13                          = 0x0000005A
    TAPE_LIBRARY_CLIENT_KMIPv13                             = 0x0000005B
    TAPE_LIBRARY_SERVER_KMIPv13                             = 0x0000005C
    SYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv13                  = 0x0000005D
    SYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv13                  = 0x0000005E
    ASYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv13                 = 0x0000005F
    ASYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv13                 = 0x00000060
    BASIC_CRYPTOGRAPHIC_CLIENT_KMIPv13                      = 0x00000061
    BASIC_CRYPTOGRAPHIC_SERVER_KMIPv13                      = 0x00000062
    ADVANCED_CRYPTOGRAPHIC_CLIENT_KMIPv13                   = 0x00000063
    ADVANCED_CRYPTOGRAPHIC_SERVER_KMIPv13                   = 0x00000064
    RNG_CRYPTOGRAPHIC_CLIENT_KMIPv13                        = 0x00000065
    RNG_CRYPTOGRAPHIC_SERVER_KMIPv13                        = 0x00000066
    BASIC_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv13              = 0x00000067
    INTERMEDIATE_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv13       = 0x00000068
    ADVANCED_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv13           = 0x00000069
    SYMMETRIC_KEY_FOUNDRY_SERVER_KMIPv13                    = 0x0000006A
    OPAQUE_MANAGED_OBJECT_STORE_CLIENT_KMIPv13              = 0x0000006B
    OPAQUE_MANAGED_OBJECT_STORE_SERVER_KMIPv13              = 0x0000006C
    SUITE_B_MINLOS_128_CLIENT_KMIPv13                       = 0x0000006D
    SUITE_B_MINLOS_128_SERVER_KMIPv13                       = 0x0000006E
    SUITE_B_MINLOS_192_CLIENT_KMIPv13                       = 0x0000006F
    SUITE_B_MINLOS_192_SERVER_KMIPv13                       = 0x00000070
    STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_CLIENT_KMIPv13 = 0x00000071
    STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_SERVER_KMIPv13 = 0x00000072
    HTTPS_CLIENT_KMIPv13                                    = 0x00000073
    HTTPS_SERVER_KMIPv13                                    = 0x00000074
    JSON_CLIENT_KMIPv13                                     = 0x00000075
    JSON_SERVER_KMIPv13                                     = 0x00000076
    XML_CLIENT_KMIPv13                                      = 0x00000077
    XML_SERVER_KMIPv13                                      = 0x00000078
    BASELINE_SERVER_BASIC_KMIPv14                           = 0x00000079
    BASELINE_SERVER_TLSv12_KMIPv14                          = 0x0000007A
    BASELINE_CLIENT_BASIC_KMIPv14                           = 0x0000007B
    BASELINE_CLIENT_TLSv12_KMIPv14                          = 0x0000007C
    COMPLETE_SERVER_BASIC_KMIPv14                           = 0x0000007D
    COMPLETE_SERVER_TLSv12_KMIPv14                          = 0x0000007E
    TAPE_LIBRARY_CLIENT_KMIPv14                             = 0x0000007F
    TAPE_LIBRARY_SERVER_KMIPv14                             = 0x00000080
    SYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv14                  = 0x00000081
    SYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv14                  = 0x00000082
    ASYMMETRIC_KEY_LIFECYCLE_CLIENT_KMIPv14                 = 0x00000083
    ASYMMETRIC_KEY_LIFECYCLE_SERVER_KMIPv14                 = 0x00000084
    BASIC_CRYPTOGRAPHIC_CLIENT_KMIPv14                      = 0x00000085
    BASIC_CRYPTOGRAPHIC_SERVER_KMIPv14                      = 0x00000086
    ADVANCED_CRYPTOGRAPHIC_CLIENT_KMIPv14                   = 0x00000087
    ADVANCED_CRYPTOGRAPHIC_SERVER_KMIPv14                   = 0x00000088
    RNG_CRYPTOGRAPHIC_CLIENT_KMIPv14                        = 0x00000089
    RNG_CRYPTOGRAPHIC_SERVER_KMIPv14                        = 0x0000008A
    BASIC_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv14              = 0x0000008B
    INTERMEDIATE_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv14       = 0x0000008C
    ADVANCED_SYMMETRIC_KEY_FOUNDRY_CLIENT_KMIPv14           = 0x0000008D
    SYMMETRIC_KEY_FOUNDRY_SERVER_KMIPv14                    = 0x0000008E
    OPAQUE_MANAGED_OBJECT_STORE_CLIENT_KMIPv14              = 0x0000008F
    OPAQUE_MANAGED_OBJECT_STORE_SERVER_KMIPv14              = 0x00000090
    SUITE_B_MINLOS_128_CLIENT_KMIPv14                       = 0x00000091
    SUITE_B_MINLOS_128_SERVER_KMIPv14                       = 0x00000092
    SUITE_B_MINLOS_192_CLIENT_KMIPv14                       = 0x00000093
    SUITE_B_MINLOS_192_SERVER_KMIPv14                       = 0x00000094
    STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_CLIENT_KMIPv14 = 0x00000095
    STORAGE_ARRAY_WITH_SELF_ENCRYPTING_DRIVE_SERVER_KMIPv14 = 0x00000096
    HTTPS_CLIENT_KMIPv14                                    = 0x00000097
    HTTPS_SERVER_KMIPv14                                    = 0x00000098
    JSON_CLIENT_KMIPv14                                     = 0x00000099
    JSON_SERVER_KMIPv14                                     = 0x0000009A
    XML_CLIENT_KMIPv14                                      = 0x0000009B
    XML_SERVER_KMIPv14                                      = 0x0000009C


class PutFunction(enum.Enum):
    NEW     = 0x00000001
    REPLACE = 0x00000002


class QueryFunction(enum.Enum):
    QUERY_OPERATIONS                  = 0x00000001
    QUERY_OBJECTS                     = 0x00000002
    QUERY_SERVER_INFORMATION          = 0x00000003
    QUERY_APPLICATION_NAMESPACES      = 0x00000004
    QUERY_EXTENSION_LIST              = 0x00000005
    QUERY_EXTENSION_MAP               = 0x00000006
    QUERY_ATTESTATION_TYPES           = 0x00000007
    QUERY_RNGS                        = 0x00000008
    QUERY_VALIDATIONS                 = 0x00000009
    QUERY_PROFILES                    = 0x0000000A
    QUERY_CAPABILITIES                = 0x0000000B
    QUERY_CLIENT_REGISTRATION_METHODS = 0x0000000C


class RecommendedCurve(enum.Enum):
    P_192            = 0x00000001
    K_163            = 0x00000002
    B_163            = 0x00000003
    P_224            = 0x00000004
    K_233            = 0x00000005
    B_233            = 0x00000006
    P_256            = 0x00000007
    K_283            = 0x00000008
    B_283            = 0x00000009
    P_384            = 0x0000000A
    K_409            = 0x0000000B
    B_409            = 0x0000000C
    P_521            = 0x0000000D
    K_571            = 0x0000000E
    B_571            = 0x0000000F
    SECP112R1        = 0x00000010
    SECP112R2        = 0x00000011
    SECP128R1        = 0x00000012
    SECP128R2        = 0x00000013
    SECP160K1        = 0x00000014
    SECP160R1        = 0x00000015
    SECP160R2        = 0x00000016
    SECP191K1        = 0x00000017
    SECP224K1        = 0x00000018
    SECP256K1        = 0x00000019
    SECT113R1        = 0x0000001A
    SECT113R2        = 0x0000001B
    SECT131R1        = 0x0000001C
    SECT131R2        = 0x0000001D
    SECT163R1        = 0x0000001E
    SECT193R1        = 0x0000001F
    SECT193R2        = 0x00000020
    SECT239K1        = 0x00000021
    ANSIX9P192V2     = 0x00000022
    ANSIX9P192V3     = 0x00000023
    ANSIX9P239V1     = 0x00000024
    ANSIX9P239V2     = 0x00000025
    ANSIX9P239V3     = 0x00000026
    ANSIX9C2PNB163V1 = 0x00000027
    ANSIX9C2PNB163V2 = 0x00000028
    ANSIX9C2PNB163V3 = 0x00000029
    ANSIX9C2PNB176V1 = 0x0000002A
    ANSIX9C2TNB191V1 = 0x0000002B
    ANSIX9C2TNB191V2 = 0x0000002C
    ANSIX9C2TNB191V3 = 0x0000002D
    ANSIX9C2PNB208W1 = 0x0000002E
    ANSIX9C2TNB239V1 = 0x0000002F
    ANSIX9C2TNB239V2 = 0x00000030
    ANSIX9C2TNB239V3 = 0x00000031
    ANSIX9C2PNB272W1 = 0x00000032
    ANSIX9C2PNB304W1 = 0x00000033
    ANSIX9C2TNB359V1 = 0x00000034
    ANSIX9C2PNB368W1 = 0x00000035
    ANSIX9C2TNB431R1 = 0x00000036
    BRAINPOOLP160R1  = 0x00000037
    BRAINPOOLP160T1  = 0x00000038
    BRAINPOOLP192R1  = 0x00000039
    BRAINPOOLP192T1  = 0x0000003A
    BRAINPOOLP224R1  = 0x0000003B
    BRAINPOOLP224T1  = 0x0000003C
    BRAINPOOLP256R1  = 0x0000003D
    BRAINPOOLP256T1  = 0x0000003E
    BRAINPOOLP320R1  = 0x0000003F
    BRAINPOOLP320T1  = 0x00000040
    BRAINPOOLP384R1  = 0x00000041
    BRAINPOOLP384T1  = 0x00000042
    BRAINPOOLP512R1  = 0x00000043
    BRAINPOOLP512T1  = 0x00000044


class ResultReason(enum.Enum):
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
    KEY_VALUE_NOT_PRESENT               = 0x00000013
    ATTESTATION_REQUIRED                = 0x00000014
    ATTESTATION_FAILED                  = 0x00000015
    SENSITIVE                           = 0x00000016
    NOT_EXTRACTABLE                     = 0x00000017
    OBJECT_ALREADY_EXISTS               = 0x00000018
    GENERAL_FAILURE                     = 0x00000100


class ResultStatus(enum.Enum):
    SUCCESS           = 0x00000000
    OPERATION_FAILED  = 0x00000001
    OPERATION_PENDING = 0x00000002
    OPERATION_UNDONE  = 0x00000003


class RevocationReasonCode(enum.Enum):
    UNSPECIFIED            = 0x00000001
    KEY_COMPROMISE         = 0x00000002
    CA_COMPROMISE          = 0x00000003
    AFFILIATION_CHANGED    = 0x00000004
    SUPERSEDED             = 0x00000005
    CESSATION_OF_OPERATION = 0x00000006
    PRIVILEGE_WITHDRAWN    = 0x00000007


class RNGAlgorithm(enum.Enum):
    UNSPECIFIED = 0x00000001
    FIPS186_2   = 0x00000002
    DRBG        = 0x00000003
    NRBG        = 0x00000004
    ANSI_X931   = 0x00000005
    ANSI_X962   = 0x00000006


class RNGMode(enum.Enum):
    UNSPECIFIED              = 0x00000001
    SHARED_INSTANTIATION     = 0x00000002
    NON_SHARED_INSTANTIATION = 0x00000003


class SecretDataType(enum.Enum):
    PASSWORD = 0x00000001
    SEED     = 0x00000002


class ShreddingAlgorithm(enum.Enum):
    UNSPECIFIED   = 0x00000001
    CRYPTOGRAPHIC = 0x00000002
    UNSUPPORTED   = 0x00000003


class SplitKeyMethod(enum.Enum):
    XOR                            = 0x00000001
    POLYNOMIAL_SHARING_GF_2_16     = 0x00000002
    POLYNOMIAL_SHARING_PRIME_FIELD = 0x00000003
    POLYNOMIAL_SHARING_GF_2_8      = 0x00000004


class State(enum.Enum):
    PRE_ACTIVE            = 0x00000001
    ACTIVE                = 0x00000002
    DEACTIVATED           = 0x00000003
    COMPROMISED           = 0x00000004
    DESTROYED             = 0x00000005
    DESTROYED_COMPROMISED = 0x00000006


class StorageStatus(enum.Enum):
    ONLINE_STORAGE   = 0x00000001
    ARCHIVAL_STORAGE = 0x00000002


class Tags(enum.Enum):
    DEFAULT                                  = 0x420000
    ACTIVATION_DATE                          = 0x420001
    APPLICATION_DATA                         = 0x420002
    APPLICATION_NAMESPACE                    = 0x420003
    APPLICATION_SPECIFIC_INFORMATION         = 0x420004
    ARCHIVE_DATE                             = 0x420005
    ASYNCHRONOUS_CORRELATION_VALUE           = 0x420006
    ASYNCHRONOUS_INDICATOR                   = 0x420007
    ATTRIBUTE                                = 0x420008
    ATTRIBUTE_INDEX                          = 0x420009
    ATTRIBUTE_NAME                           = 0x42000A
    ATTRIBUTE_VALUE                          = 0x42000B
    AUTHENTICATION                           = 0x42000C
    BATCH_COUNT                              = 0x42000D
    BATCH_ERROR_CONTINUATION_OPTION          = 0x42000E
    BATCH_ITEM                               = 0x42000F
    BATCH_ORDER_OPTION                       = 0x420010
    BLOCK_CIPHER_MODE                        = 0x420011
    CANCELLATION_RESULT                      = 0x420012
    CERTIFICATE                              = 0x420013
    CERTIFICATE_IDENTIFIER                   = 0x420014  # DEPRECATED
    CERTIFICATE_ISSUER                       = 0x420015  # DEPRECATED
    CERTIFICATE_ISSUER_ALTERNATIVE_NAME      = 0x420016  # DEPRECATED
    CERTIFICATE_ISSUER_DISTINGUISHED_NAME    = 0x420017  # DEPRECATED
    CERTIFICATE_REQUEST                      = 0x420018
    CERTIFICATE_REQUEST_TYPE                 = 0x420019
    CERTIFICATE_SUBJECT                      = 0x42001A  # DEPRECATED
    CERTIFICATE_SUBJECT_ALTERNATIVE_NAME     = 0x42001B  # DEPRECATED
    CERTIFICATE_SUBJECT_DISTINGUISHED_NAME   = 0x42001C  # DEPRECATED
    CERTIFICATE_TYPE                         = 0x42001D
    CERTIFICATE_VALUE                        = 0x42001E
    COMMON_TEMPLATE_ATTRIBUTE                = 0x42001F
    COMPROMISE_DATE                          = 0x420020
    COMPROMISE_OCCURRENCE_DATE               = 0x420021
    CONTACT_INFORMATION                      = 0x420022
    CREDENTIAL                               = 0x420023
    CREDENTIAL_TYPE                          = 0x420024
    CREDENTIAL_VALUE                         = 0x420025
    CRITICALITY_INDICATOR                    = 0x420026
    CRT_COEFFICIENT                          = 0x420027
    CRYPTOGRAPHIC_ALGORITHM                  = 0x420028
    CRYPTOGRAPHIC_DOMAIN_PARAMETERS          = 0x420029
    CRYPTOGRAPHIC_LENGTH                     = 0x42002A
    CRYPTOGRAPHIC_PARAMETERS                 = 0x42002B
    CRYPTOGRAPHIC_USAGE_MASK                 = 0x42002C
    CUSTOM_ATTRIBUTE                         = 0x42002D
    D                                        = 0x42002E
    DEACTIVATION_DATE                        = 0x42002F
    DERIVATION_DATA                          = 0x420030
    DERIVATION_METHOD                        = 0x420031
    DERIVATION_PARAMETERS                    = 0x420032
    DESTROY_DATE                             = 0x420033
    DIGEST                                   = 0x420034
    DIGEST_VALUE                             = 0x420035
    ENCRYPTION_KEY_INFORMATION               = 0x420036
    G                                        = 0x420037
    HASHING_ALGORITHM                        = 0x420038
    INITIAL_DATE                             = 0x420039
    INITIALIZATION_VECTOR                    = 0x42003A
    ISSUER                                   = 0x42003B  # DEPRECATED
    ITERATION_COUNT                          = 0x42003C
    IV_COUNTER_NONCE                         = 0x42003D
    J                                        = 0x42003E
    KEY                                      = 0x42003F
    KEY_BLOCK                                = 0x420040
    KEY_COMPRESSION_TYPE                     = 0x420041
    KEY_FORMAT_TYPE                          = 0x420042
    KEY_MATERIAL                             = 0x420043
    KEY_PART_IDENTIFIER                      = 0x420044
    KEY_VALUE                                = 0x420045
    KEY_WRAPPING_DATA                        = 0x420046
    KEY_WRAPPING_SPECIFICATION               = 0x420047
    LAST_CHANGE_DATE                         = 0x420048
    LEASE_TIME                               = 0x420049
    LINK                                     = 0x42004A
    LINK_TYPE                                = 0x42004B
    LINKED_OBJECT_IDENTIFIER                 = 0x42004C
    MAC_SIGNATURE                            = 0x42004D
    MAC_SIGNATURE_KEY_INFORMATION            = 0x42004E
    MAXIMUM_ITEMS                            = 0x42004F
    MAXIMUM_RESPONSE_SIZE                    = 0x420050
    MESSAGE_EXTENSION                        = 0x420051
    MODULUS                                  = 0x420052
    NAME                                     = 0x420053
    NAME_TYPE                                = 0x420054
    NAME_VALUE                               = 0x420055
    OBJECT_GROUP                             = 0x420056
    OBJECT_TYPE                              = 0x420057
    OFFSET                                   = 0x420058
    OPAQUE_DATA_TYPE                         = 0x420059
    OPAQUE_DATA_VALUE                        = 0x42005A
    OPAQUE_OBJECT                            = 0x42005B
    OPERATION                                = 0x42005C
    OPERATION_POLICY_NAME                    = 0x42005D
    P                                        = 0x42005E
    PADDING_METHOD                           = 0x42005F
    PRIME_EXPONENT_P                         = 0x420060
    PRIME_EXPONENT_Q                         = 0x420061
    PRIME_FIELD_SIZE                         = 0x420062
    PRIVATE_EXPONENT                         = 0x420063
    PRIVATE_KEY                              = 0x420064
    PRIVATE_KEY_TEMPLATE_ATTRIBUTE           = 0x420065
    PRIVATE_KEY_UNIQUE_IDENTIFIER            = 0x420066
    PROCESS_START_DATE                       = 0x420067
    PROTECT_STOP_DATE                        = 0x420068
    PROTOCOL_VERSION                         = 0x420069
    PROTOCOL_VERSION_MAJOR                   = 0x42006A
    PROTOCOL_VERSION_MINOR                   = 0x42006B
    PUBLIC_EXPONENT                          = 0x42006C
    PUBLIC_KEY                               = 0x42006D
    PUBLIC_KEY_TEMPLATE_ATTRIBUTE            = 0x42006E
    PUBLIC_KEY_UNIQUE_IDENTIFIER             = 0x42006F
    PUT_FUNCTION                             = 0x420070
    Q                                        = 0x420071
    Q_STRING                                 = 0x420072
    QLENGTH                                  = 0x420073
    QUERY_FUNCTION                           = 0x420074
    RECOMMENDED_CURVE                        = 0x420075
    REPLACED_UNIQUE_IDENTIFIER               = 0x420076
    REQUEST_BATCH_ITEM                       = 0x42000F
    REQUEST_HEADER                           = 0x420077
    REQUEST_MESSAGE                          = 0x420078
    REQUEST_PAYLOAD                          = 0x420079
    RESPONSE_BATCH_ITEM                      = 0x42000F
    RESPONSE_HEADER                          = 0x42007A
    RESPONSE_MESSAGE                         = 0x42007B
    RESPONSE_PAYLOAD                         = 0x42007C
    RESULT_MESSAGE                           = 0x42007D
    RESULT_REASON                            = 0x42007E
    RESULT_STATUS                            = 0x42007F
    REVOCATION_MESSAGE                       = 0x420080
    REVOCATION_REASON                        = 0x420081
    REVOCATION_REASON_CODE                   = 0x420082
    KEY_ROLE_TYPE                            = 0x420083
    SALT                                     = 0x420084
    SECRET_DATA                              = 0x420085
    SECRET_DATA_TYPE                         = 0x420086
    SERIAL_NUMBER                            = 0x420087  # DEPRECATED
    SERVER_INFORMATION                       = 0x420088
    SPLIT_KEY                                = 0x420089
    SPLIT_KEY_METHOD                         = 0x42008A
    SPLIT_KEY_PARTS                          = 0x42008B
    SPLIT_KEY_THRESHOLD                      = 0x42008C
    STATE                                    = 0x42008D
    STORAGE_STATUS_MASK                      = 0x42008E
    SYMMETRIC_KEY                            = 0x42008F
    TEMPLATE                                 = 0x420090
    TEMPLATE_ATTRIBUTE                       = 0x420091
    TIME_STAMP                               = 0x420092
    UNIQUE_BATCH_ITEM_ID                     = 0x420093
    UNIQUE_IDENTIFIER                        = 0x420094
    USAGE_LIMITS                             = 0x420095
    USAGE_LIMITS_COUNT                       = 0x420096
    USAGE_LIMITS_TOTAL                       = 0x420097
    USAGE_LIMITS_UNIT                        = 0x420098
    USERNAME                                 = 0x420099
    VALIDITY_DATE                            = 0x42009A
    VALIDITY_INDICATOR                       = 0x42009B
    VENDOR_EXTENSION                         = 0x42009C
    VENDOR_IDENTIFICATION                    = 0x42009D
    WRAPPING_METHOD                          = 0x42009E
    X                                        = 0x42009F
    Y                                        = 0x4200A0
    PASSWORD                                 = 0x4200A1
    DEVICE_IDENTIFIER                        = 0x4200A2
    ENCODING_OPTION                          = 0x4200A3
    EXTENSION_INFORMATION                    = 0x4200A4
    EXTENSION_NAME                           = 0x4200A5
    EXTENSION_TAG                            = 0x4200A6
    EXTENSION_TYPE                           = 0x4200A7
    FRESH                                    = 0x4200A8
    MACHINE_IDENTIFIER                       = 0x4200A9
    MEDIA_IDENTIFIER                         = 0x4200AA
    NETWORK_IDENTIFIER                       = 0x4200AB
    OBJECT_GROUP_MEMBER                      = 0x4200AC
    CERTIFICATE_LENGTH                       = 0x4200AD
    DIGITAL_SIGNATURE_ALGORITHM              = 0x4200AE
    CERTIFICATE_SERIAL_NUMBER                = 0x4200AF
    DEVICE_SERIAL_NUMBER                     = 0x4200B0
    ISSUER_ALTERNATIVE_NAME                  = 0x4200B1
    ISSUER_DISTINGUISHED_NAME                = 0x4200B2
    SUBJECT_ALTERNATIVE_NAME                 = 0x4200B3
    SUBJECT_DISTINGUISHED_NAME               = 0x4200B4
    X_509_CERTIFICATE_IDENTIFER              = 0x4200B5
    X_509_CERTIFICATE_ISSUER                 = 0x4200B6
    X_509_CERTIFICATE_SUBJECT                = 0x4200B7
    KEY_VALUE_LOCATION                       = 0x4200B8
    KEY_VALUE_LOCATION_VALUE                 = 0x4200B9
    KEY_VALUE_LOCATION_TYPE                  = 0x4200BA
    KEY_VALUE_PRESENT                        = 0x4200BB
    ORIGINAL_CREATION_DATE                   = 0x4200BC
    PGP_KEY                                  = 0x4200BD
    PGP_KEY_VERSION                          = 0x4200BE
    ALTERNATIVE_NAME                         = 0x4200BF
    ALTERNATIVE_NAME_VALUE                   = 0x4200C0
    ALTERNATIVE_NAME_TYPE                    = 0x4200C1
    DATA                                     = 0x4200C2
    SIGNATURE_DATA                           = 0x4200C3
    DATA_LENGTH                              = 0x4200C4
    RANDOM_IV                                = 0x4200C5
    MAC_DATA                                 = 0x4200C6
    ATTESTATION_TYPE                         = 0x4200C7
    NONCE                                    = 0x4200C8
    NONCE_ID                                 = 0x4200C9
    NONCE_VALUE                              = 0x4200CA
    ATTESTATION_MEASUREMENT                  = 0x4200CB
    ATTESTATION_ASSERTION                    = 0x4200CC
    IV_LENGTH                                = 0x4200CD
    TAG_LENGTH                               = 0x4200CE
    FIXED_FIELD_LENGTH                       = 0x4200CF
    COUNTER_LENGTH                           = 0x4200D0
    INITIAL_COUNTER_VALUE                    = 0x4200D1
    INVOCATION_FIELD_LENGTH                  = 0x4200D2
    ATTESTATION_CAPABLE_INDICATOR            = 0x4200D3
    OFFSET_ITEMS                             = 0x4200D4
    LOCATED_ITEMS                            = 0x4200D5
    CORRELATION_VALUE                        = 0x4200D6
    INIT_INDICATOR                           = 0x4200D7
    FINAL_INDICATOR                          = 0x4200D8
    RNG_PARAMETERS                           = 0x4200D9
    RNG_ALGORITHM                            = 0x4200DA
    DRBG_ALGORITHM                           = 0x4200DB
    FIPS186_VARIATION                        = 0x4200DC
    PREDICTION_RESISTANCE                    = 0x4200DD
    RANDOM_NUMBER_GENERATOR                  = 0x4200DE
    VALIDATION_INFORMATION                   = 0x4200DF
    VALIDATION_AUTHORITY_TYPE                = 0x4200E0
    VALIDATION_AUTHORITY_COUNTRY             = 0x4200E1
    VALIDATION_AUTHORITY_URI                 = 0x4200E2
    VALIDATION_VERSION_MAJOR                 = 0x4200E3
    VALIDATION_VERSION_MINOR                 = 0x4200E4
    VALIDATION_TYPE                          = 0x4200E5
    VALIDATION_LEVEL                         = 0x4200E6
    VALIDATION_CERTIFICATE_IDENTIFIER        = 0x4200E7
    VALIDATION_CERTIFICATE_URI               = 0x4200E8
    VALIDATION_VENDOR_URI                    = 0x4200E9
    VALIDATION_PROFILE                       = 0x4200EA
    PROFILE_INFORMATION                      = 0x4200EB
    PROFILE_NAME                             = 0x4200EC
    SERVER_URI                               = 0x4200ED
    SERVER_PORT                              = 0x4200EE
    STREAMING_CAPABILITY                     = 0x4200EF
    ASYNCHRONOUS_CAPABILITY                  = 0x4200F0
    ATTESTATION_CAPABILITY                   = 0x4200F1
    UNWRAP_MODE                              = 0x4200F2
    DESTROY_ACTION                           = 0x4200F3
    SHREDDING_ALGORITHM                      = 0x4200F4
    RNG_MODE                                 = 0x4200F5
    CLIENT_REGISTRATION_METHOD               = 0x4200F6
    CAPABILITY_INFORMATION                   = 0x4200F7
    KEY_WRAP_TYPE                            = 0x4200F8
    BATCH_UNDO_CAPABILITY                    = 0x4200F9
    BATCH_CONTINUE_CAPABILITY                = 0x4200FA
    PKCS12_FRIENDLY_NAME                     = 0x4200FB
    DESCRIPTION                              = 0x4200FC
    COMMENT                                  = 0x4200FD
    AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA = 0x4200FE
    AUTHENTICATED_ENCRYPTION_TAG             = 0x4200FF
    SALT_LENGTH                              = 0x420100
    MASK_GENERATOR                           = 0x420101
    MASK_GENERATOR_HASHING_ALGORITHM         = 0x420102
    P_SOURCE                                 = 0x420103
    TRAILER_FIELD                            = 0x420104
    CLIENT_CORRELATION_VALUE                 = 0x420105
    SERVER_CORRELATION_VALUE                 = 0x420106
    DIGESTED_DATA                            = 0x420107
    CERTIFICATE_SUBJECT_CN                   = 0x420108
    CERTIFICATE_SUBJECT_O                    = 0x420109
    CERTIFICATE_SUBJECT_OU                   = 0x42010A
    CERTIFICATE_SUBJECT_EMAIL                = 0x42010B
    CERTIFICATE_SUBJECT_C                    = 0x42010C
    CERTIFICATE_SUBJECT_ST                   = 0x42010D
    CERTIFICATE_SUBJECT_L                    = 0x42010E
    CERTIFICATE_SUBJECT_UID                  = 0x42010F
    CERTIFICATE_SUBJECT_SERIAL_NUMBER        = 0x420110
    CERTIFICATE_SUBJECT_TITLE                = 0x420111
    CERTIFICATE_SUBJECT_DC                   = 0x420112
    CERTIFICATE_SUBJECT_DN_QUALIFIER         = 0x420113
    CERTIFICATE_ISSUER_CN                    = 0x420114
    CERTIFICATE_ISSUER_O                     = 0x420115
    CERTIFICATE_ISSUER_OU                    = 0x420116
    CERTIFICATE_ISSUER_EMAIL                 = 0x420117
    CERTIFICATE_ISSUER_C                     = 0x420118
    CERTIFICATE_ISSUER_ST                    = 0x420119
    CERTIFICATE_ISSUER_L                     = 0x42011A
    CERTIFICATE_ISSUER_UID                   = 0x42011B
    CERTIFICATE_ISSUER_SERIAL_NUMBER         = 0x42011C
    CERTIFICATE_ISSUER_TITLE                 = 0x42011D
    CERTIFICATE_ISSUER_DC                    = 0x42011E
    CERTIFICATE_ISSUER_DN_QUALIFIER          = 0x42011F
    SENSITIVE                                = 0x420120
    ALWAYS_SENSITIVE                         = 0x420121
    EXTRACTABLE                              = 0x420122
    NEVER_EXTRACTABLE                        = 0x420123
    REPLACE_EXISTING                         = 0x420124


class Types(enum.Enum):
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


class UnwrapMode(enum.Enum):
    UNSPECIFIED   = 0x00000001
    PROCESSED     = 0x00000002
    NOT_PROCESSED = 0x00000003


class UsageLimitsUnit(enum.Enum):
    BYTE   = 0x00000001
    OBJECT = 0x00000002


class ValidationAuthorityType(enum.Enum):
    UNSPECIFIED     = 0x00000001
    NIST_CMVP       = 0x00000002
    COMMON_CRITERIA = 0x00000003


class ValidationType(enum.Enum):
    UNSPECIFIED = 0x00000001
    HARDWARE    = 0x00000002
    SOFTWARE    = 0x00000003
    FIRMWARE    = 0x00000004
    HYBRID      = 0x00000005


class ValidityIndicator(enum.Enum):
    VALID   = 0x00000001
    INVALID = 0x00000002
    UNKNOWN = 0x00000003


class WrappingMethod(enum.Enum):
    ENCRYPT               = 0x00000001
    MAC_SIGN              = 0x00000002
    ENCRYPT_THEN_MAC_SIGN = 0x00000003
    MAC_SIGN_THEN_ENCRYPT = 0x00000004
    TR_31                 = 0x00000005
