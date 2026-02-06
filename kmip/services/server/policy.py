# Copyright (c) 2016 The Johns Hopkins University/Applied Physics Laboratory
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

from kmip.core import enums
from kmip.core.messages import contents

class AttributeRuleSet(object):
    """
    A set of flags and indicators defining how an attribute may be used.

    Every attribute defined by the KMIP specification comes with a set of
    rules defining how and under what conditions the attribute should be
    used. This class acts as a basic struct storing those rules.

    Attributes:
        always_has_value: A flag defining if the attribute is always set.
        initially_set_by: A list of entities that can implicitly set the
            attribute.
        modifiable_by_server: A flag defining if the server can modify the
            attribute.
        modifiable_by_client: A flag defining if the client can modify the
            attribute.
        deletable_by_client: A flag defining if the client can delete the
            attribute.
        multiple_instances_permitted: A flag defining if the attribute is
            multivalued.
        implicitly_set_by: A list of operations that can implicitly set the
            attribute.
        applies_to_object_types: A list of object types that the attribute
            is applicable for.
        version_added: The KMIP version in which support for the attribute
            was added.
        version_deprecated: The KMIP version in which support for the
            attribute was deprecated.
    """

    def __init__(self,
                 always_has_value,
                 initially_set_by,
                 modifiable_by_server,
                 modifiable_by_client,
                 deletable_by_client,
                 multivalued,
                 implicitly_set_by,
                 applies_to_object_types,
                 version_added,
                 version_deprecated=None):
        """
        Create an AttributeRuleSet.

        Args:
            always_has_value (bool): A flag indicating whether or not this
                attribute is always set for a managed object. Required.
            initially_set_by (list): A list of strings indicating if the
                attribute can be initially set by the 'server' and/or the
                'client'. Required.
            modifiable_by_server (bool): A flag indicating whether the server
                can independently modify the value of the attribute without
                any prompting by the client. Required.
            modifiable_by_client (bool): A flag indicating whether the client
                can modify the value of the attribute. Required.
            deletable_by_client (bool): A flag indicating whether the client
                can delete the attribute from the managed object. Required.
            multivalued (bool): A flag indicating whether or not a managed
                object can have multiple instances of the attribute set at
                the same time. Required.
            implicitly_set_by (list): A list of Operation enumerations
                detailing which server operations are allowed to set the
                value of the attribute without direct instruction by the
                client.Required.
            applies_to_object_types (list): A list of ObjectType enumerations
                detailing which managed object types the attribute applies to.
            version_added (ProtocolVersion): The KMIP version in which support
                for the attribute was added. Required.
            version_deprecated (ProtocolVersion): The KMIP version in which
                support for the attribute was deprecated. Optional, defaults
                to None.
        """
        self.always_has_value = always_has_value
        self.initially_set_by = initially_set_by
        self.modifiable_by_server = modifiable_by_server
        self.modifiable_by_client = modifiable_by_client
        self.deletable_by_client = deletable_by_client
        self.multiple_instances_permitted = multivalued
        self.implicitly_set_by = implicitly_set_by
        self.applies_to_object_types = applies_to_object_types
        self.version_added = version_added
        self.version_deprecated = version_deprecated

class AttributePolicy(object):
    """
    A collection of attribute rules and methods to query those rules.

    This policy class allows for the basic storage and retrieval of
    attribute metadata. This metadata changes slightly across KMIP versions
    and across the object types associated with different attributes. It
    includes information on which entities can modify the attributes, which
    object types the attributes are applicable to, and more. It is meant to
    be used only by the KmipEngine.

    Metadata queries include questions like:
    * Is this attribute supported in KMIP 1.0?
    * Is this attribute deprecated in KMIP 1.1?
    * Is this attribute applicable for the SymmetricKey object type?
    * Is this attribute allowed to have multiple values?
    """

    def __init__(self, version):
        """
        Create an AttributePolicy.

        Args:
            version (ProtocolVersion): The KMIP protocol version under which
                this set of attribute policies should be evaluated. Required.
        """
        self._version = version

        # TODO (peterhamilton) Alphabetize these
        self._attribute_rule_sets = {
            'Unique Identifier': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Name': AttributeRuleSet(
                False,
                ('client', ),
                True,
                True,
                True,
                True,
                (
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Object Type': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Cryptographic Algorithm': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Cryptographic Length': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Cryptographic Parameters': AttributeRuleSet(
                False,
                ('client', ),
                False,
                True,
                True,
                True,
                (
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Cryptographic Domain Parameters': AttributeRuleSet(
                False,
                ('client', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.TEMPLATE
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Certificate Type': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.REGISTER,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Certificate Length': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.REGISTER,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                ),
                contents.ProtocolVersion(1, 1)
            ),
            'X.509 Certificate Identifier': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.REGISTER,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY
                ),
                (
                    # TODO (peterhamilton) Enforce only on X.509 certificates
                    enums.ObjectType.CERTIFICATE,
                ),
                contents.ProtocolVersion(1, 1)
            ),
            'X.509 Certificate Subject': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.REGISTER,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY
                ),
                (
                    # TODO (peterhamilton) Enforce only on X.509 certificates
                    enums.ObjectType.CERTIFICATE,
                ),
                contents.ProtocolVersion(1, 1)
            ),
            'X.509 Certificate Issuer': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.REGISTER,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY
                ),
                (
                    # TODO (peterhamilton) Enforce only on X.509 certificates
                    enums.ObjectType.CERTIFICATE,
                ),
                contents.ProtocolVersion(1, 1)
            ),
            'Certificate Identifier': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.REGISTER,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                ),
                contents.ProtocolVersion(1, 0),
                contents.ProtocolVersion(1, 1)
            ),
            'Certificate Subject': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.REGISTER,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                ),
                contents.ProtocolVersion(1, 0),
                contents.ProtocolVersion(1, 1)
            ),
            'Certificate Issuer': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.REGISTER,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                ),
                contents.ProtocolVersion(1, 0),
                contents.ProtocolVersion(1, 1)
            ),
            'Digital Signature Algorithm': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                # TODO (peterhamilton) Enforce only for X.509 certificates
                False,  # True for PGP certificates
                (
                    enums.Operation.REGISTER,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                ),
                contents.ProtocolVersion(1, 1)
            ),
            'Digest': AttributeRuleSet(
                True,  # If the server has access to the data
                ('server', ),
                False,
                False,
                False,
                True,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Operation Policy Name': AttributeRuleSet(
                False,
                ('server', 'client'),
                True,
                False,
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0),
                contents.ProtocolVersion(2, 0)
            ),
            'Cryptographic Usage Mask': AttributeRuleSet(
                True,
                ('server', 'client'),
                True,
                False,
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Lease Time': AttributeRuleSet(
                False,
                ('server', ),
                True,
                False,
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.SECRET_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Usage Limits': AttributeRuleSet(
                False,
                ('server', 'client'),  # Values differ based on source
                True,
                True,  # Conditional on values and operations used
                True,  # Conditional on operations used
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR,
                    enums.Operation.GET_USAGE_ALLOCATION
                ),
                (
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'State': AttributeRuleSet(
                True,
                ('server', ),
                True,
                False,  # Only modifiable by server for certain requests
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.ACTIVATE,
                    enums.Operation.REVOKE,
                    enums.Operation.DESTROY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.SECRET_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Initial Date': AttributeRuleSet(
                True,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Activation Date': AttributeRuleSet(
                False,
                ('server', 'client'),
                True,  # Only while in Pre-Active state
                True,  # Only while in Pre-Active state
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.ACTIVATE,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Process Start Date': AttributeRuleSet(
                False,
                ('server', 'client'),
                True,  # Only while in Pre-Active / Active state and more
                True,  # Only while in Pre-Active / Active state and more
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.REKEY
                ),
                (
                    enums.ObjectType.SYMMETRIC_KEY,
                    # Only SplitKeys of SymmetricKeys
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Protect Stop Date': AttributeRuleSet(
                False,
                ('server', 'client'),
                True,  # Only while in Pre-Active / Active state and more
                True,  # Only while in Pre-Active / Active state and more
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.REKEY
                ),
                (
                    enums.ObjectType.SYMMETRIC_KEY,
                    # Only SplitKeys of SymmetricKeys
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Deactivation Date': AttributeRuleSet(
                False,
                ('server', 'client'),
                True,  # Only while in Pre-Active / Active state
                True,  # Only while in Pre-Active / Active state
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.REVOKE,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Destroy Date': AttributeRuleSet(
                False,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.DESTROY,
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Compromise Occurrence Date': AttributeRuleSet(
                False,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.REVOKE,
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Compromise Date': AttributeRuleSet(
                False,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.REVOKE,
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Revocation Reason': AttributeRuleSet(
                False,
                ('server', ),
                True,
                False,
                False,
                False,
                (
                    enums.Operation.REVOKE,
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Archive Date': AttributeRuleSet(
                False,
                ('server', ),
                False,
                False,
                False,
                False,
                (
                    enums.Operation.ARCHIVE,
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Object Group': AttributeRuleSet(
                False,
                ('server', 'client'),
                True,
                True,
                True,
                True,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Fresh': AttributeRuleSet(
                False,
                ('server', 'client'),
                True,
                False,
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 1)
            ),
            'Link': AttributeRuleSet(
                False,
                ('server', ),
                True,
                True,
                True,
                True,
                (
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Application Specific Information': AttributeRuleSet(
                False,
                ('server', 'client'),  # Only if omitted in client request
                True,  # Only if attribute omitted in client request
                True,
                True,
                True,
                (
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Contact Information': AttributeRuleSet(
                False,
                ('server', 'client'),
                True,
                True,
                True,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Last Change Date': AttributeRuleSet(
                True,
                ('server', ),
                True,
                False,
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.ACTIVATE,
                    enums.Operation.REVOKE,
                    enums.Operation.DESTROY,
                    enums.Operation.ARCHIVE,
                    enums.Operation.RECOVER,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR,
                    enums.Operation.ADD_ATTRIBUTE,
                    enums.Operation.MODIFY_ATTRIBUTE,
                    enums.Operation.DELETE_ATTRIBUTE,
                    enums.Operation.GET_USAGE_ALLOCATION
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            'Custom Attribute': AttributeRuleSet(
                False,
                ('server', 'client'),
                True,  # Only for server-created attributes
                True,  # Only for client-created attributes
                True,  # Only for client-created attributes
                True,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER,
                    enums.Operation.DERIVE_KEY,
                    enums.Operation.ACTIVATE,
                    enums.Operation.REVOKE,
                    enums.Operation.DESTROY,
                    enums.Operation.CERTIFY,
                    enums.Operation.RECERTIFY,
                    enums.Operation.REKEY,
                    enums.Operation.REKEY_KEY_PAIR
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 0)
            ),
            "Sensitive": AttributeRuleSet(
                True,
                ("server", "client"),
                True,
                True,
                False,
                False,
                (
                    enums.Operation.CREATE,
                    enums.Operation.CREATE_KEY_PAIR,
                    enums.Operation.REGISTER
                ),
                (
                    enums.ObjectType.CERTIFICATE,
                    enums.ObjectType.SYMMETRIC_KEY,
                    enums.ObjectType.PUBLIC_KEY,
                    enums.ObjectType.PRIVATE_KEY,
                    enums.ObjectType.SPLIT_KEY,
                    enums.ObjectType.TEMPLATE,
                    enums.ObjectType.SECRET_DATA,
                    enums.ObjectType.OPAQUE_DATA
                ),
                contents.ProtocolVersion(1, 4)
            )
        }

    def is_attribute_supported(self, attribute):
        """
        Check if the attribute is supported by the current KMIP version.

        Args:
            attribute (string): The name of the attribute
                (e.g., 'Cryptographic Algorithm'). Required.
        Returns:
            bool: True if the attribute is supported by the current KMIP
                version. False otherwise.
        """
        if attribute not in self._attribute_rule_sets.keys():
            return False

        rule_set = self._attribute_rule_sets.get(attribute)
        if self._version >= rule_set.version_added:
            return True
        else:
            return False

    def is_attribute_deprecated(self, attribute):
        """
        Check if the attribute is deprecated by the current KMIP version.

        Args:
            attribute (string): The name of the attribute
                (e.g., 'Unique Identifier'). Required.
        """
        rule_set = self._attribute_rule_sets.get(attribute)
        if rule_set.version_deprecated:
            if self._version >= rule_set.version_deprecated:
                return True
            else:
                return False
        else:
            return False

    def is_attribute_deletable_by_client(self, attribute):
        """
        Check if the attribute can be deleted by the client.

        Args:
            attribute (string): The name of the attribute (e.g., "Name").

        Returns:
            bool: True if the attribute can be deleted by the client. False
                otherwise.
        """
        rule_set = self._attribute_rule_sets.get(attribute)
        return rule_set.deletable_by_client

    def is_attribute_modifiable_by_client(self, attribute):
        """
        Check if the attribute can be modified by the client.

        Args:
            attribute (string): The name of the attribute (e.g., "Name").

        Returns:
            bool: True if the attribute can be modified by the client. False
                otherwise.
        """
        rule_set = self._attribute_rule_sets.get(attribute)
        return rule_set.modifiable_by_client

    def is_attribute_applicable_to_object_type(self, attribute, object_type):
        """
        Check if the attribute is supported by the given object type.

        Args:
            attribute (string): The name of the attribute (e.g., 'Name').
                Required.
            object_type (ObjectType): An ObjectType enumeration
                (e.g., ObjectType.SYMMETRIC_KEY). Required.
        Returns:
            bool: True if the attribute is applicable to the object type.
                False otherwise.
        """
        # TODO (peterhamilton) Handle applicability between certificate types
        rule_set = self._attribute_rule_sets.get(attribute)
        if object_type in rule_set.applies_to_object_types:
            return True
        else:
            return False

    def is_attribute_multivalued(self, attribute):
        """
        Check if the attribute is allowed to have multiple instances.

        Args:
            attribute (string): The name of the attribute
                (e.g., 'State'). Required.
        """
        # TODO (peterhamilton) Handle multivalue swap between certificate types
        rule_set = self._attribute_rule_sets.get(attribute)
        return rule_set.multiple_instances_permitted

    def get_all_attribute_names(self):
        """
        Get a list of all supported attribute names.

        Returns:
            list: A list of string attribute names.
        """
        return self._attribute_rule_sets.keys()
