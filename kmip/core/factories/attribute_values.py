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

from kmip.core import attributes
from kmip.core import enums
from kmip.core import primitives
from kmip.core import utils


class AttributeValueFactory(object):

    def create_attribute_value(self, name, value):
        # Switch on the name of the attribute
        if name is enums.AttributeType.UNIQUE_IDENTIFIER:
            return attributes.UniqueIdentifier(value)
        elif name is enums.AttributeType.NAME:
            return self._create_name(value)
        elif name is enums.AttributeType.OBJECT_TYPE:
            return attributes.ObjectType(value)
        elif name is enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM:
            return attributes.CryptographicAlgorithm(value)
        elif name is enums.AttributeType.CRYPTOGRAPHIC_LENGTH:
            return self._create_cryptographic_length(value)
        elif name is enums.AttributeType.CRYPTOGRAPHIC_PARAMETERS:
            return self._create_cryptographic_parameters(value)
        elif name is enums.AttributeType.CRYPTOGRAPHIC_DOMAIN_PARAMETERS:
            raise NotImplementedError()
        elif name is enums.AttributeType.CERTIFICATE_TYPE:
            raise NotImplementedError()
        elif name is enums.AttributeType.CERTIFICATE_LENGTH:
            return primitives.Integer(value, enums.Tags.CERTIFICATE_LENGTH)
        elif name is enums.AttributeType.X_509_CERTIFICATE_IDENTIFIER:
            raise NotImplementedError()
        elif name is enums.AttributeType.X_509_CERTIFICATE_SUBJECT:
            raise NotImplementedError()
        elif name is enums.AttributeType.X_509_CERTIFICATE_ISSUER:
            raise NotImplementedError()
        elif name is enums.AttributeType.CERTIFICATE_IDENTIFIER:
            raise NotImplementedError()
        elif name is enums.AttributeType.CERTIFICATE_SUBJECT:
            raise NotImplementedError()
        elif name is enums.AttributeType.CERTIFICATE_ISSUER:
            raise NotImplementedError()
        elif name is enums.AttributeType.DIGITAL_SIGNATURE_ALGORITHM:
            raise NotImplementedError()
        elif name is enums.AttributeType.DIGEST:
            return attributes.Digest()
        elif name is enums.AttributeType.OPERATION_POLICY_NAME:
            return attributes.OperationPolicyName(value)
        elif name is enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK:
            return self._create_cryptographic_usage_mask(value)
        elif name is enums.AttributeType.LEASE_TIME:
            return primitives.Interval(value, enums.Tags.LEASE_TIME)
        elif name is enums.AttributeType.USAGE_LIMITS:
            raise NotImplementedError()
        elif name is enums.AttributeType.STATE:
            return attributes.State(value)
        elif name is enums.AttributeType.INITIAL_DATE:
            return primitives.DateTime(value, enums.Tags.INITIAL_DATE)
        elif name is enums.AttributeType.ACTIVATION_DATE:
            return primitives.DateTime(value, enums.Tags.ACTIVATION_DATE)
        elif name is enums.AttributeType.PROCESS_START_DATE:
            return primitives.DateTime(value, enums.Tags.PROCESS_START_DATE)
        elif name is enums.AttributeType.PROTECT_STOP_DATE:
            return primitives.DateTime(value, enums.Tags.PROTECT_STOP_DATE)
        elif name is enums.AttributeType.DEACTIVATION_DATE:
            return primitives.DateTime(value, enums.Tags.DEACTIVATION_DATE)
        elif name is enums.AttributeType.DESTROY_DATE:
            return primitives.DateTime(value, enums.Tags.DESTROY_DATE)
        elif name is enums.AttributeType.COMPROMISE_OCCURRENCE_DATE:
            return primitives.DateTime(
                value, enums.Tags.COMPROMISE_OCCURRENCE_DATE)
        elif name is enums.AttributeType.COMPROMISE_DATE:
            return primitives.DateTime(value, enums.Tags.COMPROMISE_DATE)
        elif name is enums.AttributeType.REVOCATION_REASON:
            raise NotImplementedError()
        elif name is enums.AttributeType.ARCHIVE_DATE:
            return primitives.DateTime(value, enums.Tags.ARCHIVE_DATE)
        elif name is enums.AttributeType.OBJECT_GROUP:
            return self._create_object_group(value)
        elif name is enums.AttributeType.FRESH:
            return primitives.Boolean(value, enums.Tags.FRESH)
        elif name is enums.AttributeType.LINK:
            raise NotImplementedError()
        elif name is enums.AttributeType.APPLICATION_SPECIFIC_INFORMATION:
            return self._create_application_specific_information(value)
        elif name is enums.AttributeType.CONTACT_INFORMATION:
            return self._create_contact_information(value)
        elif name is enums.AttributeType.LAST_CHANGE_DATE:
            return primitives.DateTime(value, enums.Tags.LAST_CHANGE_DATE)
        elif name is enums.AttributeType.CUSTOM_ATTRIBUTE:
            return attributes.CustomAttribute(value)
        else:
            if not isinstance(name, str):
                raise ValueError('Unrecognized attribute type: '
                                 '{0}'.format(name))
            elif name.startswith('x-'):
                # Custom attribute indicated
                return attributes.CustomAttribute(value)

    def _create_name(self, name):
        if name is not None:
            if isinstance(name, attributes.Name):
                return attributes.Name.create(name.name_value, name.name_type)

            elif isinstance(name, str):
                return attributes.Name.create(
                            name,
                            enums.NameType.UNINTERPRETED_TEXT_STRING
                        )
            else:
                raise ValueError('Unrecognized attribute type: '
                                 '{0}'.format(name))
        else:
            return attributes.Name()

    def _create_cryptographic_length(self, length):
        if length is not None and not isinstance(length, int):
            msg = utils.build_er_error(attributes.CryptographicLength,
                                       'constructor argument type', int,
                                       type(length))
            raise TypeError(msg)

        return attributes.CryptographicLength(length)

    def _create_cryptographic_parameters(self, params):
        bcm = None
        padding_method = None
        hashing_algorithm = None
        key_role_type = None
        digital_signature_algorithm = None
        cryptographic_algorithm = None

        if params is not None:

            if 'block_cipher_mode' in params:
                bcm = attributes.CryptographicParameters.BlockCipherMode(
                    params.get('block_cipher_mode'))

            padding_method = None
            if 'padding_method' in params:
                padding_method = attributes.CryptographicParameters. \
                    PaddingMethod(params.get('padding_method'))

            key_role_type = None
            if 'key_role_type' in params:
                key_role_type = attributes.CryptographicParameters.KeyRoleType(
                    params.get('key_role_type'))

            hashing_algorithm = None
            if 'hashing_algorithm' in params:
                hashing_algorithm = attributes.HashingAlgorithm(
                    params.get("hashing_algorithm"))

            if 'digital_signature_algorithm' in params:
                digital_signature_algorithm = \
                    attributes.CryptographicParameters. \
                    DigitalSignatureAlgorithm(
                        params.get("digital_signature_algorithm"))

            if 'cryptographic_algorithm' in params:
                cryptographic_algorithm = attributes.CryptographicAlgorithm(
                    params.get("cryptographic_algorithm"))

        return attributes.CryptographicParameters(
            block_cipher_mode=bcm,
            padding_method=padding_method,
            hashing_algorithm=hashing_algorithm,
            key_role_type=key_role_type,
            digital_signature_algorithm=digital_signature_algorithm,
            cryptographic_algorithm=cryptographic_algorithm)

    def _create_cryptographic_usage_mask(self, flags):
        mask = None
        if flags is not None:
            mask = 0
            for flag in flags:
                mask |= flag.value

        return attributes.CryptographicUsageMask(mask)

    def _create_object_group(self, group):
        if group is not None and not isinstance(group, str):
            msg = utils.build_er_error(attributes.ObjectGroup,
                                       'constructor argument type', str,
                                       type(group))
            raise TypeError(msg)

        return attributes.ObjectGroup(group)

    def _create_application_specific_information(self, info):
        if info is None:
            return attributes.ApplicationSpecificInformation()
        else:
            application_namespace = info.get('application_namespace')
            application_data = info.get('application_data')

            if not isinstance(application_namespace, str):
                msg = utils.build_er_error(
                    attributes.ApplicationSpecificInformation,
                    'constructor argument type',
                    str, type(application_namespace))
                raise TypeError(msg)

            if not isinstance(application_data, str):
                msg = utils.build_er_error(
                    attributes.ApplicationSpecificInformation,
                    'constructor argument type',
                    str, type(application_data))
                raise TypeError(msg)

            return attributes.ApplicationSpecificInformation.create(
                application_namespace, application_data)

    def _create_contact_information(self, info):
        if info is None:
            return attributes.ContactInformation()
        else:
            if not isinstance(info, str):
                msg = utils.build_er_error(attributes.ContactInformation,
                                           'constructor argument type', str,
                                           type(info))
                raise TypeError(msg)

            return attributes.ContactInformation(info)
