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

from kmip.core.enums import AttributeType

from kmip.core.attributes import ApplicationSpecificInformation
from kmip.core.attributes import ContactInformation
from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import CryptographicLength
from kmip.core.attributes import CryptographicUsageMask
from kmip.core.attributes import CustomAttribute
from kmip.core.attributes import Name
from kmip.core.attributes import ObjectGroup
from kmip.core.attributes import UniqueIdentifier

from kmip.core import utils


class AttributeValueFactory(object):

    def create_attribute_value(self, name, value):
        # Switch on the name of the attribute
        if name is AttributeType.UNIQUE_IDENTIFIER:
            value = self._create_unique_identifier(value)
        elif name is AttributeType.NAME:
            value = self._create_name(value)
        elif name is AttributeType.OBJECT_TYPE:
            value = self._create_object_type(value)
        elif name is AttributeType.CRYPTOGRAPHIC_ALGORITHM:
            value = self._create_cryptographic_algorithm(value)
        elif name is AttributeType.CRYPTOGRAPHIC_LENGTH:
            value = self._create_cryptographic_length(value)
        elif name is AttributeType.CRYPTOGRAPHIC_PARAMETERS:
            value = self._create_cryptographic_parameters(value)
        elif name is AttributeType.CRYPTOGRAPHIC_DOMAIN_PARAMETERS:
            value = self._create_cryptographic_domain_parameters(value)
        elif name is AttributeType.CERTIFICATE_TYPE:
            value = self._create_certificate_type(value)
        elif name is AttributeType.CERTIFICATE_LENGTH:
            value = self._create_certificate_length(value)
        elif name is AttributeType.X_509_CERTIFICATE_IDENTIFIER:
            value = self._create_x_509_certificate_identifier(value)
        elif name is AttributeType.X_509_CERTIFICATE_SUBJECT:
            value = self._create_x_509_certificate_subject(value)
        elif name is AttributeType.X_509_CERTIFICATE_ISSUER:
            value = self._create_x_509_certificate_issuer(value)
        elif name is AttributeType.CERTIFICATE_IDENTIFIER:
            value = self._create_certificate_identifier(value)
        elif name is AttributeType.CERTIFICATE_SUBJECT:
            value = self._create_certificate_subject(value)
        elif name is AttributeType.CERTIFICATE_ISSUER:
            value = self._create_certificate_issuer(value)
        elif name is AttributeType.DIGITAL_SIGNATURE_ALGORITHM:
            value = self._create_digital_signature_algorithm(value)
        elif name is AttributeType.DIGEST:
            value = self._create_digest(value)
        elif name is AttributeType.OPERATION_POLICY_NAME:
            value = self._create_operation_policy_name(value)
        elif name is AttributeType.CRYPTOGRAPHIC_USAGE_MASK:
            value = self._create_cryptographic_usage_mask(value)
        elif name is AttributeType.LEASE_TIME:
            value = self._create_lease_time(value)
        elif name is AttributeType.USAGE_LIMITS:
            value = self._create_usage_limits(value)
        elif name is AttributeType.STATE:
            value = self._create_state(value)
        elif name is AttributeType.INITIAL_DATE:
            value = self._create_initial_date(value)
        elif name is AttributeType.ACTIVATION_DATE:
            value = self._create_activation_date(value)
        elif name is AttributeType.PROCESS_START_DATE:
            value = self._create_process_start_date(value)
        elif name is AttributeType.PROTECT_STOP_DATE:
            value = self._create_protect_stop_date(value)
        elif name is AttributeType.DEACTIVATION_DATE:
            value = self._create_deactivation_date(value)
        elif name is AttributeType.DESTROY_DATE:
            value = self._create_destroy_date(value)
        elif name is AttributeType.COMPROMISE_OCCURRENCE_DATE:
            value = self._create_compromise_occurrence_date(value)
        elif name is AttributeType.COMPROMISE_DATE:
            value = self._create_compromise_date(value)
        elif name is AttributeType.REVOCATION_REASON:
            value = self._create_revocation_reason(value)
        elif name is AttributeType.ARCHIVE_DATE:
            value = self._create_archive_date(value)
        elif name is AttributeType.OBJECT_GROUP:
            value = self._create_object_group(value)
        elif name is AttributeType.FRESH:
            value = self._create_fresh(value)
        elif name is AttributeType.LINK:
            value = self._create_link(value)
        elif name is AttributeType.APPLICATION_SPECIFIC_INFORMATION:
            value = self._create_application_specific_information(value)
        elif name is AttributeType.CONTACT_INFORMATION:
            value = self._create_contact_information(value)
        elif name is AttributeType.LAST_CHANGE_DATE:
            value = self._create_last_change_date(value)
        elif name is AttributeType.CUSTOM_ATTRIBUTE:
            value = self._create_custom_attribute(value)
        else:
            if not isinstance(name, str):
                raise ValueError('Unrecognized attribute type: '
                                 '{}'.format(name))
            elif name.startswith('x-'):
                # Custom attribute indicated
                value = self._create_custom_attribute(value)

        return value

    def _create_unique_identifier(self, uuid):
        return UniqueIdentifier(uuid)

    def _create_name(self, name):
        if name is not None:
            name_value = name.get('name_value')
            name_type = name.get('name_type')

            return Name.create(name_value, name_type)
        else:
            return Name()

    def _create_object_type(self, obj):
        raise NotImplementedError()

    def _create_cryptographic_algorithm(self, alg):
        return CryptographicAlgorithm(alg)

    def _create_cryptographic_length(self, length):
        if length is not None and not isinstance(length, int):
            msg = utils.build_er_error(CryptographicLength,
                                       'constructor argument type', int,
                                       type(length))
            raise TypeError(msg)

        return CryptographicLength(length)

    def _create_cryptographic_parameters(self, params):
        raise NotImplementedError()

    def _create_cryptographic_domain_parameters(self, params):
        raise NotImplementedError()

    def _create_certificate_type(self, cert):
        raise NotImplementedError()

    def _create_certificate_length(self, length):
        raise NotImplementedError()

    def _create_x_509_certificate_identifier(self, ident):
        raise NotImplementedError()

    def _create_x_509_certificate_subject(self, subject):
        raise NotImplementedError()

    def _create_x_509_certificate_issuer(self, issuer):
        raise NotImplementedError()

    def _create_certificate_identifier(self, ident):
        raise NotImplementedError()

    def _create_certificate_subject(self, subject):
        raise NotImplementedError()

    def _create_certificate_issuer(self, issuer):
        raise NotImplementedError()

    def _create_digital_signature_algorithm(self, alg):
        raise NotImplementedError()

    def _create_digest(self, digest):
        raise NotImplementedError()

    def _create_operation_policy_name(self, name):
        raise NotImplementedError()

    def _create_cryptographic_usage_mask(self, flags):
        mask = None
        if flags is not None:
            mask = 0
            for flag in flags:
                mask |= flag.value

        return CryptographicUsageMask(mask)

    def _create_lease_time(self, lease):
        raise NotImplementedError()

    def _create_usage_limits(self, limits):
        raise NotImplementedError()

    def _create_state(self, state):
        raise NotImplementedError()

    def _create_initial_date(self, date):
        raise NotImplementedError()

    def _create_activation_date(self, date):
        raise NotImplementedError()

    def _create_process_start_date(self, date):
        raise NotImplementedError()

    def _create_protect_stop_date(self, date):
        raise NotImplementedError()

    def _create_deactivation_date(self, date):
        raise NotImplementedError()

    def _create_destroy_date(self, date):
        raise NotImplementedError()

    def _create_compromise_occurrence_date(self, date):
        raise NotImplementedError()

    def _create_compromise_date(self, date):
        raise NotImplementedError()

    def _create_revocation_reason(self, reason):
        raise NotImplementedError()

    def _create_archive_date(self, date):
        raise NotImplementedError()

    def _create_object_group(self, group):
        if group is not None and not isinstance(group, str):
            msg = utils.build_er_error(ObjectGroup,
                                       'constructor argument type', str,
                                       type(group))
            raise TypeError(msg)

        return ObjectGroup(group)

    def _create_fresh(self, fresh):
        raise NotImplementedError()

    def _create_link(self, link):
        raise NotImplementedError()

    def _create_application_specific_information(self, info):
        if info is None:
            return ApplicationSpecificInformation()
        else:
            application_namespace = info.get('application_namespace')
            application_data = info.get('application_data')

            if not isinstance(application_namespace, str):
                msg = utils.build_er_error(ApplicationSpecificInformation,
                                           'constructor argument type',
                                           str, type(application_namespace))
                raise TypeError(msg)

            if not isinstance(application_data, str):
                msg = utils.build_er_error(ApplicationSpecificInformation,
                                           'constructor argument type',
                                           str, type(application_data))
                raise TypeError(msg)

            return ApplicationSpecificInformation.create(application_namespace,
                                                         application_data)

    def _create_contact_information(self, info):
        if info is None:
            return ContactInformation()
        else:
            if not isinstance(info, str):
                msg = utils.build_er_error(ContactInformation,
                                           'constructor argument type', str,
                                           type(info))
                raise TypeError(msg)

            return ContactInformation(info)

    def _create_last_change_date(self, date):
        raise NotImplementedError()

    def _create_custom_attribute(self, data):
        return CustomAttribute(data)
