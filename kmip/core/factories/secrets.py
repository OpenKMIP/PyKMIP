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

from kmip.core.factories.keys import KeyFactory

from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import CryptographicLength

from kmip.core.enums import ObjectType

from kmip.core.errors import ErrorStrings

from kmip.core.objects import Attribute
from kmip.core.objects import KeyBlock
from kmip.core.objects import KeyWrappingData
from kmip.core.objects import KeyValueStruct
from kmip.core.objects import KeyValue

from kmip.core.secrets import SymmetricKey
from kmip.core.secrets import Template

from kmip.core import utils


class SecretFactory(object):

    def __init__(self):
        self.key_factory = KeyFactory()

        self.base_error = ErrorStrings.BAD_EXP_RECV
        self.template_input = self.base_error.format('Template', '{0}', '{1}',
                                                     '{2}')

    def create_secret(self, secret_type, value=None):
        if secret_type is ObjectType.CERTIFICATE:
            return self._create_certificate(value)
        elif secret_type is ObjectType.SYMMETRIC_KEY:
            return self._create_symmetric_key(value)
        elif secret_type is ObjectType.PUBLIC_KEY:
            return self._create_public_key(value)
        elif secret_type is ObjectType.PRIVATE_KEY:
            return self._create_private_key(value)
        elif secret_type is ObjectType.SPLIT_KEY:
            return self._create_split_key(value)
        elif secret_type is ObjectType.TEMPLATE:
            return self._create_template(value)
        elif secret_type is ObjectType.SECRET_DATA:
            return self._create_secret_data(value)
        elif secret_type is ObjectType.OPAQUE_DATA:
            return self._create_opaque_data(value)

    def _create_certificate(self, value):
        raise NotImplementedError()

    def _create_symmetric_key(self, value):
        if value is None:
            return SymmetricKey()
        else:
            key_type = value.get('key_format_type')
            key_compression_type = value.get('key_compression_type')
            key_value = value.get('key_value')
            cryptographic_algorithm = value.get('cryptographic_algorithm')
            cryptographic_length = value.get('cryptographic_length')
            key_wrapping_data = value.get('key_wrapping_data')

            key_format_type = KeyBlock.KeyFormatType(key_type)

            key_comp_type = None
            if key_compression_type is not None:
                key_comp_type = KeyBlock.KeyCompressionType(
                    key_compression_type)

            key_material = self.key_factory.create_key(key_type,
                                                       key_value)
            key_val_struc = KeyValueStruct(key_format_type=key_format_type,
                                           key_material=key_material)
            key_value = KeyValue(key_value=key_val_struc,
                                 key_format_type=key_format_type)
            crypto_algorithm = CryptographicAlgorithm(cryptographic_algorithm)
            crypto_length = CryptographicLength(cryptographic_length)

            key_wrap_data = None
            if key_wrapping_data is not None:
                # TODO (peter-hamilton) This currently isn't used in the tests
                # TODO (peter-hamilton) but needs to be updated to properly
                # TODO (peter-hamilton) create a KeyWrappingData object.
                key_wrap_data = KeyWrappingData(key_wrapping_data)

            key_block = KeyBlock(key_format_type,
                                 key_comp_type,
                                 key_value,
                                 crypto_algorithm,
                                 crypto_length,
                                 key_wrap_data)
            return SymmetricKey(key_block)

    def _create_public_key(self, value):
        raise NotImplementedError()

    def _create_private_key(self, value):
        raise NotImplementedError()

    def _create_split_key(self, value):
        raise NotImplementedError()

    def _create_template(self, value):
        if value is None:
            return Template()
        else:
            if not isinstance(value, list):
                msg = utils.build_er_error(Template,
                                           'constructor argument type', list,
                                           type(value))
                raise TypeError(msg)
            else:
                for val in value:
                    if not isinstance(val, Attribute):
                        msg = utils.build_er_error(Template,
                                                   'constructor argument type',
                                                   Attribute, type(val))
                        raise TypeError(msg)
            return Template(value)

    def _create_secret_data(self, value):
        raise NotImplementedError()

    def _create_opaque_data(self, value):
        raise NotImplementedError()
