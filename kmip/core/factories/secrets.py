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

from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import CryptographicLength

from kmip.core.enums import ObjectType

from kmip.core.misc import KeyFormatType

from kmip.core.objects import Attribute
from kmip.core.objects import KeyBlock
from kmip.core.objects import KeyMaterial
from kmip.core.objects import KeyWrappingData
from kmip.core.objects import KeyValue

from kmip.core.secrets import Certificate
from kmip.core.secrets import OpaqueObject
from kmip.core.secrets import PrivateKey
from kmip.core.secrets import PublicKey
from kmip.core.secrets import SecretData
from kmip.core.secrets import SplitKey
from kmip.core.secrets import SymmetricKey
from kmip.core.secrets import Template

from kmip.core import utils
from kmip.core import exceptions

class SecretFactory(object):

    def __init__(self):
        self.base_error = exceptions.ErrorStrings.BAD_EXP_RECV
        self.template_input = self.base_error.format('Template', '{0}', '{1}',
                                                     '{2}')

    def create(self, secret_type, value=None):
        """
        Create a secret object of the specified type with the given value.

        Args:
            secret_type (ObjectType): An ObjectType enumeration specifying the
                type of secret to create.
            value (dict): A dictionary containing secret data. Optional,
                defaults to None.

        Returns:
            secret: The newly constructed secret object.

        Raises:
            TypeError: If the provided secret type is unrecognized.

        Example:
            >>> factory.create(ObjectType.SYMMETRIC_KEY)
            SymmetricKey(...)
        """
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
        else:
            raise TypeError("Unrecognized secret type: {0}".format(
                secret_type))

    def _create_certificate(self, value):
        if value:
            return Certificate(
                certificate_type=value.get('certificate_type'),
                certificate_value=value.get('certificate_value')
            )
        else:
            return Certificate()

    def _create_symmetric_key(self, value):
        if value is None:
            return SymmetricKey()
        else:
            key_block = self._build_key_block(value)
            return SymmetricKey(key_block)

    def _create_public_key(self, value):
        if value is None:
            return PublicKey()
        else:
            key_block = self._build_key_block(value)
            return PublicKey(key_block)

    def _create_private_key(self, value):
        if value is None:
            return PrivateKey()
        else:
            key_block = self._build_key_block(value)
            return PrivateKey(key_block)

    def _create_split_key(self, value):
        if value is None:
            return SplitKey()
        else:
            key_block = self._build_key_block(value)
            return SplitKey(
                split_key_parts=value.get("split_key_parts"),
                key_part_identifier=value.get("key_part_identifier"),
                split_key_threshold=value.get("split_key_threshold"),
                split_key_method=value.get("split_key_method"),
                prime_field_size=value.get("prime_field_size"),
                key_block=key_block
            )

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
        if value:
            kind = SecretData.SecretDataType(value.get("secret_data_type"))
            key_block = self._build_key_block(value)
            return SecretData(kind, key_block)
        return SecretData()

    def _create_opaque_data(self, value):
        if value:
            kind = OpaqueObject.OpaqueDataType(value.get("opaque_data_type"))
            data = OpaqueObject.OpaqueDataValue(value.get("opaque_data_value"))
            return OpaqueObject(kind, data)
        return OpaqueObject()

    def _build_key_block(self, value):
        key_type = value.get('key_format_type')
        key_compression_type = value.get('key_compression_type')
        key_value = value.get('key_value')
        cryptographic_algorithm = value.get('cryptographic_algorithm')
        cryptographic_length = value.get('cryptographic_length')
        key_wrapping_data = value.get('key_wrapping_data')

        key_format_type = KeyFormatType(key_type)

        key_comp_type = None
        if key_compression_type is not None:
            key_comp_type = KeyBlock.KeyCompressionType(
                key_compression_type)

        key_material = KeyMaterial(key_value)
        key_value = KeyValue(key_material)

        crypto_algorithm = None
        if cryptographic_algorithm is not None:
            crypto_algorithm = CryptographicAlgorithm(
                cryptographic_algorithm
            )

        crypto_length = None
        if cryptographic_length is not None:
            crypto_length = CryptographicLength(cryptographic_length)

        key_wrap_data = None
        if key_wrapping_data:
            # TODO (peter-hamilton) This currently isn't used in the tests
            # TODO (peter-hamilton) but needs to be updated to properly
            # TODO (peter-hamilton) create a KeyWrappingData object.
            key_wrap_data = KeyWrappingData(**key_wrapping_data)

        key_block = KeyBlock(key_format_type,
                             key_comp_type,
                             key_value,
                             crypto_algorithm,
                             crypto_length,
                             key_wrap_data)
        return key_block
