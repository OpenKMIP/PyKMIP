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

import binascii
from six.moves import xrange

from kmip.core import attributes
from kmip.core.attributes import CryptographicParameters

from kmip.core.factories.attribute_values import AttributeValueFactory

from kmip.core import enums
from kmip.core.enums import AttributeType
from kmip.core.enums import Tags
from kmip.core.enums import Types
from kmip.core.enums import CredentialType
from kmip.core.enums import RevocationReasonCode as RevocationReasonCodeEnum

from kmip.core.errors import ErrorStrings
from kmip.core.misc import KeyFormatType

from kmip.core.primitives import Struct
from kmip.core.primitives import TextString
from kmip.core.primitives import ByteString
from kmip.core.primitives import Integer
from kmip.core.primitives import Enumeration

from kmip.core.utils import BytearrayStream


# 2.1
# 2.1.1
class Attribute(Struct):

    class AttributeName(TextString):

        def __init__(self, value=None):
            super(Attribute.AttributeName, self).__init__(
                value, Tags.ATTRIBUTE_NAME)

        def __eq__(self, other):
            if isinstance(other, Attribute.AttributeName):
                if self.value != other.value:
                    return False
                else:
                    return True
            else:
                NotImplemented

        def __ne__(self, other):
            if isinstance(other, Attribute.AttributeName):
                return not (self == other)
            else:
                return NotImplemented

    class AttributeIndex(Integer):

        def __init__(self, value=None):
            super(Attribute.AttributeIndex, self).__init__(
                value, Tags.ATTRIBUTE_INDEX)

    def __init__(self,
                 attribute_name=None,
                 attribute_index=None,
                 attribute_value=None):
        super(Attribute, self).__init__(tag=Tags.ATTRIBUTE)

        self.value_factory = AttributeValueFactory()

        self.attribute_name = attribute_name
        self.attribute_index = attribute_index
        self.attribute_value = attribute_value

        if attribute_value is not None:
            attribute_value.tag = Tags.ATTRIBUTE_VALUE

    def read(self, istream):
        super(Attribute, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        # Read the name of the attribute
        self.attribute_name = Attribute.AttributeName()
        self.attribute_name.read(tstream)

        # Read the attribute index if it is next
        if self.is_tag_next(Tags.ATTRIBUTE_INDEX, tstream):
            self.attribute_index = Attribute.AttributeIndex()
            self.attribute_index.read(tstream)

        # Lookup the attribute class that belongs to the attribute name
        name = self.attribute_name.value
        enum_name = name.replace('.', '_').replace(' ', '_').upper()
        enum_type = None

        try:
            enum_type = AttributeType[enum_name]
        except KeyError:
            # Likely custom attribute, pass raw name string as attribute type
            enum_type = name

        value = self.value_factory.create_attribute_value(enum_type, None)
        self.attribute_value = value
        self.attribute_value.tag = Tags.ATTRIBUTE_VALUE
        self.attribute_value.read(tstream)

        self.is_oversized(tstream)

    def write(self, ostream):
        tstream = BytearrayStream()

        self.attribute_name.write(tstream)
        if self.attribute_index is not None:
            self.attribute_index.write(tstream)
        self.attribute_value.write(tstream)

        # Write the length and value of the attribute
        self.length = tstream.length()
        super(Attribute, self).write(ostream)
        ostream.write(tstream.buffer)

    def __repr__(self):
        attribute_name = "attribute_name={0}".format(repr(self.attribute_name))
        attribute_index = "attribute_index={0}".format(
            repr(self.attribute_index)
        )
        attribute_value = "attribute_value={0}".format(
            repr(self.attribute_value)
        )
        return "Attribute({0}, {1}, {2})".format(
            attribute_name,
            attribute_index,
            attribute_value
        )

    def __str__(self):
        return str({
            'attribute_name': str(self.attribute_name),
            'attribute_index': str(self.attribute_index),
            'attribute_value': str(self.attribute_value)
        })

    def __eq__(self, other):
        if isinstance(other, Attribute):
            if self.attribute_name != other.attribute_name:
                return False
            elif self.attribute_index != other.attribute_index:
                return False
            elif self.attribute_value != other.attribute_value:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Attribute):
            return not self.__eq__(other)
        else:
            return NotImplemented


# 2.1.2
class Credential(Struct):

    class CredentialType(Enumeration):

        def __init__(self, value=None):
            super(Credential.CredentialType, self).__init__(
                CredentialType, value, Tags.CREDENTIAL_TYPE)

    class UsernamePasswordCredential(Struct):

        class Username(TextString):
            def __init__(self, value=None):
                super(Credential.UsernamePasswordCredential.Username,
                      self).__init__(
                    value, Tags.USERNAME)

        class Password(TextString):
            def __init__(self, value=None):
                super(Credential.UsernamePasswordCredential.Password,
                      self).__init__(
                    value, Tags.PASSWORD)

        def __init__(self, username=None, password=None):
            super(Credential.UsernamePasswordCredential, self).__init__(
                tag=Tags.CREDENTIAL_VALUE)
            self.username = username
            self.password = password
            self.validate()

        def read(self, istream):
            super(Credential.UsernamePasswordCredential, self).read(istream)
            tstream = BytearrayStream(istream.read(self.length))

            # Read the username of the credential
            self.username = self.Username()
            self.username.read(tstream)

            # Read the password if it is next
            if self.is_tag_next(Tags.PASSWORD, tstream):
                self.password = self.Password()
                self.password.read(tstream)

            self.is_oversized(tstream)
            self.validate()

        def write(self, ostream):
            tstream = BytearrayStream()

            self.username.write(tstream)
            if self.password is not None:
                self.password.write(tstream)

            # Write the length and value of the credential
            self.length = tstream.length()
            super(Credential.UsernamePasswordCredential, self).write(ostream)
            ostream.write(tstream.buffer)

        def validate(self):
            pass

    class DeviceCredential(Struct):

        class DeviceSerialNumber(TextString):

            def __init__(self, value=None):
                super(Credential.DeviceCredential.DeviceSerialNumber, self).\
                    __init__(value, Tags.DEVICE_SERIAL_NUMBER)

        class Password(TextString):

            def __init__(self, value=None):
                super(Credential.DeviceCredential.Password, self).\
                    __init__(value, Tags.PASSWORD)

        class DeviceIdentifier(TextString):

            def __init__(self, value=None):
                super(Credential.DeviceCredential.DeviceIdentifier, self).\
                    __init__(value, Tags.DEVICE_IDENTIFIER)

        class NetworkIdentifier(TextString):

            def __init__(self, value=None):
                super(Credential.DeviceCredential.NetworkIdentifier, self).\
                    __init__(value, Tags.NETWORK_IDENTIFIER)

        class MachineIdentifier(TextString):

            def __init__(self, value=None):
                super(Credential.DeviceCredential.MachineIdentifier, self).\
                    __init__(value, Tags.MACHINE_IDENTIFIER)

        class MediaIdentifier(TextString):

            def __init__(self, value=None):
                super(Credential.DeviceCredential.MediaIdentifier, self).\
                    __init__(value, Tags.MEDIA_IDENTIFIER)

        def __init__(self,
                     device_serial_number=None,
                     password=None,
                     device_identifier=None,
                     network_identifier=None,
                     machine_identifier=None,
                     media_identifier=None):
            super(Credential.DeviceCredential, self).__init__(
                tag=Tags.CREDENTIAL_VALUE)
            self.device_serial_number = device_serial_number
            self.password = password
            self.device_identifier = device_identifier
            self.network_identifier = network_identifier
            self.machine_identifier = machine_identifier
            self.media_identifier = media_identifier

        def read(self, istream):
            super(Credential.DeviceCredential, self).read(istream)
            tstream = BytearrayStream(istream.read(self.length))

            # Read the password if it is next
            if self.is_tag_next(Tags.DEVICE_SERIAL_NUMBER, tstream):
                self.device_serial_number = self.DeviceSerialNumber()
                self.device_serial_number.read(tstream)

            # Read the password if it is next
            if self.is_tag_next(Tags.PASSWORD, tstream):
                self.password = self.Password()
                self.password.read(tstream)

            # Read the password if it is next
            if self.is_tag_next(Tags.DEVICE_IDENTIFIER, tstream):
                self.device_identifier = self.DeviceIdentifier()
                self.device_identifier.read(tstream)

            # Read the password if it is next
            if self.is_tag_next(Tags.NETWORK_IDENTIFIER, tstream):
                self.network_identifier = self.NetworkIdentifier()
                self.network_identifier.read(tstream)

            # Read the password if it is next
            if self.is_tag_next(Tags.MACHINE_IDENTIFIER, tstream):
                self.machine_identifier = self.MachineIdentifier()
                self.machine_identifier.read(tstream)

            # Read the password if it is next
            if self.is_tag_next(Tags.MEDIA_IDENTIFIER, tstream):
                self.media_identifier = self.MediaIdentifier()
                self.media_identifier.read(tstream)

            self.is_oversized(tstream)
            self.validate()

        def write(self, ostream):
            tstream = BytearrayStream()

            if self.device_serial_number is not None:
                self.device_serial_number.write(tstream)
            if self.password is not None:
                self.password.write(tstream)
            if self.device_identifier is not None:
                self.device_identifier.write(tstream)
            if self.network_identifier is not None:
                self.network_identifier.write(tstream)
            if self.machine_identifier is not None:
                self.machine_identifier.write(tstream)
            if self.media_identifier is not None:
                self.media_identifier.write(tstream)

            # Write the length and value of the credential
            self.length = tstream.length()
            super(Credential.DeviceCredential, self).write(ostream)
            ostream.write(tstream.buffer)

        def validate(self):
            pass

    def __init__(self, credential_type=None, credential_value=None):
        super(Credential, self).__init__(tag=Tags.CREDENTIAL)
        self.credential_type = credential_type
        self.credential_value = credential_value

    def read(self, istream):
        super(Credential, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        # Read the type of the credential
        self.credential_type = self.CredentialType()
        self.credential_type.read(tstream)

        # Use the type to determine what credential value to read
        if self.credential_type.value is CredentialType.USERNAME_AND_PASSWORD:
            self.credential_value = self.UsernamePasswordCredential()
        elif self.credential_type.value is CredentialType.DEVICE:
            self.credential_value = self.DeviceCredential()
        else:
            # TODO (peter-hamilton) Use more descriptive error here
            raise NotImplementedError()
        self.credential_value.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.credential_type.write(tstream)
        self.credential_value.write(tstream)

        # Write the length and value of the credential
        self.length = tstream.length()
        super(Credential, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        pass


# 2.1.3
class KeyBlock(Struct):

    class KeyCompressionType(Enumeration):

        def __init__(self, value=None):
            super(KeyBlock.KeyCompressionType, self).__init__(
                enums.KeyCompressionType, value, Tags.KEY_COMPRESSION_TYPE)

    def __init__(self,
                 key_format_type=None,
                 key_compression_type=None,
                 key_value=None,
                 cryptographic_algorithm=None,
                 cryptographic_length=None,
                 key_wrapping_data=None):
        super(KeyBlock, self).__init__(Tags.KEY_BLOCK)
        self.key_format_type = key_format_type
        self.key_compression_type = key_compression_type
        self.key_value = key_value
        self.cryptographic_algorithm = cryptographic_algorithm
        self.cryptographic_length = cryptographic_length
        self.key_wrapping_data = key_wrapping_data
        self.validate()

    def read(self, istream):
        super(KeyBlock, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.key_format_type = KeyFormatType()
        self.key_format_type.read(tstream)

        if self.is_tag_next(Tags.KEY_COMPRESSION_TYPE, tstream):
            self.key_compression_type = KeyBlock.KeyCompressionType()
            self.key_compression_type.read(tstream)

        self.key_value = KeyValue()
        self.key_value.read(tstream)

        if self.is_tag_next(Tags.CRYPTOGRAPHIC_ALGORITHM, tstream):
            self.cryptographic_algorithm = attributes.CryptographicAlgorithm()
            self.cryptographic_algorithm.read(tstream)

        if self.is_tag_next(Tags.CRYPTOGRAPHIC_LENGTH, tstream):
            self.cryptographic_length = attributes.CryptographicLength()
            self.cryptographic_length.read(tstream)

        if self.is_tag_next(Tags.KEY_WRAPPING_DATA, tstream):
            self.key_wrapping_data = KeyWrappingData()
            self.key_wrapping_data.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.key_format_type.write(tstream)

        if self.key_compression_type is not None:
            self.key_compression_type.write(tstream)

        self.key_value.write(tstream)

        if self.cryptographic_algorithm is not None:
            self.cryptographic_algorithm.write(tstream)
        if self.cryptographic_length is not None:
            self.cryptographic_length.write(tstream)
        if self.key_wrapping_data is not None:
            self.key_wrapping_data.write(tstream)

        # Write the length and value of the credential
        self.length = tstream.length()
        super(KeyBlock, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.key_format_type is not None:
            if type(self.key_format_type) is not KeyFormatType:
                member = 'KeyBlock.key_format_type'
                exp_type = KeyFormatType
                rcv_type = type(self.key_format_type)
                msg = ErrorStrings.BAD_EXP_RECV.format(member, 'type',
                                                       exp_type, rcv_type)
                raise TypeError(msg)


# 2.1.4
class KeyMaterial(ByteString):

    def __init__(self, value=None):
        super(KeyMaterial, self).__init__(value, Tags.KEY_MATERIAL)


# TODO (peter-hamilton) Get rid of this and replace with a KeyMaterial factory.
class KeyMaterialStruct(Struct):

    def __init__(self):
        super(KeyMaterialStruct, self).__init__(Tags.KEY_MATERIAL)

        self.data = BytearrayStream()

        self.validate()

    def read(self, istream):
        super(KeyMaterialStruct, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.data = BytearrayStream(tstream.read())

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()
        tstream.write(self.data.buffer)

        self.length = tstream.length()
        super(KeyMaterialStruct, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # NOTE (peter-hamilton): Intentional pass, no way to validate data.
        pass


class KeyValue(Struct):

    def __init__(self,
                 key_material=None,
                 attributes=None):
        super(KeyValue, self).__init__(Tags.KEY_VALUE)

        if key_material is None:
            self.key_material = KeyMaterial()
        else:
            self.key_material = key_material

        if attributes is None:
            self.attributes = list()
        else:
            self.attributes = attributes

        self.validate()

    def read(self, istream):
        super(KeyValue, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        # TODO (peter-hamilton) Replace this with a KeyMaterial factory.
        if self.is_type_next(Types.STRUCTURE, tstream):
            self.key_material = KeyMaterialStruct()
            self.key_material.read(tstream)
        else:
            self.key_material = KeyMaterial()
            self.key_material.read(tstream)

        while self.is_tag_next(Tags.ATTRIBUTE, tstream):
            attribute = Attribute()
            attribute.read(tstream)
            self.attributes.append(attribute)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.key_material.write(tstream)

        for attribute in self.attributes:
            attribute.write(tstream)

        self.length = tstream.length()
        super(KeyValue, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Replace with check against KeyMaterial factory.
        if not isinstance(self.key_material, KeyMaterial):
            msg = "invalid key material"
            msg += "; expected {0}, received {1}".format(
                KeyMaterial, self.key_material)
            raise TypeError(msg)

        if isinstance(self.attributes, list):
            for i in xrange(len(self.attributes)):
                attribute = self.attributes[i]
                if not isinstance(attribute, Attribute):
                    msg = "invalid attribute ({0} in list)".format(i)
                    msg += "; expected {0}, received {1}".format(
                        Attribute, attribute)
                    raise TypeError(msg)
        else:
            msg = "invalid attributes list"
            msg += "; expected {0}, received {1}".format(
                list, self.attributes)
            raise TypeError(msg)


# 2.1.5
class WrappingMethod(Enumeration):

    def __init__(self, value=None):
        super(WrappingMethod, self).__init__(
            enums.WrappingMethod, value, Tags.WRAPPING_METHOD)


class EncodingOption(Enumeration):

    def __init__(self, value=None):
        super(EncodingOption, self).__init__(
            enums.EncodingOption, value, Tags.ENCODING_OPTION)


class KeyInformation(Struct):

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None,
                 tag=Tags.ENCRYPTION_KEY_INFORMATION):
        super(KeyInformation, self).__init__(tag=tag)
        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.validate()

    def read(self, istream):
        super(KeyInformation, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.unique_identifier = attributes.UniqueIdentifier()
        self.unique_identifier.read(tstream)

        if self.is_tag_next(Tags.CRYPTOGRAPHIC_PARAMETERS, tstream):
            self.cryptographic_parameters = CryptographicParameters()
            self.cryptographic_parameters.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.unique_identifier.write(tstream)

        if self.cryptographic_parameters is not None:
            self.cryptographic_parameters.write(tstream)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(KeyInformation, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


class EncryptionKeyInformation(KeyInformation):

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None,
                 tag=Tags.ENCRYPTION_KEY_INFORMATION):
        super(EncryptionKeyInformation, self).__init__(
            unique_identifier, cryptographic_parameters, tag)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


class MACSignatureKeyInformation(KeyInformation):

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None,
                 tag=Tags.MAC_SIGNATURE_KEY_INFORMATION):
        super(MACSignatureKeyInformation, self).__init__(
            unique_identifier, cryptographic_parameters, tag)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


class KeyWrappingData(Struct):

    class MACSignature(ByteString):

        def __init__(self, value=None):
            super(KeyWrappingData.MACSignature, self).__init__(
                value, Tags.MAC_SIGNATURE)

    class IVCounterNonce(ByteString):

        def __init__(self, value=None):
            super(KeyWrappingData.IVCounterNonce, self).__init__(
                value, Tags.IV_COUNTER_NONCE)

    def __init__(self,
                 wrapping_method=None,
                 encryption_key_information=None,
                 mac_signature_key_information=None,
                 mac_signature=None,
                 iv_counter_nonce=None,
                 encoding_option=None):
        super(KeyWrappingData, self).__init__(Tags.KEY_WRAPPING_DATA)
        self.wrapping_method = wrapping_method
        self.encryption_key_information = encryption_key_information
        self.mac_signature_key_information = mac_signature_key_information
        self.mac_signature = mac_signature
        self.iv_counter_nonce = iv_counter_nonce
        self.encoding_option = encoding_option
        self.validate()

    def read(self, istream):
        super(KeyWrappingData, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.wrapping_method = WrappingMethod()
        self.wrapping_method.read(tstream)

        if self.is_tag_next(Tags.ENCRYPTION_KEY_INFORMATION, tstream):
            self.encryption_key_information = EncryptionKeyInformation()
            self.encryption_key_information.read(tstream)

        if self.is_tag_next(Tags.MAC_SIGNATURE_KEY_INFORMATION, tstream):
            self.mac_signature_key_information = MACSignatureKeyInformation()
            self.mac_signature_key_information.read(tstream)

        if self.is_tag_next(Tags.MAC_SIGNATURE, tstream):
            self.mac_signature = KeyWrappingData.MACSignature()
            self.mac_signature.read(tstream)

        if self.is_tag_next(Tags.IV_COUNTER_NONCE, tstream):
            self.iv_counter_nonce = KeyWrappingData.IVCounterNonce()
            self.iv_counter_nonce.read(tstream)

        if self.is_tag_next(Tags.ENCODING_OPTION, tstream):
            self.encoding_option = EncodingOption()
            self.encoding_option.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the contents of the key wrapping data
        self.wrapping_method.write(tstream)

        if self.encryption_key_information is not None:
            self.encryption_key_information.write(tstream)
        if self.mac_signature_key_information is not None:
            self.mac_signature_key_information.write(tstream)
        if self.mac_signature is not None:
            self.mac_signature.write(tstream)
        if self.iv_counter_nonce is not None:
            self.iv_counter_nonce.write(tstream)
        if self.encoding_option is not None:
            self.encoding_option.write(tstream)

        # Write the length and value of the key wrapping data
        self.length = tstream.length()
        super(KeyWrappingData, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation
        pass


# 2.1.6
class KeyWrappingSpecification(Struct):

    class AttributeName(TextString):

        def __init__(self, value=None):
            super(KeyWrappingSpecification.AttributeName, self).__init__(
                value, Tags.ATTRIBUTE_NAME)

    def __init__(self,
                 wrapping_method=None,
                 encryption_key_information=None,
                 mac_signature_key_information=None,
                 attribute_name=None,
                 encoding_option=None):
        super(KeyWrappingSpecification, self).__init__(
            tag=Tags.KEY_WRAPPING_SPECIFICATION)
        self.wrapping_method = wrapping_method
        self.encryption_key_information = encryption_key_information
        self.mac_signature_key_information = mac_signature_key_information
        self.attribute_name = attribute_name
        self.encoding_option = encoding_option

    def read(self, istream):
        super(KeyWrappingSpecification, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.wrapping_method = WrappingMethod()
        self.wrapping_method.read(tstream)

        if self.is_tag_next(Tags.ENCRYPTION_KEY_INFORMATION, tstream):
            self.encryption_key_information = EncryptionKeyInformation()
            self.encryption_key_information.read(tstream)

        if self.is_tag_next(Tags.MAC_SIGNATURE_KEY_INFORMATION, tstream):
            self.mac_signature_key_information = MACSignatureKeyInformation()
            self.mac_signature_key_information.read(tstream)

        if self.is_tag_next(Tags.ATTRIBUTE_NAME, tstream):
            self.attribute_name = KeyWrappingSpecification.AttributeName()
            self.attribute_name.read(tstream)

        if self.is_tag_next(Tags.ENCODING_OPTION, tstream):
            self.encoding_option = EncodingOption()
            self.encoding_option.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the contents of the key wrapping data
        self.wrapping_method.write(tstream)

        if self.encryption_key_information is not None:
            self.encryption_key_information.write(tstream)
        if self.mac_signature_key_information is not None:
            self.mac_signature_key_information.write(tstream)
        if self.attribute_name is not None:
            self.attribute_name.write(tstream)
        if self.encoding_option is not None:
            self.encoding_option.write(tstream)

        # Write the length and value of the key wrapping data
        self.length = tstream.length()
        super(KeyWrappingSpecification, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 2.1.8
class TemplateAttribute(Struct):

    def __init__(self,
                 names=None,
                 attributes=None,
                 tag=Tags.TEMPLATE_ATTRIBUTE):
        super(TemplateAttribute, self).__init__(tag)

        if names is None:
            self.names = list()
        else:
            self.names = names

        if attributes is None:
            self.attributes = list()
        else:
            self.attributes = attributes

        self.validate()

    def read(self, istream):
        super(TemplateAttribute, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.names = list()
        self.attributes = list()

        # Read the names of the template attribute, 0 or more
        while self.is_tag_next(Tags.NAME, tstream):
            name = attributes.Name()
            name.read(tstream)
            self.names.append(name)

        # Read the attributes of the template attribute, 0 or more
        while self.is_tag_next(Tags.ATTRIBUTE, tstream):
            attribute = Attribute()
            attribute.read(tstream)
            self.attributes.append(attribute)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the names and attributes of the template attribute
        for name in self.names:
            name.write(tstream)
        for attribute in self.attributes:
            attribute.write(tstream)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(TemplateAttribute, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass

    def __eq__(self, other):
        if isinstance(other, TemplateAttribute):
            if len(self.names) != len(other.names):
                return False
            if len(self.attributes) != len(other.attributes):
                return False

            for i in xrange(len(self.names)):
                a = self.names[i]
                b = other.names[i]

                if a != b:
                    return False

            for i in xrange(len(self.attributes)):
                a = self.attributes[i]
                b = other.attributes[i]

                if a != b:
                    return False

            return True
        else:
            return NotImplemented


class CommonTemplateAttribute(TemplateAttribute):

    def __init__(self,
                 names=None,
                 attributes=None):
        super(CommonTemplateAttribute, self).__init__(
            names, attributes, Tags.COMMON_TEMPLATE_ATTRIBUTE)


class PrivateKeyTemplateAttribute(TemplateAttribute):

    def __init__(self,
                 names=None,
                 attributes=None):
        super(PrivateKeyTemplateAttribute, self).__init__(
            names, attributes, Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE)


class PublicKeyTemplateAttribute(TemplateAttribute):

    def __init__(self,
                 names=None,
                 attributes=None):
        super(PublicKeyTemplateAttribute, self).__init__(
            names, attributes, Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE)


# 2.1.9
class ExtensionName(TextString):
    """
    The name of an extended Object.

    A part of ExtensionInformation, specifically identifying an Object that is
    a custom vendor addition to the KMIP specification. See Section 2.1.9 of
    the KMIP 1.1 specification for more information.

    Attributes:
        value: The string data representing the extension name.
    """
    def __init__(self, value=''):
        """
        Construct an ExtensionName object.

        Args:
            value (str): The string data representing the extension name.
                Optional, defaults to the empty string.
        """
        super(ExtensionName, self).__init__(value, Tags.EXTENSION_NAME)


# 2.1.10
class Data(ByteString):

    def __init__(self, value=None):
        super(Data, self).__init__(value, Tags.DATA)

    def __str__(self):
        return str(binascii.hexlify(self.value))


# 2.1.13
class MACData(ByteString):

    def __init__(self, value=None):
        super(MACData, self).__init__(value, Tags.MAC_DATA)

    def __str__(self):
        return str(binascii.hexlify(self.value))


class ExtensionTag(Integer):
    """
    The tag of an extended Object.

    A part of ExtensionInformation. See Section 2.1.9 of the KMIP 1.1
    specification for more information.

    Attributes:
        value: The tag number identifying the extended object.
    """
    def __init__(self, value=0):
        """
        Construct an ExtensionTag object.

        Args:
            value (int): A number representing the extension tag. Often
                displayed in hex format. Optional, defaults to 0.
        """
        super(ExtensionTag, self).__init__(value, Tags.EXTENSION_TAG)


class ExtensionType(Integer):
    """
    The type of an extended Object.

    A part of ExtensionInformation, specifically identifying the type of the
    Object in the specification extension. See Section 2.1.9 of the KMIP 1.1
    specification for more information.

    Attributes:
        value: The type enumeration for the extended object.
    """
    def __init__(self, value=None):
        """
        Construct an ExtensionType object.

        Args:
            value (Types): A number representing a Types enumeration value,
                indicating the type of the extended Object. Optional, defaults
                to None.
        """
        super(ExtensionType, self).__init__(value, Tags.EXTENSION_TYPE)


class ExtensionInformation(Struct):
    """
    A structure describing Objects defined in KMIP specification extensions.

    It is used specifically for Objects with Item Tag values in the Extensions
    range and appears in responses to Query requests for server extension
    information. See Sections 2.1.9 and 4.25 of the KMIP 1.1 specification for
    more information.

    Attributes:
        extension_name: The name of the extended Object.
        extension_tag: The tag of the extended Object.
        extension_type: The type of the extended Object.
    """
    def __init__(self, extension_name=None, extension_tag=None,
                 extension_type=None):
        """
        Construct an ExtensionInformation object.

        Args:
            extension_name (ExtensionName): The name of the extended Object.
            extension_tag (ExtensionTag): The tag of the extended Object.
            extension_type (ExtensionType): The type of the extended Object.
        """
        super(ExtensionInformation, self).__init__(Tags.EXTENSION_INFORMATION)

        if extension_name is None:
            self.extension_name = ExtensionName()
        else:
            self.extension_name = extension_name

        self.extension_tag = extension_tag
        self.extension_type = extension_type

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the ExtensionInformation object and decode it
        into its constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(ExtensionInformation, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.extension_name.read(tstream)

        if self.is_tag_next(Tags.EXTENSION_TAG, tstream):
            self.extension_tag = ExtensionTag()
            self.extension_tag.read(tstream)
        if self.is_tag_next(Tags.EXTENSION_TYPE, tstream):
            self.extension_type = ExtensionType()
            self.extension_type.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the ExtensionInformation object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = BytearrayStream()

        self.extension_name.write(tstream)

        if self.extension_tag is not None:
            self.extension_tag.write(tstream)
        if self.extension_type is not None:
            self.extension_type.write(tstream)

        self.length = tstream.length()
        super(ExtensionInformation, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the ExtensionInformation object.
        """
        self.__validate()

    def __validate(self):
        if not isinstance(self.extension_name, ExtensionName):
            msg = "invalid extension name"
            msg += "; expected {0}, received {1}".format(
                ExtensionName, self.extension_name)
            raise TypeError(msg)

        if self.extension_tag is not None:
            if not isinstance(self.extension_tag, ExtensionTag):
                msg = "invalid extension tag"
                msg += "; expected {0}, received {1}".format(
                    ExtensionTag, self.extension_tag)
                raise TypeError(msg)

        if self.extension_type is not None:
            if not isinstance(self.extension_type, ExtensionType):
                msg = "invalid extension type"
                msg += "; expected {0}, received {1}".format(
                    ExtensionType, self.extension_type)
                raise TypeError(msg)

    def __eq__(self, other):
        if isinstance(other, ExtensionInformation):
            if self.extension_name != other.extension_name:
                return False
            elif self.extension_tag != other.extension_tag:
                return False
            elif self.extension_type != other.extension_type:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ExtensionInformation):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        name = "extension_name={0}".format(repr(self.extension_name))
        tag = "extension_tag={0}".format(repr(self.extension_tag))
        typ = "extension_type={0}".format(repr(self.extension_type))
        return "ExtensionInformation({0}, {1}, {2})".format(name, tag, typ)

    def __str__(self):
        return repr(self)

    @classmethod
    def create(cls, extension_name=None, extension_tag=None,
               extension_type=None):
        """
        Construct an ExtensionInformation object from provided extension
        values.

        Args:
            extension_name (str): The name of the extension. Optional,
                defaults to None.
            extension_tag (int): The tag number of the extension. Optional,
                defaults to None.
            extension_type (int): The type index of the extension. Optional,
                defaults to None.

        Returns:
            ExtensionInformation: The newly created set of extension
                information.

        Example:
            >>> x = ExtensionInformation.create('extension', 1, 1)
            >>> x.extension_name.value
            ExtensionName(value='extension')
            >>> x.extension_tag.value
            ExtensionTag(value=1)
            >>> x.extension_type.value
            ExtensionType(value=1)
        """
        extension_name = ExtensionName(extension_name)
        extension_tag = ExtensionTag(extension_tag)
        extension_type = ExtensionType(extension_type)

        return ExtensionInformation(
            extension_name=extension_name,
            extension_tag=extension_tag,
            extension_type=extension_type)


# 3.31, 9.1.3.2.19
class RevocationReasonCode(Enumeration):

    def __init__(self, value=RevocationReasonCodeEnum.UNSPECIFIED):
        super(RevocationReasonCode, self).__init__(
            RevocationReasonCodeEnum, value=value,
            tag=Tags.REVOCATION_REASON_CODE)


# 3.31
class RevocationReason(Struct):
    """
    A structure describing  the reason for a revocation operation.

    See Sections 2.1.9 and 4.25 of the KMIP 1.1 specification for
    more information.

    Attributes:
        code: The revocation reason code enumeration
        message: An optional revocation message
    """

    def __init__(self, code=None, message=None):
        """
        Construct a RevocationReason object.

        Parameters:
            code(RevocationReasonCode): revocation reason code
            message(string): An optional revocation message
        """
        super(RevocationReason, self).__init__(tag=Tags.REVOCATION_REASON)
        if code is not None:
            self.revocation_code = RevocationReasonCode(value=code)
        else:
            self.revocation_code = RevocationReasonCode()

        if message is not None:
            self.revocation_message = TextString(
                value=message,
                tag=Tags.REVOCATION_MESSAGE)
        else:
            self.revocation_message = None

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the RevocationReason object and decode it
        into its constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(RevocationReason, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.revocation_code = RevocationReasonCode()
        self.revocation_code.read(tstream)

        if self.is_tag_next(Tags.REVOCATION_MESSAGE, tstream):
            self.revocation_message = TextString()
            self.revocation_message.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the RevocationReason object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = BytearrayStream()

        self.revocation_code.write(tstream)
        if self.revocation_message is not None:
            self.revocation_message.write(tstream)

        # Write the length and value
        self.length = tstream.length()
        super(RevocationReason, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        validate the RevocationReason object
        """
        if not isinstance(self.revocation_code, RevocationReasonCode):
            msg = "RevocationReaonCode expected"
            raise TypeError(msg)
        if self.revocation_message is not None:
            if not isinstance(self.revocation_message, TextString):
                msg = "TextString expect"
                raise TypeError(msg)
