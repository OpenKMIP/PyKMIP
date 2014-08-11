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

import attributes
from kmip.core.attributes import CryptographicParameters

from kmip.core.factories.attribute_values import AttributeValueFactory
from kmip.core.factories.keys import KeyFactory

from kmip.core import enums
from kmip.core.enums import AttributeType
from kmip.core.enums import Tags
from kmip.core.enums import Types
from kmip.core.enums import CredentialType

from kmip.core.errors import ErrorStrings

from kmip.core.primitives import Struct
from kmip.core.primitives import TextString
from kmip.core.primitives import ByteString
from kmip.core.primitives import Integer
from kmip.core.primitives import Enumeration

from utils import BytearrayStream


# 2.1
# 2.1.1
class Attribute(Struct):

    class AttributeName(TextString):

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value, Tags.ATTRIBUTE_NAME)

    class AttributeIndex(Integer):

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value, Tags.ATTRIBUTE_INDEX)

    def __init__(self,
                 attribute_name=None,
                 attribute_index=None,
                 attribute_value=None):
        super(self.__class__, self).__init__(tag=Tags.ATTRIBUTE)

        self.value_factory = AttributeValueFactory()

        self.attribute_name = attribute_name
        self.attribute_index = attribute_index
        self.attribute_value = attribute_value

        if attribute_value is not None:
            attribute_value.tag = Tags.ATTRIBUTE_VALUE

    def read(self, istream):
        super(self.__class__, self).read(istream)
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
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)


# 2.1.2
class Credential(Struct):

    class CredentialType(Enumeration):

        ENUM_TYPE = CredentialType

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value, Tags.CREDENTIAL_TYPE)

    class UsernamePasswordCredential(Struct):

        class Username(TextString):
            def __init__(self, value=None):
                super(self.__class__, self).__init__(value, Tags.USERNAME)

        class Password(TextString):
            def __init__(self, value=None):
                super(self.__class__, self).__init__(value, Tags.PASSWORD)

        def __init__(self, username=None, password=None):
            super(self.__class__, self).__init__(tag=Tags.CREDENTIAL_VALUE)
            self.username = username
            self.password = password
            self.validate()

        def read(self, istream):
            super(self.__class__, self).read(istream)
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
            super(self.__class__, self).write(ostream)
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
                super(Credential.DeviceCredential.NetworkIdetifier, self).\
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
            super(self.__class__, self).__init__(tag=Tags.CREDENTIAL_VALUE)
            super.device_serial_number = device_serial_number
            super.password = password
            super.device_identifier = device_identifier
            super.network_identifier = network_identifier
            super.machine_identifier = machine_identifier
            super.media_identifier = media_identifier

        def read(self, istream):
            super(self.__class__, self).read(istream)
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
            super(self.__class__, self).write(ostream)
            ostream.write(tstream.buffer)

        def validate(self):
            pass

    def __init__(self, credential_type=None, credential_value=None):
        super(self.__class__, self).__init__(tag=Tags.CREDENTIAL)
        self.credential_type = credential_type
        self.credential_value = credential_value

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        # Read the type of the credential
        self.credential_type = self.CredentialType()
        self.credential_type.read(tstream)

        # Use the type to determine what credential value to read
        if self.credential_type.enum is CredentialType.USERNAME_AND_PASSWORD:
            self.credential_value = self.UsernamePasswordCredential()
        elif self.credential_type.enum is CredentialType.DEVICE:
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
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        pass


# 2.1.3
class KeyBlock(Struct):

    class KeyFormatType(Enumeration):
        ENUM_TYPE = enums.KeyFormatType

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value, Tags.KEY_FORMAT_TYPE)

    class KeyCompressionType(Enumeration):
        ENUM_TYPE = enums.KeyCompressionType

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value,
                                                 Tags.KEY_COMPRESSION_TYPE)

    def __init__(self,
                 key_format_type=None,
                 key_compression_type=None,
                 key_value=None,
                 cryptographic_algorithm=None,
                 cryptographic_length=None,
                 key_wrapping_data=None):
        super(self.__class__, self).__init__(Tags.KEY_BLOCK)
        self.key_format_type = key_format_type
        self.key_compression_type = key_compression_type
        self.key_value = key_value
        self.cryptographic_algorithm = cryptographic_algorithm
        self.cryptographic_length = cryptographic_length
        self.key_wrapping_data = key_wrapping_data
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.key_format_type = KeyBlock.KeyFormatType()
        self.key_format_type.read(tstream)
        key_format_type = self.key_format_type.enum

        if self.is_tag_next(Tags.KEY_COMPRESSION_TYPE, tstream):
            self.key_compression_type = KeyBlock.KeyCompressionType()
            self.key_compression_type.read(tstream)

        self.key_value = KeyValue(key_format_type=key_format_type)
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
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.key_format_type is not None:
            if type(self.key_format_type) is not KeyBlock.KeyFormatType:
                member = 'KeyBlock.key_format_type'
                exp_type = KeyBlock.KeyFormatType
                rcv_type = type(self.key_format_type)
                msg = ErrorStrings.BAD_EXP_RECV.format(member, 'type',
                                                       exp_type, rcv_type)
                raise TypeError(msg)


# 2.1.4
class KeyValueString(ByteString):

    def __init__(self, value=None):
        super(self.__class__, self).__init__(value, Tags.KEY_VALUE)


class KeyValueStruct(Struct):

    def __init__(self,
                 key_format_type=None,
                 key_material=None,
                 attributes=None):
        super(self.__class__, self).__init__(Tags.KEY_VALUE)
        self.key_format_type = key_format_type
        self.key_material = key_material
        self.attributes = attributes
        self.key_factory = KeyFactory()
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.key_material = self.key_factory.create_key(self.key_format_type)
        self.key_material.read(tstream)

        self.attributes = list()

        # Read the attributes, 0 or more
        while self.is_tag_next(Tags.ATTRIBUTE, tstream):
            attribute = Attribute()
            attribute.read(tstream)
            self.attributes.append(attribute)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.key_material.write(tstream)

        if self.attributes is not None:
            for attribute in self.attributes:
                attribute.write(tstream)

        # Write the length and value of the credential
        self.length = tstream.length()
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


class KeyValue(Struct):
    '''
    KeyValue can be either a ByteString or a Struct. Therefore, this class
    acts as a wrapper for two different KeyValue objects, KeyValueString,
    which represents the ByteString format, and KeyValueStruct, which
    represents the Struct format, both of which are defined above. This
    KeyValue object does not read or write itself; instead, it reads and
    writes its internal key_value attribute, which is either a KeyValueString
    or a KeyValueStruct.

    When reading, the class determines what the format of its internal
    structure should be by looking at the type of the object it will read
    using KeyValue.is_type_next(). This is one of the only places in the
    code where this approach is used.
    '''

    def __init__(self,
                 key_value=None,
                 key_format_type=None):
        super(self.__class__, self).__init__(Tags.KEY_VALUE)
        self.key_value = key_value
        self.key_format_type = key_format_type
        if self.key_value is not None:
            self.type = key_value.type
        self.validate()

    def read(self, istream):
        if self.is_type_next(Types.BYTE_STRING, istream):
            self.key_value = KeyValueString()
            self.key_value.read(istream)
        elif self.is_type_next(Types.STRUCTURE, istream):
            kft = self.key_format_type
            self.key_value = KeyValueStruct(key_format_type=kft)
            self.key_value.read(istream)

    def write(self, ostream):
        tstream = BytearrayStream()
        self.key_value.write(tstream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 2.1.5
class WrappingMethod(Enumeration):
    ENUM_TYPE = enums.WrappingMethod

    def __init__(self, value=None):
        super(WrappingMethod, self).__init__(value, Tags.WRAPPING_METHOD)


class EncodingOption(Enumeration):
    ENUM_TYPE = enums.EncodingOption

    def __init__(self, value=None):
        super(WrappingMethod, self).__init__(value, Tags.ENCODING_OPTION)


class KeyInformation(Struct):

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None,
                 tag=Tags.ENCRYPTION_KEY_INFORMATION):
        super(self.__class__, self).\
            __init__(tag=Tags.ENCRYPTION_KEY_INFORMATION)
        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
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
        super(self.__class__, self).write(ostream)
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
        super(self.__class__, self).\
            __init__(unique_identifier, cryptographic_parameters, tag)

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
        super(self.__class__, self).\
            __init__(unique_identifier, cryptographic_parameters, tag)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


class KeyWrappingData(Struct):

    class MACSignature(ByteString):

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value, Tags.MAC_SIGNATURE)

    class IVCounterNonce(ByteString):

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value, Tags.IV_COUNTER_NONCE)

    def __init__(self,
                 wrapping_method=None,
                 encryption_key_information=None,
                 mac_signature_key_information=None,
                 mac_signature=None,
                 iv_counter_nonce=None,
                 encoding_option=None):
        super(self.__class__, self).__init__(Tags.KEY_WRAPPING_DATA)
        self.wrapping_method = wrapping_method
        self.encryption_key_information = encryption_key_information
        self.mac_signature_key_information = mac_signature_key_information
        self.mac_signature = mac_signature
        self.iv_counter_nonce = iv_counter_nonce
        self.encoding_option = encoding_option
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
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
        super(self.__class__, self).write(ostream)
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
            super(self.__class__, self).__init__(value, Tags.ATTRIBUTE_NAME)

    def __init__(self,
                 wrapping_method=None,
                 encryption_key_information=None,
                 mac_signature_key_information=None,
                 attribute_name=None,
                 encoding_option=None):
        super(self.__class__, self).\
            __init__(tag=Tags.KEY_WRAPPING_SPECIFICATION)
        self.wrapping_method = wrapping_method
        self.encryption_key_information = encryption_key_information
        self.mac_signature_key_information = mac_signature_key_information
        self.attribute_name = attribute_name
        self.encoding_option = encoding_option

    def read(self, istream):
        super(self.__class__, self).read(istream)
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
        super(self.__class__, self).write(ostream)
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
                 attributes=None):
        super(self.__class__, self).__init__(tag=Tags.TEMPLATE_ATTRIBUTE)
        self.names = names
        self.attributes = attributes
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
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
        if self.names is not None:
            for name in self.names:
                name.write(tstream)
        if self.attributes is not None:
            for attribute in self.attributes:
                attribute.write(tstream)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass
