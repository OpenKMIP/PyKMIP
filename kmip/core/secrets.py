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

from kmip.core.attributes import CertificateType

from kmip.core import enums
from kmip.core.enums import Tags

from kmip.core.misc import CertificateValue

from kmip.core.objects import Attribute
from kmip.core.objects import KeyBlock

from kmip.core.primitives import Struct
from kmip.core.primitives import Integer
from kmip.core.primitives import Enumeration
from kmip.core.primitives import BigInteger
from kmip.core.primitives import ByteString

from kmip.core.utils import BytearrayStream


# 2.2
# 2.2.1
class Certificate(Struct):
    """
    A structure representing a DER-encoded X.509 public key certificate.

    See Section 2.2.1 of the KMIP 1.1 specification for more information.

    Attributes:
        certificate_type: The type of the certificate.
        certificate_value: The bytes of the certificate.
    """

    def __init__(self,
                 certificate_type=None,
                 certificate_value=None):
        """
        Construct a Certificate object.

        Args:
            certificate_type (CertificateTypeEnum): The type of the
                certificate. Optional, defaults to None.
            certificate_value (bytes): The bytes of the certificate. Optional,
                defaults to None.
        """
        super(Certificate, self).__init__(Tags.CERTIFICATE)

        if certificate_type is None:
            self.certificate_type = CertificateType()
        else:
            self.certificate_type = CertificateType(certificate_type)

        if certificate_value is None:
            self.certificate_value = CertificateValue()
        else:
            self.certificate_value = CertificateValue(certificate_value)

    def read(self, istream):
        """
        Read the data encoding the Certificate object and decode it into its
        constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(Certificate, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.certificate_type = CertificateType()
        self.certificate_value = CertificateValue()

        self.certificate_type.read(tstream)
        self.certificate_value.read(tstream)

        self.is_oversized(tstream)

    def write(self, ostream):
        """
        Write the data encoding the Certificate object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = BytearrayStream()

        self.certificate_type.write(tstream)
        self.certificate_value.write(tstream)

        self.length = tstream.length()
        super(Certificate, self).write(ostream)
        ostream.write(tstream.buffer)

    def __eq__(self, other):
        if isinstance(other, Certificate):
            if self.certificate_type != other.certificate_type:
                return False
            elif self.certificate_value != other.certificate_value:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Certificate):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        return "{0}(certificate_type={1}, certificate_value=b'{2}')".format(
            type(self).__name__,
            str(self.certificate_type),
            str(self.certificate_value))

    def __str__(self):
        return "{0}".format(str(self.certificate_value))


# 2.2.2
class KeyBlockKey(Struct):

    def __init__(self, key_block=None, tag=Tags.DEFAULT):
        super(KeyBlockKey, self).__init__(tag)
        self.key_block = key_block
        self.validate()

    def read(self, istream):
        super(KeyBlockKey, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.key_block = KeyBlock()
        self.key_block.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.key_block.write(tstream)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(KeyBlockKey, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


class SymmetricKey(KeyBlockKey):

    def __init__(self, key_block=None):
        super(SymmetricKey, self).__init__(key_block, Tags.SYMMETRIC_KEY)
        self.validate()

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 2.2.3
class PublicKey(KeyBlockKey):

    def __init__(self, key_block=None):
        super(PublicKey, self).__init__(key_block, Tags.PUBLIC_KEY)
        self.validate()

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 2.2.4
class PrivateKey(KeyBlockKey):

    def __init__(self, key_block=None):
        super(PrivateKey, self).__init__(key_block, Tags.PRIVATE_KEY)
        self.validate()

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 2.2.5
class SplitKey(Struct):

    class SplitKeyParts(Integer):

        def __init__(self, value=None):
            super(SplitKey.SplitKeyParts, self).__init__(
                value, Tags.SPLIT_KEY_PARTS)

    class KeyPartIdentifier(Integer):

        def __init__(self, value=None):
            super(SplitKey.KeyPartIdentifier, self).__init__(
                value, Tags.KEY_PART_IDENTIFIER)

    class SplitKeyThreshold(Integer):

        def __init__(self, value=None):
            super(SplitKey.SplitKeyThreshold, self).__init__(
                value, Tags.SPLIT_KEY_THRESHOLD)

    class SplitKeyMethod(Enumeration):

        def __init__(self, value=None):
            super(SplitKey.SplitKeyMethod, self).__init__(
                enums.SplitKeyMethod, value, Tags.SPLIT_KEY_METHOD)

    class PrimeFieldSize(BigInteger):

        def __init__(self, value=None):
            super(SplitKey.PrimeFieldSize, self).__init__(
                value, Tags.PRIME_FIELD_SIZE)

    def __init__(self,
                 split_key_parts=None,
                 key_part_identifier=None,
                 split_key_threshold=None,
                 split_key_method=None,
                 prime_field_size=None,
                 key_block=None):
        super(SplitKey, self).__init__(Tags.SPLIT_KEY)
        self.split_key_parts = split_key_parts
        self.key_part_identifier = key_part_identifier
        self.split_key_threshold = split_key_threshold
        self.split_key_method = split_key_method
        self.prime_field_size = prime_field_size
        self.key_block = key_block
        self.validate()

    def read(self, istream):
        super(SplitKey, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.split_key_parts = SplitKey.SplitKeyParts()
        self.split_key_parts.read(tstream)

        self.key_part_identifier = SplitKey.KeyPartIdentifier()
        self.key_part_identifier.read(tstream)

        self.split_key_threshold = SplitKey.SplitKeyThreshold()
        self.split_key_threshold.read(tstream)

        if self.is_tag_next(Tags.PRIME_FIELD_SIZE, tstream):
            self.prime_field_size = SplitKey.PrimeFieldSize()
            self.prime_field_size.read(tstream)

        self.key_block = KeyBlock()
        self.key_block.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.split_key_parts.write(tstream)
        self.key_part_identifier.write(tstream)
        self.split_key_threshold.write(tstream)
        self.split_key_method.write(tstream)

        if self.prime_field_size is not None:
            self.prime_field_size.write(tstream)

        self.key_block.write(tstream)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(SplitKey, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 2.2.6
class Template(Struct):

    def __init__(self, attributes=None):
        super(Template, self).__init__(Tags.TEMPLATE)
        self.attributes = attributes
        self.validate()

    def read(self, istream):
        super(Template, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.attributes = list()

        attribute = Attribute()
        attribute.read(tstream)
        self.attributes.append(attribute)

        while self.is_tag_next(Tags.ATTRIBUTE, tstream):
            attribute = Attribute()
            attribute.read(tstream)
            self.attributes.append(attribute)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        for attribute in self.attributes:
            attribute.write(tstream)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(Template, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 2.2.7
class SecretData(Struct):

    class SecretDataType(Enumeration):

        def __init__(self, value=None):
            super(SecretData.SecretDataType, self).__init__(
                enums.SecretDataType, value, Tags.SECRET_DATA_TYPE)

    def __init__(self,
                 secret_data_type=None,
                 key_block=None):
        super(SecretData, self).__init__(Tags.SECRET_DATA)
        self.secret_data_type = secret_data_type
        self.key_block = key_block
        self.validate()

    def read(self, istream):
        super(SecretData, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.secret_data_type = SecretData.SecretDataType()
        self.key_block = KeyBlock()

        self.secret_data_type.read(tstream)
        self.key_block.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.secret_data_type.write(tstream)
        self.key_block.write(tstream)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(SecretData, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 2.2.8
class OpaqueObject(Struct):

    class OpaqueDataType(Enumeration):

        def __init__(self, value=None):
            super(OpaqueObject.OpaqueDataType, self).__init__(
                enums.OpaqueDataType, value, Tags.OPAQUE_DATA_TYPE)

    class OpaqueDataValue(ByteString):

        def __init__(self, value=None):
            super(OpaqueObject.OpaqueDataValue, self).__init__(
                value, Tags.OPAQUE_DATA_VALUE)

    def __init__(self,
                 opaque_data_type=None,
                 opaque_data_value=None):
        super(OpaqueObject, self).__init__(Tags.OPAQUE_OBJECT)
        self.opaque_data_type = opaque_data_type
        self.opaque_data_value = opaque_data_value
        self.validate()

    def read(self, istream):
        super(OpaqueObject, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.opaque_data_type = OpaqueObject.OpaqueDataType()
        self.opaque_data_value = OpaqueObject.OpaqueDataValue()

        self.opaque_data_type.read(tstream)
        self.opaque_data_value.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.opaque_data_type.write(tstream)
        self.opaque_data_value.write(tstream)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(OpaqueObject, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass
