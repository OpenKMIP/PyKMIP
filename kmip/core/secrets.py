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
from kmip.core import exceptions

from kmip.core.misc import CertificateValue

from kmip.core import objects
from kmip.core.objects import Attribute
from kmip.core.objects import KeyBlock

from kmip.core import primitives
from kmip.core.primitives import Struct
from kmip.core.primitives import Enumeration
from kmip.core.primitives import ByteString

from kmip.core import utils
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
            certificate_type (CertificateType): The type of the
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

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Certificate object and decode it into its
        constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(Certificate, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        self.certificate_type = CertificateType()
        self.certificate_value = CertificateValue()

        self.certificate_type.read(tstream, kmip_version=kmip_version)
        self.certificate_value.read(tstream, kmip_version=kmip_version)

        self.is_oversized(tstream)

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Certificate object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        tstream = BytearrayStream()

        self.certificate_type.write(tstream, kmip_version=kmip_version)
        self.certificate_value.write(tstream, kmip_version=kmip_version)

        self.length = tstream.length()
        super(Certificate, self).write(ostream, kmip_version=kmip_version)
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

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(KeyBlockKey, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        self.key_block = KeyBlock()
        self.key_block.read(tstream, kmip_version=kmip_version)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        self.key_block.write(tstream, kmip_version=kmip_version)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(KeyBlockKey, self).write(ostream, kmip_version=kmip_version)
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

class SplitKey(primitives.Struct):
    """
    A split key cryptographic object.

    This object represents a symmetric or private key that has been split into
    multiple parts. The fields of this object specify how the key was split
    and how it can be reassembled.

    Attributes:
        split_key_parts: The total number of parts of the split key.
        key_part_identifier: The ID specifying the part of the key in the key
            block.
        split_key_threshold: The minimum number of parts needed to reconstruct
            the key.
        split_key_method: The method by which the key was split.
        prime_field_size: The prime field size used for the Polynomial Sharing
            Prime Field split key method.
        key_block: The split key part held by this object.
    """

    def __init__(self,
                 split_key_parts=None,
                 key_part_identifier=None,
                 split_key_threshold=None,
                 split_key_method=None,
                 prime_field_size=None,
                 key_block=None):
        """
        Construct a SplitKey object.

        Args:
            split_key_parts (int): An integer specifying the total number of
                parts of the split key. Optional, defaults to None. Required
                for read/write.
            key_part_identifier (int): An integer specifying which key part is
                contained in the key block. Optional, defaults to None.
                Required for read/write.
            split_key_threshold (int): An integer specifying the minimum number
                of key parts required to reconstruct the split key. Optional,
                defaults to None. Required for read/write.
            split_key_method (enum): A SplitKeyMethod enumeration specifying
                the method by which the key was split. Optional, defaults to
                None. Required for read/write.
            prime_field_size (int): A big integer specifying the prime field
                size used for the Polynomial Sharing Prime Field split key
                method. Optional, defaults to None. Required for read/write
                only if the split key method is Polynomial Sharing Prime Field.
            key_block (struct): A KeyBlock structure containing the split key
                part identified by the key part identifier. Optional, defaults
                to None. Required for read/write.

        """
        super(SplitKey, self).__init__(enums.Tags.SPLIT_KEY)

        self._split_key_parts = None
        self._key_part_identifier = None
        self._split_key_threshold = None
        self._split_key_method = None
        self._prime_field_size = None
        self._key_block = None

        self.split_key_parts = split_key_parts
        self.key_part_identifier = key_part_identifier
        self.split_key_threshold = split_key_threshold
        self.split_key_method = split_key_method
        self.prime_field_size = prime_field_size
        self.key_block = key_block

    @property
    def split_key_parts(self):
        if self._split_key_parts is not None:
            return self._split_key_parts.value
        return None

    @split_key_parts.setter
    def split_key_parts(self, value):
        if value is None:
            self._split_key_parts = None
        elif isinstance(value, int):
            self._split_key_parts = primitives.Integer(
                value=value,
                tag=enums.Tags.SPLIT_KEY_PARTS
            )
        else:
            raise TypeError("The split key parts must be an integer.")

    @property
    def key_part_identifier(self):
        if self._key_part_identifier is not None:
            return self._key_part_identifier.value
        return None

    @key_part_identifier.setter
    def key_part_identifier(self, value):
        if value is None:
            self._key_part_identifier = None
        elif isinstance(value, int):
            self._key_part_identifier = primitives.Integer(
                value=value,
                tag=enums.Tags.KEY_PART_IDENTIFIER
            )
        else:
            raise TypeError("The key part identifier must be an integer.")

    @property
    def split_key_threshold(self):
        if self._split_key_threshold is not None:
            return self._split_key_threshold.value
        return None

    @split_key_threshold.setter
    def split_key_threshold(self, value):
        if value is None:
            self._split_key_threshold = None
        elif isinstance(value, int):
            self._split_key_threshold = primitives.Integer(
                value=value,
                tag=enums.Tags.SPLIT_KEY_THRESHOLD
            )
        else:
            raise TypeError("The split key threshold must be an integer.")

    @property
    def split_key_method(self):
        if self._split_key_method is not None:
            return self._split_key_method.value
        return None

    @split_key_method.setter
    def split_key_method(self, value):
        if value is None:
            self._split_key_method = None
        elif isinstance(value, enums.SplitKeyMethod):
            self._split_key_method = primitives.Enumeration(
                enums.SplitKeyMethod,
                value=value,
                tag=enums.Tags.SPLIT_KEY_METHOD
            )
        else:
            raise TypeError(
                "The split key method must be a SplitKeyMethod enumeration."
            )

    @property
    def prime_field_size(self):
        if self._prime_field_size is not None:
            return self._prime_field_size.value
        return None

    @prime_field_size.setter
    def prime_field_size(self, value):
        if value is None:
            self._prime_field_size = None
        elif isinstance(value, int):
            self._prime_field_size = primitives.BigInteger(
                value=value,
                tag=enums.Tags.PRIME_FIELD_SIZE
            )
        else:
            raise TypeError("The prime field size must be an integer.")

    @property
    def key_block(self):
        if self._key_block is not None:
            return self._key_block
        return None

    @key_block.setter
    def key_block(self, value):
        if value is None:
            self._key_block = None
        elif isinstance(value, objects.KeyBlock):
            self._key_block = value
        else:
            raise TypeError("The key block must be a KeyBlock structure.")

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the SplitKey object and decode it.

        Args:
            input_buffer (stream): A data stream containing the encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(SplitKey, self).read(input_buffer, kmip_version=kmip_version)
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.SPLIT_KEY_PARTS, local_buffer):
            self._split_key_parts = primitives.Integer(
                tag=enums.Tags.SPLIT_KEY_PARTS
            )
            self._split_key_parts.read(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidKmipEncoding(
                "The SplitKey encoding is missing the SplitKeyParts field."
            )

        if self.is_tag_next(enums.Tags.KEY_PART_IDENTIFIER, local_buffer):
            self._key_part_identifier = primitives.Integer(
                tag=enums.Tags.KEY_PART_IDENTIFIER
            )
            self._key_part_identifier.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The SplitKey encoding is missing the KeyPartIdentifier field."
            )

        if self.is_tag_next(enums.Tags.SPLIT_KEY_THRESHOLD, local_buffer):
            self._split_key_threshold = primitives.Integer(
                tag=enums.Tags.SPLIT_KEY_THRESHOLD
            )
            self._split_key_threshold.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The SplitKey encoding is missing the SplitKeyThreshold field."
            )

        if self.is_tag_next(enums.Tags.SPLIT_KEY_METHOD, local_buffer):
            self._split_key_method = primitives.Enumeration(
                enums.SplitKeyMethod,
                tag=enums.Tags.SPLIT_KEY_METHOD
            )
            self._split_key_method.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The SplitKey encoding is missing the SplitKeyMethod field."
            )

        if self.is_tag_next(enums.Tags.PRIME_FIELD_SIZE, local_buffer):
            self._prime_field_size = primitives.BigInteger(
                tag=enums.Tags.PRIME_FIELD_SIZE
            )
            self._prime_field_size.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            corner_case = enums.SplitKeyMethod.POLYNOMIAL_SHARING_PRIME_FIELD
            if self.split_key_method == corner_case:
                raise exceptions.InvalidKmipEncoding(
                    "The SplitKey encoding is missing the PrimeFieldSize "
                    "field. This field is required when the SplitKeyMethod is "
                    "PolynomialSharingPrimeField."
                )

        if self.is_tag_next(enums.Tags.KEY_BLOCK, local_buffer):
            self._key_block = objects.KeyBlock()
            self._key_block.read(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidKmipEncoding(
                "The SplitKey encoding is missing the KeyBlock field."
            )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the SplitKey object to a buffer.

        Args:
            output_buffer (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_buffer = utils.BytearrayStream()

        if self._split_key_parts:
            self._split_key_parts.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The SplitKey object is missing the SplitKeyParts field."
            )

        if self._key_part_identifier:
            self._key_part_identifier.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The SplitKey object is missing the KeyPartIdentifier field."
            )

        if self._split_key_threshold:
            self._split_key_threshold.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The SplitKey object is missing the SplitKeyThreshold field."
            )

        if self._split_key_method:
            self._split_key_method.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The SplitKey object is missing the SplitKeyMethod field."
            )

        if self._prime_field_size:
            self._prime_field_size.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            corner_case = enums.SplitKeyMethod.POLYNOMIAL_SHARING_PRIME_FIELD
            if self.split_key_method == corner_case:
                raise exceptions.InvalidField(
                    "The SplitKey object is missing the PrimeFieldSize field. "
                    "This field is required when the SplitKeyMethod is "
                    "PolynomialSharingPrimeField."
                )

        if self._key_block:
            self._key_block.write(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidField(
                "The SplitKey object is missing the KeyBlock field."
            )

        self.length = local_buffer.length()
        super(SplitKey, self).write(output_buffer, kmip_version=kmip_version)
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        args = [
            "split_key_parts={}".format(repr(self.split_key_parts)),
            "key_part_identifier={}".format(repr(self.key_part_identifier)),
            "split_key_threshold={}".format(repr(self.split_key_threshold)),
            "split_key_method={}".format(self.split_key_method),
            "prime_field_size={}".format(repr(self.prime_field_size)),
            "key_block={}".format(repr(self.key_block))
        ]
        return "SplitKey({})".format(", ".join(args))

    def __str__(self):
        # TODO (peter-hamilton) Replace str() call below with a dict() call.
        value = ", ".join(
            [
                '"split_key_parts": {}'.format(self.split_key_parts),
                '"key_part_identifier": {}'.format(self.key_part_identifier),
                '"split_key_threshold": {}'.format(self.split_key_threshold),
                '"split_key_method": {}'.format(self.split_key_method),
                '"prime_field_size": {}'.format(self.prime_field_size),
                '"key_block": {}'.format(str(self.key_block))
            ]
        )
        return "{" + value + "}"

    def __eq__(self, other):
        if isinstance(other, SplitKey):
            if self.split_key_parts != other.split_key_parts:
                return False
            elif self.key_part_identifier != other.key_part_identifier:
                return False
            elif self.split_key_threshold != other.split_key_threshold:
                return False
            elif self.split_key_method != other.split_key_method:
                return False
            elif self.prime_field_size != other.prime_field_size:
                return False
#            elif self.key_block != other.key_block:
#                return False
            return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, SplitKey):
            return not self.__eq__(other)
        else:
            return NotImplemented

# 2.2.6
class Template(Struct):

    def __init__(self, attributes=None):
        super(Template, self).__init__(Tags.TEMPLATE)
        self.attributes = attributes
        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(Template, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        self.attributes = list()

        attribute = Attribute()
        attribute.read(tstream, kmip_version=kmip_version)
        self.attributes.append(attribute)

        while self.is_tag_next(Tags.ATTRIBUTE, tstream):
            attribute = Attribute()
            attribute.read(tstream, kmip_version=kmip_version)
            self.attributes.append(attribute)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        for attribute in self.attributes:
            attribute.write(tstream, kmip_version=kmip_version)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(Template, self).write(ostream, kmip_version=kmip_version)
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

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(SecretData, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        self.secret_data_type = SecretData.SecretDataType()
        self.key_block = KeyBlock()

        self.secret_data_type.read(tstream, kmip_version=kmip_version)
        self.key_block.read(tstream, kmip_version=kmip_version)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        self.secret_data_type.write(tstream, kmip_version=kmip_version)
        self.key_block.write(tstream, kmip_version=kmip_version)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(SecretData, self).write(ostream, kmip_version=kmip_version)
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

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(OpaqueObject, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        self.opaque_data_type = OpaqueObject.OpaqueDataType()
        self.opaque_data_value = OpaqueObject.OpaqueDataValue()

        self.opaque_data_type.read(tstream, kmip_version=kmip_version)
        self.opaque_data_value.read(tstream, kmip_version=kmip_version)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        self.opaque_data_type.write(tstream, kmip_version=kmip_version)
        self.opaque_data_value.write(tstream, kmip_version=kmip_version)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(OpaqueObject, self).write(ostream, kmip_version=kmip_version)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass
