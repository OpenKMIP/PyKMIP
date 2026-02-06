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

import enum as enumeration
import logging

import struct
import sys
import time

from struct import pack, unpack

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import utils

class Base(object):
    TAG_SIZE = 3
    TYPE_SIZE = 1
    LENGTH_SIZE = 4

    def __init__(self, tag=enums.Tags.DEFAULT, type=enums.Types.DEFAULT):
        self.tag = tag
        self.type = type
        self.length = None

    # TODO (peter-hamilton) Convert this into a classmethod, class name can be
    #                       obtained from cls parameter that replaces self
    def is_oversized(self, stream):
        extra = len(stream.peek())
        if extra > 0:
            raise exceptions.StreamNotEmptyError(Base.__name__, extra)

    def read_tag(self, istream):
        # Read in the bytes for the tag
        tts = istream.read(self.TAG_SIZE)
        tag = unpack('!I', b'\x00' + tts[0:self.TAG_SIZE])[0]

        enum_tag = enums.Tags(tag)

        # Verify that the tag matches for the current object
        if enum_tag is not self.tag:
            raise exceptions.ReadValueError(
                Base.__name__,
                'tag',
                hex(self.tag.value),
                hex(tag)
            )

    def read_type(self, istream):
        # Read in the bytes for the type
        tts = istream.read(self.TYPE_SIZE)
        num_bytes = len(tts)
        if num_bytes != self.TYPE_SIZE:
            min_bytes = 'a minimum of {0} bytes'.format(self.TYPE_SIZE)
            raise exceptions.ReadValueError(
                Base.__name__,
                'type',
                min_bytes,
                '{0} bytes'.format(num_bytes)
            )
        typ = unpack('!B', tts)[0]

        enum_typ = enums.Types(typ)

        if enum_typ is not self.type:
            raise exceptions.ReadValueError(
                Base.__name__,
                'type',
                self.type.value,
                typ
            )

    def read_length(self, istream):
        # Read in the bytes for the length
        lst = istream.read(self.LENGTH_SIZE)
        num_bytes = len(lst)
        if num_bytes != self.LENGTH_SIZE:
            min_bytes = 'a minimum of {0} bytes'.format(self.LENGTH_SIZE)
            raise exceptions.ReadValueError(
                Base.__name__,
                'length',
                min_bytes,
                '{0} bytes'.format(num_bytes)
            )
        self.length = unpack('!I', lst)[0]

    def read_value(self, istream):
        raise NotImplementedError()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        self.read_tag(istream)
        self.read_type(istream)
        self.read_length(istream)

    def write_tag(self, ostream):
        # Write the tag to the output stream
        ostream.write(pack('!I', self.tag.value)[1:])

    def write_type(self, ostream):
        if type(self.type) is not enums.Types:
            msg = exceptions.ErrorStrings.BAD_EXP_RECV
            raise TypeError(msg.format(Base.__name__, 'type',
                                       enums.Types, type(self.type)))
        ostream.write(pack('!B', self.type.value))

    def write_length(self, ostream):
        if type(self.length) is not int:
            msg = exceptions.ErrorStrings.BAD_EXP_RECV
            raise TypeError(msg.format(Base.__name__, 'length',
                                       int, type(self.length)))
        num_bytes = utils.count_bytes(self.length)
        if num_bytes > self.LENGTH_SIZE:
            raise exceptions.WriteOverflowError(
                Base.__name__,
                'length',
                self.LENGTH_SIZE,
                num_bytes
            )
        ostream.write(pack('!I', self.length))

    def write_value(self, ostream):
        raise NotImplementedError()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        self.write_tag(ostream)
        self.write_type(ostream)
        self.write_length(ostream)

    def validate(self):
        raise NotImplementedError()

    @staticmethod
    def is_tag_next(tag, stream):
        next_tag = stream.peek(Base.TAG_SIZE)
        if len(next_tag) != Base.TAG_SIZE:
            return False
        next_tag = unpack('!I', b'\x00' + next_tag)[0]
        if next_tag == tag.value:
            return True
        else:
            return False

    @staticmethod
    def is_type_next(kmip_type, stream):
        tag_type_size = Base.TAG_SIZE + Base.TYPE_SIZE
        tt = stream.peek(tag_type_size)

        if len(tt) != tag_type_size:
            return False

        typ = unpack('!B', tt[Base.TAG_SIZE:])[0]

        if typ == kmip_type.value:
            return True
        else:
            return False

class Struct(Base):

    def __init__(self, tag=enums.Tags.DEFAULT):
        super(Struct, self).__init__(tag, type=enums.Types.STRUCTURE)

    # NOTE (peter-hamilton) If seen, should indicate repr needs to be defined
    def __repr__(self):
        return "Struct()"

class Integer(Base):
    LENGTH = 4

    # Set for signed 32-bit integers
    MIN = -2147483648
    MAX = 2147483647

    def __init__(self, value=None, tag=enums.Tags.DEFAULT, signed=True):
        super(Integer, self).__init__(tag, type=enums.Types.INTEGER)

        self.value = value
        if self.value is None:
            self.value = 0

        self.length = self.LENGTH
        self.padding_length = self.LENGTH
        if signed:
            self.pack_string = '!i'
        else:
            self.pack_string = '!I'

        self.validate()

    def read_value(self, istream):
        if self.length is not self.LENGTH:
            raise exceptions.ReadValueError(
                Integer.__name__,
                'length',
                self.LENGTH,
                self.length
            )

        self.value = unpack(self.pack_string, istream.read(self.length))[0]
        pad = unpack(self.pack_string, istream.read(self.padding_length))[0]

        if pad != 0:
            raise exceptions.ReadValueError(
                Integer.__name__,
                'pad',
                0,
                pad
            )
        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(Integer, self).read(istream, kmip_version=kmip_version)
        self.read_value(istream)

    def write_value(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        ostream.write(pack(self.pack_string, self.value))
        ostream.write(pack(self.pack_string, 0))

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(Integer, self).write(ostream, kmip_version=kmip_version)
        self.write_value(ostream, kmip_version=kmip_version)

    def validate(self):
        """
        Verify that the value of the Integer object is valid.

        Raises:
            TypeError: if the value is not of type int or long
            ValueError: if the value cannot be represented by a signed 32-bit
                integer
        """
        if self.value is not None:
            if type(self.value) is not int:
                raise TypeError('expected (one of): {0}, observed: {1}'.format(
                    int, type(self.value)))
            else:
                if self.value > Integer.MAX:
                    raise ValueError('integer value greater than accepted max')
                elif self.value < Integer.MIN:
                    raise ValueError('integer value less than accepted min')

    def __repr__(self):
        return "{0}(value={1})".format(type(self).__name__, self.value)

    def __str__(self):
        return str(self.value)

    def __eq__(self, other):
        if isinstance(other, Integer):
            return self.value == other.value
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Integer):
            return not self.__eq__(other)
        else:
            return NotImplemented

    def __lt__(self, other):
        if isinstance(other, Integer):
            return self.value < other.value
        else:
            return NotImplemented

    def __gt__(self, other):
        if isinstance(other, Integer):
            return self.value > other.value
        else:
            return NotImplemented

    def __le__(self, other):
        if isinstance(other, Integer):
            return self.__eq__(other) or self.__lt__(other)
        else:
            return NotImplemented

    def __ge__(self, other):
        if isinstance(other, Integer):
            return self.__eq__(other) or self.__gt__(other)
        else:
            return NotImplemented

class LongInteger(Base):
    """
    An encodeable object representing a long integer value.

    A LongInteger is one of the KMIP primitive object types. It is encoded as
    a signed, big-endian, 64-bit integer. For more information, see Section
    9.1 of the KMIP 1.1 specification.
    """

    LENGTH = 8

    # Bounds for signed 64-bit integers
    MIN = -9223372036854775808
    MAX = 9223372036854775807

    def __init__(self, value=0, tag=enums.Tags.DEFAULT):
        """
        Create a LongInteger.

        Args:
            value (int): The value of the LongInteger. Optional, defaults to 0.
            tag (Tags): An enumeration defining the tag of the LongInteger.
                Optional, defaults to Tags.DEFAULT.
        """
        super(LongInteger, self).__init__(tag, type=enums.Types.LONG_INTEGER)
        self.value = value
        self.length = LongInteger.LENGTH

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the encoding of the LongInteger from the input stream.

        Args:
            istream (stream): A buffer containing the encoded bytes of a
                LongInteger. Usually a BytearrayStream object. Required.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidPrimitiveLength: if the long integer encoding read in has
                an invalid encoded length.
        """
        super(LongInteger, self).read(istream, kmip_version=kmip_version)

        if self.length is not LongInteger.LENGTH:
            raise exceptions.InvalidPrimitiveLength(
                "invalid long integer length read; "
                "expected: {0}, observed: {1}".format(
                    LongInteger.LENGTH, self.length))

        self.value = unpack('!q', istream.read(self.length))[0]
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the encoding of the LongInteger to the output stream.

        Args:
            ostream (stream): A buffer to contain the encoded bytes of a
                LongInteger. Usually a BytearrayStream object. Required.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        super(LongInteger, self).write(ostream, kmip_version=kmip_version)
        ostream.write(pack('!q', self.value))

    def validate(self):
        """
        Verify that the value of the LongInteger is valid.

        Raises:
            TypeError: if the value is not of type int or long
            ValueError: if the value cannot be represented by a signed 64-bit
                integer
        """
        if self.value is not None:
            if not isinstance(self.value, int):
                raise TypeError('expected (one of): {0}, observed: {1}'.format(
                    int, type(self.value)))
            else:
                if self.value > LongInteger.MAX:
                    raise ValueError(
                        'long integer value greater than accepted max')
                elif self.value < LongInteger.MIN:
                    raise ValueError(
                        'long integer value less than accepted min')

    def __repr__(self):
        return "LongInteger(value={0}, tag={1})".format(self.value, self.tag)

    def __str__(self):
        return str(self.value)

    def __eq__(self, other):
        if isinstance(other, LongInteger):
            if self.value == other.value:
                return True
            else:
                return False
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, LongInteger):
            return not self.__eq__(other)
        else:
            return NotImplemented

class BigInteger(Base):
    """
    An encodeable object representing a big integer value.

    A BigInteger is one of the KMIP primitive object types. It is encoded as
    a signed, big-endian, integer of arbitrary size. For more information, see
    Section 9.1 of the KMIP 1.1 specification.
    """

    def __init__(self, value=0, tag=enums.Tags.DEFAULT):
        super(BigInteger, self).__init__(tag, type=enums.Types.BIG_INTEGER)
        self.value = value

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the encoding of the BigInteger from the input stream.

        Args:
            istream (stream): A buffer containing the encoded bytes of the
                value of a BigInteger. Usually a BytearrayStream object.
                Required.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidPrimitiveLength: if the big integer encoding read in has
                an invalid encoded length.
        """
        super(BigInteger, self).read(istream, kmip_version=kmip_version)

        # Check for a valid length before even trying to parse the value.
        if self.length % 8:
            raise exceptions.InvalidPrimitiveLength(
                "invalid big integer length read; "
                "expected: multiple of 8, observed: {0}".format(self.length))

        sign = 1
        binary = ''

        # Read the value byte by byte and convert it into binary, padding each
        # byte as needed.
        for _ in range(self.length):
            byte = struct.unpack('!B', istream.read(1))[0]
            bits = "{0:b}".format(byte)
            pad = len(bits) % 8
            if pad:
                bits = ('0' * (8 - pad)) + bits
            binary += bits

        # If the value is negative, convert via two's complement.
        if binary[0] == '1':
            sign = -1
            binary = binary.replace('1', 'i')
            binary = binary.replace('0', '1')
            binary = binary.replace('i', '0')

            pivot = binary.rfind('0')
            binary = binary[0:pivot] + '1' + ('0' * len(binary[pivot + 1:]))

        # Convert the value back to an integer and reapply the sign.
        self.value = int(binary, 2) * sign

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the encoding of the BigInteger to the output stream.

        Args:
            ostream (Stream): A buffer to contain the encoded bytes of a
                BigInteger object. Usually a BytearrayStream object.
                Required.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        # Convert the value to binary and pad it as needed.
        binary = "{0:b}".format(abs(self.value))
        binary = ("0" * (64 - (len(binary) % 64))) + binary

        # If the value is negative, convert via two's complement.
        if self.value < 0:
            binary = binary.replace('1', 'i')
            binary = binary.replace('0', '1')
            binary = binary.replace('i', '0')

            pivot = binary.rfind('0')
            binary = binary[0:pivot] + '1' + ('0' * len(binary[pivot + 1:]))

        # Convert each byte to hex and build the hex string for the value.
        hexadecimal = b''
        for i in range(0, len(binary), 8):
            byte = binary[i:i + 8]
            byte = int(byte, 2)
            hexadecimal += struct.pack('!B', byte)

        self.length = len(hexadecimal)
        super(BigInteger, self).write(ostream, kmip_version=kmip_version)
        ostream.write(hexadecimal)

    def validate(self):
        """
        Verify that the value of the BigInteger is valid.

        Raises:
            TypeError: if the value is not of type int or long
        """
        if self.value is not None:
            if not isinstance(self.value, int):
                raise TypeError('expected (one of): {0}, observed: {1}'.format(
                    int, type(self.value)))

    def __repr__(self):
        return "BigInteger(value={0}, tag={1})".format(self.value, self.tag)

    def __str__(self):
        return str(self.value)

    def __eq__(self, other):
        if isinstance(other, BigInteger):
            if self.value == other.value:
                return True
            else:
                return False
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, BigInteger):
            return not self.__eq__(other)
        else:
            return NotImplemented

class Enumeration(Base):
    """
    An encodeable object representing an enumeration.

    An Enumeration is one of the KMIP primitive object types. It is encoded as
    an unsigned, big-endian, 32-bit integer. For more information, see Section
    9.1 of the KMIP 1.1 specification.
    """
    LENGTH = 4

    # Bounds for unsigned 32-bit integers
    MIN = 0
    MAX = 4294967295

    def __init__(self, enum, value=None, tag=enums.Tags.DEFAULT):
        """
        Create an Enumeration.

        Args:
            enum (class): The enumeration class of which value is a member
                (e.g., Tags). Required.
            value (int): The value of the Enumeration, must be an integer
                (e.g., Tags.DEFAULT). Optional, defaults to None.
            tag (Tags): An enumeration defining the tag of the Enumeration.
                Optional, defaults to Tags.DEFAULT.
        """
        super(Enumeration, self).__init__(tag, enums.Types.ENUMERATION)

        self.value = value
        self.enum = enum
        self.length = Enumeration.LENGTH

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the encoding of the Enumeration from the input stream.

        Args:
            istream (stream): A buffer containing the encoded bytes of an
                Enumeration. Usually a BytearrayStream object. Required.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidPrimitiveLength: if the Enumeration encoding read in has an
                invalid encoded length.
            InvalidPaddingBytes: if the Enumeration encoding read in does not
                use zeroes for its padding bytes.
        """
        super(Enumeration, self).read(istream, kmip_version=kmip_version)

        # Check for a valid length before even trying to parse the value.
        if self.length != Enumeration.LENGTH:
            raise exceptions.InvalidPrimitiveLength(
                "enumeration length must be {0}".format(Enumeration.LENGTH))

        # Decode the Enumeration value and the padding bytes.
        value = unpack('!I', istream.read(Enumeration.LENGTH))[0]
        self.value = self.enum(value)
        pad = unpack('!I', istream.read(Enumeration.LENGTH))[0]

        # Verify that the padding bytes are zero bytes.
        if pad != 0:
            raise exceptions.InvalidPaddingBytes("padding bytes must be zero")

        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the encoding of the Enumeration to the output stream.

        Args:
            ostream (stream): A buffer to contain the encoded bytes of an
                Enumeration. Usually a BytearrayStream object. Required.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        super(Enumeration, self).write(ostream, kmip_version=kmip_version)
        ostream.write(pack('!I', self.value.value))
        ostream.write(pack('!I', 0))

    def validate(self):
        """
        Verify that the value of the Enumeration is valid.

        Raises:
            TypeError: if the enum is not of type Enum
            ValueError: if the value is not of the expected Enum subtype or if
                the value cannot be represented by an unsigned 32-bit integer
        """
        if not isinstance(self.enum, enumeration.EnumMeta):
            raise TypeError(
                'enumeration type {0} must be of type EnumMeta'.format(
                    self.enum))
        if self.value is not None:
            if not isinstance(self.value, self.enum):
                raise TypeError(
                    'enumeration {0} must be of type {1}'.format(
                        self.value, self.enum))
            if type(self.value.value) is not int:
                raise TypeError('enumeration value must be an int')
            else:
                if self.value.value > Enumeration.MAX:
                    raise ValueError(
                        'enumeration value greater than accepted max')
                elif self.value.value < Enumeration.MIN:
                    raise ValueError(
                        'enumeration value less than accepted min')

    def __repr__(self):
        enum = "enum={0}".format(self.enum.__name__)
        value = "value={0}".format(self.value)
        tag = "tag={0}".format(self.tag)
        return "Enumeration({0}, {1}, {2})".format(enum, value, tag)

    def __str__(self):
        return str(self.value)

    def __eq__(self, other):
        if isinstance(other, Enumeration):
            return ((self.enum == other.enum) and (self.value == other.value))
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Enumeration):
            return not self.__eq__(other)
        else:
            return NotImplemented

class Boolean(Base):
    """
    An encodeable object representing a boolean value.

    A Boolean is one of the KMIP primitive object types. It is encoded as an
    unsigned, big-endian, 8-byte value, capable of taking the values True (1)
    or False (0). For more information, see Section 9.1 of the KMIP 1.1
    specification.
    """
    LENGTH = 8

    def __init__(self, value=True, tag=enums.Tags.DEFAULT):
        """
        Create a Boolean object.

        Args:
            value (bool): The value of the Boolean. Optional, defaults to True.
            tag (Tags): An enumeration defining the tag of the Boolean object.
                Optional, defaults to Tags.DEFAULT.
        """
        super(Boolean, self).__init__(tag, type=enums.Types.BOOLEAN)
        self.logger = logging.getLogger(__name__)
        self.value = value
        self.length = self.LENGTH

        self.validate()

    def read_value(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the value of the Boolean object from the input stream.

        Args:
            istream (Stream): A buffer containing the encoded bytes of the
                value of a Boolean object. Usually a BytearrayStream object.
                Required.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: if the read boolean value is not a 0 or 1.
        """
        try:
            value = unpack('!Q', istream.read(self.LENGTH))[0]
        except Exception:
            self.logger.error("Error reading boolean value from buffer")
            raise

        if value == 1:
            self.value = True
        elif value == 0:
            self.value = False
        else:
            raise ValueError("expected: 0 or 1, observed: {0}".format(value))

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the encoding of the Boolean object from the input stream.

        Args:
            istream (Stream): A buffer containing the encoded bytes of a
                Boolean object. Usually a BytearrayStream object. Required.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(Boolean, self).read(istream, kmip_version=kmip_version)
        self.read_value(istream, kmip_version=kmip_version)

    def write_value(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the value of the Boolean object to the output stream.

        Args:
            ostream (Stream): A buffer to contain the encoded bytes of the
                value of a Boolean object. Usually a BytearrayStream object.
                Required.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        try:
            ostream.write(pack('!Q', self.value))
        except Exception:
            self.logger.error("Error writing boolean value to buffer")
            raise

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the encoding of the Boolean object to the output stream.

        Args:
            ostream (Stream): A buffer to contain the encoded bytes of a
                Boolean object. Usually a BytearrayStream object. Required.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        super(Boolean, self).write(ostream, kmip_version=kmip_version)
        self.write_value(ostream, kmip_version=kmip_version)

    def validate(self):
        """
        Verify that the value of the Boolean object is valid.

        Raises:
            TypeError: if the value is not of type bool.
        """
        if self.value:
            if not isinstance(self.value, bool):
                raise TypeError("expected: {0}, observed: {1}".format(
                    bool, type(self.value)))

    def __repr__(self):
        return "{0}(value={1})".format(type(self).__name__, repr(self.value))

    def __str__(self):
        return "{0}".format(repr(self.value))

    def __eq__(self, other):
        if isinstance(other, Boolean):
            return self.value == other.value
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Boolean):
            return not self.__eq__(other)
        else:
            return NotImplemented

class TextString(Base):
    PADDING_SIZE = 8
    BYTE_FORMAT = '!c'

    def __init__(self, value=None, tag=enums.Tags.DEFAULT):
        super(TextString, self).__init__(tag, type=enums.Types.TEXT_STRING)

        if value is None:
            self.value = ''
        else:
            self.value = value

        self.validate()

        if self.value is not None:
            self.length = len(self.value)
            self.padding_length = self.PADDING_SIZE - (self.length %
                                                       self.PADDING_SIZE)
            if self.padding_length == self.PADDING_SIZE:
                self.padding_length = 0
        else:
            self.length = None
            self.padding_length = None

    def read_value(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        # Read string text
        self.value = ''
        for _ in range(self.length):
            c = unpack(self.BYTE_FORMAT, istream.read(1))[0]
            if sys.version >= '3':
                c = c.decode()
            self.value += c

        # Read padding and check content
        self.padding_length = self.PADDING_SIZE - (self.length %
                                                   self.PADDING_SIZE)
        if self.padding_length == self.PADDING_SIZE:
            self.padding_length = 0
        if self.padding_length < self.PADDING_SIZE:
            for _ in range(self.padding_length):
                pad = unpack('!B', istream.read(1))[0]
                if pad != 0:
                    raise exceptions.ReadValueError(
                        TextString.__name__,
                        'pad',
                        0,
                        pad
                    )

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(TextString, self).read(istream, kmip_version=kmip_version)
        self.read_value(istream, kmip_version=kmip_version)
        self.validate()

    def write_value(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        # Write string to stream
        for char in self.value:
            ostream.write(pack(self.BYTE_FORMAT, char.encode()))

        # Write padding to stream
        for _ in range(self.padding_length):
            ostream.write(pack('!B', 0))

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(TextString, self).write(ostream, kmip_version=kmip_version)
        self.write_value(ostream, kmip_version=kmip_version)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.value is not None:
            if not isinstance(self.value, str):
                msg = exceptions.ErrorStrings.BAD_EXP_RECV
                raise TypeError(msg.format('TextString', 'value', str,
                                           type(self.value)))

    def __repr__(self):
        return "{0}(value={1})".format(type(self).__name__, repr(self.value))

    def __str__(self):
        return "{0}".format(str(self.value))

    def __eq__(self, other):
        if isinstance(other, TextString):
            return self.value == other.value
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, TextString):
            return not (self == other)
        else:
            return NotImplemented

class ByteString(Base):
    PADDING_SIZE = 8
    BYTE_FORMAT = '!B'

    def __init__(self, value=None, tag=enums.Tags.DEFAULT):
        super(ByteString, self).__init__(tag, type=enums.Types.BYTE_STRING)

        if value is None:
            self.value = bytes()
        else:
            self.value = bytes(value)

        self.validate()

        if self.value is not None:
            self.length = len(self.value)
            self.padding_length = self.PADDING_SIZE - (self.length %
                                                       self.PADDING_SIZE)
            if self.padding_length == self.PADDING_SIZE:
                self.padding_length = 0
        else:
            self.length = None
            self.padding_length = None

    def read_value(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        # Read bytes into bytearray
        data = bytearray()
        for _ in range(self.length):
            data.append(istream.read(1)[0])
        self.value = bytes(data)

        # Read padding and check content
        self.padding_length = self.PADDING_SIZE - (self.length %
                                                   self.PADDING_SIZE)
        if self.padding_length == self.PADDING_SIZE:
            self.padding_length = 0

        if self.padding_length < self.PADDING_SIZE:
            for _ in range(self.padding_length):
                pad = unpack('!B', istream.read(1))[0]
                if pad != 0:
                    raise exceptions.ReadValueError(
                        TextString.__name__,
                        'pad',
                        0,
                        pad
                    )

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(ByteString, self).read(istream, kmip_version=kmip_version)
        self.read_value(istream, kmip_version=kmip_version)

    def write_value(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        # Write bytes to stream
        data = bytearray(self.value)
        for byte in data:
            ostream.write(pack(self.BYTE_FORMAT, byte))

        # Write padding to stream
        for _ in range(self.padding_length):
            ostream.write(pack('!B', 0))

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(ByteString, self).write(ostream, kmip_version=kmip_version)
        self.write_value(ostream, kmip_version=kmip_version)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Test is pointless, value is always bytes. Fix.
        if self.value is not None:
            data_type = type(self.value)
            if data_type is not bytes:
                msg = exceptions.ErrorStrings.BAD_EXP_RECV
                raise TypeError(msg.format('ByteString', 'value', bytes,
                                           data_type))

    def __repr__(self):
        return "{0}(value={1})".format(type(self).__name__, repr(self.value))

    def __str__(self):
        return "{0}".format(str(self.value))

    def __eq__(self, other):
        if isinstance(other, ByteString):
            return self.value == other.value
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ByteString):
            return not (self == other)
        else:
            return NotImplemented

class DateTime(LongInteger):
    """
    An encodeable object representing a date/time value.

    A DateTime is one of the KMIP primitive object types. It is encoded as
    a signed, big-endian, 64-bit integer, representing a POSIX time value as
    the number of seconds since the Epoch (1970 January 1, 00:00:00 UTC). For
    more information, see Section 9.1 of the KMIP 1.1 specification.
    """

    def __init__(self, value=None, tag=enums.Tags.DEFAULT):
        """
        Create a DateTime.

        Args:
            value (int): The value of the DateTime in number of seconds since
                the Epoch. See the time package for additional information.
                Optional, defaults to the current time.
            tag (Tags): An enumeration defining the tag of the LongInteger.
                Optional, defaults to Tags.DEFAULT.
        """
        if value is None:
            value = int(time.time())
        super(DateTime, self).__init__(value, tag)
        self.type = enums.Types.DATE_TIME

    def __repr__(self):
        return "DateTime(value={0}, tag={1})".format(self.value, self.tag)

    def __str__(self):
        return time.asctime(time.gmtime(self.value))

class Interval(Base):
    """
    An encodeable object representing an interval of time.

    An Interval is one of the KMIP primitive object types. It is encoded as
    an unsigned, big-endian, 32-bit integer, where the value has a resolution
    of one second. For more information, see Section 9.1 of the KMIP 1.1
    specification.
    """
    LENGTH = 4

    # Bounds for unsigned 32-bit integers
    MIN = 0
    MAX = 4294967295

    def __init__(self, value=0, tag=enums.Tags.DEFAULT):
        super(Interval, self).__init__(tag, type=enums.Types.INTERVAL)

        self.value = value
        self.length = Interval.LENGTH

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the encoding of the Interval from the input stream.

        Args:
            istream (stream): A buffer containing the encoded bytes of the
                value of an Interval. Usually a BytearrayStream object.
                Required.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidPrimitiveLength: if the Interval encoding read in has an
                invalid encoded length.
            InvalidPaddingBytes: if the Interval encoding read in does not use
                zeroes for its padding bytes.
        """
        super(Interval, self).read(istream, kmip_version=kmip_version)

        # Check for a valid length before even trying to parse the value.
        if self.length != Interval.LENGTH:
            raise exceptions.InvalidPrimitiveLength(
                "interval length must be {0}".format(Interval.LENGTH))

        # Decode the Interval value and the padding bytes.
        self.value = unpack('!I', istream.read(Interval.LENGTH))[0]
        pad = unpack('!I', istream.read(Interval.LENGTH))[0]

        # Verify that the padding bytes are zero bytes.
        if pad != 0:
            raise exceptions.InvalidPaddingBytes("padding bytes must be zero")

        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the encoding of the Interval to the output stream.

        Args:
            ostream (stream): A buffer to contain the encoded bytes of an
                Interval. Usually a BytearrayStream object. Required.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        super(Interval, self).write(ostream, kmip_version=kmip_version)
        ostream.write(pack('!I', self.value))
        ostream.write(pack('!I', 0))

    def validate(self):
        """
        Verify that the value of the Interval is valid.

        Raises:
            TypeError: if the value is not of type int or long
            ValueError: if the value cannot be represented by an unsigned
                32-bit integer
        """
        if self.value is not None:
            if type(self.value) is not int:
                raise TypeError('expected (one of): {0}, observed: {1}'.format(
                    int, type(self.value)))
            else:
                if self.value > Interval.MAX:
                    raise ValueError(
                        'interval value greater than accepted max')
                elif self.value < Interval.MIN:
                    raise ValueError('interval value less than accepted min')

    def __repr__(self):
        value = "value={0}".format(self.value)
        tag = "tag={0}".format(self.tag)
        return "Interval({0}, {1})".format(value, tag)

    def __str__(self):
        return "{0}".format(self.value)

    def __eq__(self, other):
        if isinstance(other, Interval):
            return self.value == other.value
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Interval):
            return not self.__eq__(other)
        else:
            return NotImplemented
