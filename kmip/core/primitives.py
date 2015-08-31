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

import logging
import six
import sys
import time

from struct import pack, unpack
from enum import Enum

from kmip.core.enums import Types
from kmip.core.enums import Tags

from kmip.core.errors import ErrorStrings

from kmip.core import errors
from kmip.core import exceptions
from kmip.core import utils


class Base(object):
    TAG_SIZE = 3
    TYPE_SIZE = 1
    LENGTH_SIZE = 4

    def __init__(self, tag=Tags.DEFAULT, type=Types.DEFAULT):
        self.tag = tag
        self.type = type
        self.length = None

    # TODO (peter-hamilton) Convert this into a classmethod, class name can be
    #                       obtained from cls parameter that replaces self
    def is_oversized(self, stream):
        extra = len(stream.peek())
        if extra > 0:
            raise errors.StreamNotEmptyError(Base.__name__, extra)

    def read_tag(self, istream):
        # Read in the bytes for the tag
        tts = istream.read(self.TAG_SIZE)
        tag = unpack('!I', b'\x00' + tts[0:self.TAG_SIZE])[0]

        enum_tag = Tags(tag)

        # Verify that the tag matches for the current object
        if enum_tag is not self.tag:
            raise errors.ReadValueError(Base.__name__, 'tag',
                                        hex(self.tag.value), hex(tag))

    def read_type(self, istream):
        # Read in the bytes for the type
        tts = istream.read(self.TYPE_SIZE)
        num_bytes = len(tts)
        if num_bytes != self.TYPE_SIZE:
            min_bytes = 'a minimum of {0} bytes'.format(self.TYPE_SIZE)
            raise errors.ReadValueError(Base.__name__, 'type', min_bytes,
                                        '{0} bytes'.format(num_bytes))
        typ = unpack('!B', tts)[0]

        enum_typ = Types(typ)

        if enum_typ is not self.type:
            raise errors.ReadValueError(Base.__name__, 'type',
                                        self.type.value, typ)

    def read_length(self, istream):
        # Read in the bytes for the length
        lst = istream.read(self.LENGTH_SIZE)
        num_bytes = len(lst)
        if num_bytes != self.LENGTH_SIZE:
            min_bytes = 'a minimum of {0} bytes'.format(self.LENGTH_SIZE)
            raise errors.ReadValueError(Base.__name__, 'length', min_bytes,
                                        '{0} bytes'.format(num_bytes))
        self.length = unpack('!I', lst)[0]

    def read_value(self, istream):
        raise NotImplementedError()

    def read(self, istream):
        self.read_tag(istream)
        self.read_type(istream)
        self.read_length(istream)

    def write_tag(self, ostream):
        # Write the tag to the output stream
        ostream.write(pack('!I', self.tag.value)[1:])

    def write_type(self, ostream):
        if type(self.type) is not Types:
            msg = ErrorStrings.BAD_EXP_RECV
            raise TypeError(msg.format(Base.__name__, 'type',
                                       Types, type(self.type)))
        ostream.write(pack('!B', self.type.value))

    def write_length(self, ostream):
        if type(self.length) is not int:
            msg = ErrorStrings.BAD_EXP_RECV
            raise TypeError(msg.format(Base.__name__, 'length',
                                       int, type(self.length)))
        num_bytes = utils.count_bytes(self.length)
        if num_bytes > self.LENGTH_SIZE:
            raise errors.WriteOverflowError(Base.__name__, 'length',
                                            self.LENGTH_SIZE, num_bytes)
        ostream.write(pack('!I', self.length))

    def write_value(self, ostream):
        raise NotImplementedError()

    def write(self, ostream):
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

    def __init__(self, tag=Tags.DEFAULT):
        super(Struct, self).__init__(tag, type=Types.STRUCTURE)

    # NOTE (peter-hamilton) If seen, should indicate repr needs to be defined
    def __repr__(self):
        return "Struct()"


class Integer(Base):
    LENGTH = 4

    # Set for signed 32-bit integers
    MIN = -2147483648
    MAX = 2147483647

    def __init__(self, value=None, tag=Tags.DEFAULT, signed=True):
        super(Integer, self).__init__(tag, type=Types.INTEGER)

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
            raise errors.ReadValueError(Integer.__name__, 'length',
                                        self.LENGTH, self.length)

        self.value = unpack(self.pack_string, istream.read(self.length))[0]
        pad = unpack(self.pack_string, istream.read(self.padding_length))[0]

        if pad is not 0:
            raise errors.ReadValueError(Integer.__name__, 'pad', 0,
                                        pad)
        self.validate()

    def read(self, istream):
        super(Integer, self).read(istream)
        self.read_value(istream)

    def write_value(self, ostream):
        ostream.write(pack(self.pack_string, self.value))
        ostream.write(pack(self.pack_string, 0))

    def write(self, ostream):
        super(Integer, self).write(ostream)
        self.write_value(ostream)

    def validate(self):
        """
        Verify that the value of the Integer object is valid.

        Raises:
            TypeError: if the value is not of type int or long
            ValueError: if the value cannot be represented by a signed 32-bit
                integer
        """
        if self.value is not None:
            if type(self.value) not in six.integer_types:
                raise TypeError('expected (one of): {0}, observed: {1}'.format(
                    six.integer_types, type(self.value)))
            else:
                if self.value > Integer.MAX:
                    raise ValueError('integer value greater than accepted max')
                elif self.value < Integer.MIN:
                    raise ValueError('integer value less than accepted min')

    def __repr__(self):
        return "{0}(value={1})".format(type(self).__name__, repr(self.value))

    def __str__(self):
        return "{0}".format(repr(self.value))

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

    def __init__(self, value=0, tag=Tags.DEFAULT):
        """
        Create a LongInteger.

        Args:
            value (int): The value of the LongInteger. Optional, defaults to 0.
            tag (Tags): An enumeration defining the tag of the LongInteger.
                Optional, defaults to Tags.DEFAULT.
        """
        super(LongInteger, self).__init__(tag, type=Types.LONG_INTEGER)
        self.value = value
        self.length = LongInteger.LENGTH

        self.validate()

    def read(self, istream):
        """
        Read the encoding of the LongInteger from the input stream.

        Args:
            istream (stream): A buffer containing the encoded bytes of a
                LongInteger. Usually a BytearrayStream object. Required.

        Raises:
            InvalidPrimitiveLength: if the long integer encoding read in has
                an invalid encoded length.
        """
        super(LongInteger, self).read(istream)

        if self.length is not LongInteger.LENGTH:
            raise exceptions.InvalidPrimitiveLength(
                "invalid long integer length read; "
                "expected: {0}, observed: {1}".format(
                    LongInteger.LENGTH, self.length))

        self.value = unpack('!q', istream.read(self.length))[0]
        self.validate()

    def write(self, ostream):
        """
        Write the encoding of the LongInteger to the output stream.

        Args:
            ostream (stream): A buffer to contain the encoded bytes of a
                LongInteger. Usually a BytearrayStream object. Required.
        """
        super(LongInteger, self).write(ostream)
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
            if not isinstance(self.value, six.integer_types):
                raise TypeError('expected (one of): {0}, observed: {1}'.format(
                    six.integer_types, type(self.value)))
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
    BLOCK_SIZE = 8
    SHIFT_SIZE = 64

    def __init__(self, value=None, tag=Tags.DEFAULT):
        super(BigInteger, self).__init__(tag, type=Types.BIG_INTEGER)
        self.value = value

        if self.value is not None:
            self.real_length = utils.count_bytes(self.value)
            self.padding_length = self.BLOCK_SIZE - (self.length %
                                                     self.BLOCK_SIZE)
            if self.padding_length == self.BLOCK_SIZE:
                self.padding_length = 0
        else:
            self.length = None
            self.padding_length = None

        self.validate()

    def read_value(self, istream):
        if (self.length < self.BLOCK_SIZE) or (self.length % self.BLOCK_SIZE):
            raise errors.InvalidLengthError(BigInteger.__name__,
                                            ('multiple'
                                             'of {0}'.format(self.BLOCK_SIZE)),
                                            self.length)
        self.value = 0
        num_blocks = self.length / self.BLOCK_SIZE

        # Read first block as signed data
        self.value = unpack('!q', str(istream.read(self.BLOCK_SIZE)))[0]

        # Shift current value and add on next unsigned block
        for _ in range(num_blocks - 1):
            self.value = self.value << self.SHIFT_SIZE
            stream_data = istream.read(self.BLOCK_SIZE)
            self.value += unpack('!Q', stream_data)[0]

        self.validate()

    def read(self, istream):
        super(BigInteger, self).read(istream)
        self.read_value(istream)

    def write_value(self, ostream):
        # 1. Determine the sign of the value (+/-); save it.
        # 2. Extend hex of value with 0s until encoding is right size (8x).
        # 3. Write out each block of the encoding as signed, 2s complement:
        #    pack('!q', sign * block)

        # Determine sign for padding
        pad_byte = 0x00
        pad_nybl = 0x0

        if self.value < 0:
            pad_byte = 0xff
            pad_nybl = 0xf

        # Compose padding bytes
        pad = ''
        for _ in range(self.padding_length):
            pad += hex(pad_byte)[2:]

        str_rep = hex(self.value).rstrip("Ll")[2:]
        if len(str_rep) % 2:
            pad += hex(pad_nybl)[2]

        # Compose value for block-based write
        str_rep = pad + str_rep
        num_blocks = len(str_rep) / self.BLOCK_SIZE

        # Write first block as signed data
        block = int(str_rep[0:self.BLOCK_SIZE], 16)
        ostream.write(pack('!q', block))

        # Write remaining blocks as unsigned data
        for i in range(1, num_blocks):
            block = str_rep[(self.BLOCK_SIZE * i):(self.BLOCK_SIZE * (i + 1))]
            block = int(block, 16)
            ostream.write(pack('!Q', block))

    def write(self, ostream):
        super(BigInteger, self).write(ostream)
        self.write_value(ostream)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.value is not None:
            data_type = type(self.value)
            if data_type not in six.integer_types:
                raise errors.StateTypeError(
                    BigInteger.__name__, "{0}".format(six.integer_types),
                    data_type)
            num_bytes = utils.count_bytes(self.length)
            if num_bytes > self.LENGTH_SIZE:
                raise errors.StateOverflowError(
                    BigInteger.__name__, 'length', self.LENGTH_SIZE,
                    num_bytes)


class Enumeration(Integer):
    ENUM_TYPE = None

    def __init__(self, value=None, tag=Tags.DEFAULT):
        self.enum = value
        self.validate()

        if self.enum is None:
            super(Enumeration, self).__init__(None, tag, False)
        else:
            super(Enumeration, self).__init__(self.enum.value, tag, False)
        self.type = Types.ENUMERATION

    def read(self, istream):
        super(Enumeration, self).read(istream)
        self.enum = self.ENUM_TYPE(self.value)
        self.validate()

    def write(self, ostream):
        super(Enumeration, self).write(ostream)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.enum is not None:
            if not isinstance(self.enum, Enum):
                raise TypeError("expected {0}, observed {1}".format(
                    type(self.enum), Enum))

    def __repr__(self):
        return "{0}(value={1})".format(type(self).__name__, self.enum)

    def __str__(self):
        return "{0}.{1}".format(type(self.enum).__name__, self.enum.name)


class Boolean(Base):
    """
    An encodeable object representing a boolean value.

    A Boolean is one of the KMIP primitive object types. It is encoded as an
    unsigned, big-endian, 8-byte value, capable of taking the values True (1)
    or False (0). For more information, see Section 9.1 of the KMIP 1.1
    specification.
    """
    LENGTH = 8

    def __init__(self, value=True, tag=Tags.DEFAULT):
        """
        Create a Boolean object.

        Args:
            value (bool): The value of the Boolean. Optional, defaults to True.
            tag (Tags): An enumeration defining the tag of the Boolean object.
                Optional, defaults to Tags.DEFAULT.
        """
        super(Boolean, self).__init__(tag, type=Types.BOOLEAN)
        self.logger = logging.getLogger(__name__)
        self.value = value
        self.length = self.LENGTH

        self.validate()

    def read_value(self, istream):
        """
        Read the value of the Boolean object from the input stream.

        Args:
            istream (Stream): A buffer containing the encoded bytes of the
                value of a Boolean object. Usually a BytearrayStream object.
                Required.

        Raises:
            ValueError: if the read boolean value is not a 0 or 1.
        """
        try:
            value = unpack('!Q', istream.read(self.LENGTH))[0]
        except:
            self.logger.error("Error reading boolean value from buffer")
            raise

        if value == 1:
            self.value = True
        elif value == 0:
            self.value = False
        else:
            raise ValueError("expected: 0 or 1, observed: {0}".format(value))

        self.validate()

    def read(self, istream):
        """
        Read the encoding of the Boolean object from the input stream.

        Args:
            istream (Stream): A buffer containing the encoded bytes of a
                Boolean object. Usually a BytearrayStream object. Required.
        """
        super(Boolean, self).read(istream)
        self.read_value(istream)

    def write_value(self, ostream):
        """
        Write the value of the Boolean object to the output stream.

        Args:
            ostream (Stream): A buffer to contain the encoded bytes of the
                value of a Boolean object. Usually a BytearrayStream object.
                Required.
        """
        try:
            ostream.write(pack('!Q', self.value))
        except:
            self.logger.error("Error writing boolean value to buffer")
            raise

    def write(self, ostream):
        """
        Write the encoding of the Boolean object to the output stream.

        Args:
            ostream (Stream): A buffer to contain the encoded bytes of a
                Boolean object. Usually a BytearrayStream object. Required.
        """
        super(Boolean, self).write(ostream)
        self.write_value(ostream)

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

    def __init__(self, value=None, tag=Tags.DEFAULT):
        super(TextString, self).__init__(tag, type=Types.TEXT_STRING)

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

    def read_value(self, istream):
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
        if self.padding_length < self.PADDING_SIZE:
            for _ in range(self.padding_length):
                pad = unpack('!B', istream.read(1))[0]
                if pad is not 0:
                    raise errors.ReadValueError(TextString.__name__, 'pad', 0,
                                                pad)

    def read(self, istream):
        super(TextString, self).read(istream)
        self.read_value(istream)
        self.validate()

    def write_value(self, ostream):
        # Write string to stream
        for char in self.value:
            if sys.version < '3':
                c = char
            else:
                c = char.encode()
            ostream.write(pack(self.BYTE_FORMAT, c))

        # Write padding to stream
        for _ in range(self.padding_length):
            ostream.write(pack('!B', 0))

    def write(self, ostream):
        super(TextString, self).write(ostream)
        self.write_value(ostream)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.value is not None:
            data_type = type(self.value)
            if data_type is not str:
                msg = ErrorStrings.BAD_EXP_RECV
                raise TypeError(msg.format('TextString', 'value', str,
                                           data_type))

    def __repr__(self):
        return "{0}(value={1})".format(type(self).__name__, repr(self.value))

    def __str__(self):
        return "{0}".format(repr(self.value))

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

    def __init__(self, value=None, tag=Tags.DEFAULT):
        super(ByteString, self).__init__(tag, type=Types.BYTE_STRING)

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

    def read_value(self, istream):
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
                if pad is not 0:
                    raise errors.ReadValueError(TextString.__name__, 'pad', 0,
                                                pad)

    def read(self, istream):
        super(ByteString, self).read(istream)
        self.read_value(istream)

    def write_value(self, ostream):
        # Write bytes to stream
        data = bytearray(self.value)
        for byte in data:
            ostream.write(pack(self.BYTE_FORMAT, byte))

        # Write padding to stream
        for _ in range(self.padding_length):
            ostream.write(pack('!B', 0))

    def write(self, ostream):
        super(ByteString, self).write(ostream)
        self.write_value(ostream)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Test is pointless, value is always bytes. Fix.
        if self.value is not None:
            data_type = type(self.value)
            if data_type is not bytes:
                msg = ErrorStrings.BAD_EXP_RECV
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

    def __init__(self, value=None, tag=Tags.DEFAULT):
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
        self.type = Types.DATE_TIME

    def __repr__(self):
        return "DateTime(value={0}, tag={1})".format(self.value, self.tag)

    def __str__(self):
        return time.ctime(self.value)


class Interval(Integer):

    def __init__(self, value=None, tag=Tags.DEFAULT):
        super(Interval, self).__init__(value, tag)
        self.type = Types.INTERVAL
