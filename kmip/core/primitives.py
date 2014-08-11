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

from struct import pack, unpack
from enum import Enum

from kmip.core.enums import Types
from kmip.core.enums import Tags

from kmip.core.errors import ErrorStrings

import errors
import utils


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
        tag = unpack('!I', '\x00' + tts[0:self.TAG_SIZE])[0]

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
        length = unpack('!I', lst)[0]

        # Verify that the length matches the expected length, if one exists
        if self.length is not None:
            if length is not self.length:
                raise errors.ReadValueError(Base.__name__, 'length',
                                            self.length, length)
        else:
            self.length = length

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
        next_tag = unpack('!I', '\x00' + next_tag)[0]
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

    def __repr__(self):
        return '<Struct>'


class Integer(Base):
    LENGTH = 4

    def __init__(self, value=None, tag=Tags.DEFAULT):
        super(Integer, self).__init__(tag, type=Types.INTEGER)

        self.value = value
        self.length = self.LENGTH
        self.padding_length = self.LENGTH

        self.validate()

    def read_value(self, istream):
        if self.length is not self.LENGTH:
            raise errors.ReadValueError(Integer.__name__, 'length',
                                        self.LENGTH, self.length)

        self.value = unpack('!i', str(istream.read(self.length)))[0]
        pad = unpack('!i', str(istream.read(self.padding_length)))[0]

        if pad is not 0:
            raise errors.ReadValueError(Integer.__name__, 'pad', 0,
                                        pad)
        self.validate()

    def read(self, istream):
        super(Integer, self).read(istream)
        self.read_value(istream)

    def write_value(self, ostream):
        ostream.write(pack('!i', self.value))
        ostream.write(pack('!i', 0))

    def write(self, ostream):
        super(Integer, self).write(ostream)
        self.write_value(ostream)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.value is not None:
            data_type = type(self.value)
            if data_type is not int:
                raise errors.StateTypeError(Integer.__name__, int,
                                            data_type)
            num_bytes = utils.count_bytes(self.value)
            if num_bytes > self.length:
                raise errors.StateOverflowError(Integer.__name__,
                                                'value', self.length,
                                                num_bytes)

    def __repr__(self):
        return '<Integer, %d>' % (self.value)


class LongInteger(Base):
    LENGTH = 8

    def __init__(self, value=None, tag=Tags.DEFAULT):
        super(LongInteger, self).__init__(tag, type=Types.LONG_INTEGER)
        self.value = value
        self.length = self.LENGTH

        self.validate()

    def read_value(self, istream):
        if self.length is not self.LENGTH:
            raise errors.ReadValueError(LongInteger.__name__, 'length',
                                        self.LENGTH, self.length)

        self.value = unpack('!q', str(istream.read(self.length)))[0]
        self.validate()

    def read(self, istream):
        super(LongInteger, self).read(istream)
        self.read_value(istream)

    def write_value(self, ostream):
        ostream.write(pack('!q', self.value))

    def write(self, ostream):
        super(LongInteger, self).write(ostream)
        self.write_value(ostream)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.value is not None:
            data_type = type(self.value)
            if data_type not in (int, long):
                raise errors.StateTypeError(LongInteger.__name__,
                                            '{0} or {1}'.format(int, long),
                                            data_type)
            num_bytes = utils.count_bytes(self.value)
            if num_bytes > self.length:
                raise errors.StateOverflowError(LongInteger.__name__,
                                                'value', self.length,
                                                num_bytes)

    def __repr__(self):
        return '<Long Integer, %d>' % (self.value)


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
        for _ in xrange(num_blocks - 1):
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
        for _ in xrange(self.padding_length):
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
        for i in xrange(1, num_blocks):
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
            if data_type not in (int, long):
                raise errors.StateTypeError(BigInteger.__name__,
                                            '{0} or {1}'.format(int, long),
                                            data_type)
            num_bytes = utils.count_bytes(self.length)
            if num_bytes > self.LENGTH_SIZE:
                raise errors.StateOverflowError(BigInteger.__name__,
                                                'length', self.LENGTH_SIZE,
                                                num_bytes)


class Enumeration(Integer):
    ENUM_TYPE = None

    def __init__(self, value=None, tag=Tags.DEFAULT):
        self.enum = value
        self.validate()

        if self.enum is None:
            super(Enumeration, self).__init__(None, tag)
        else:
            super(Enumeration, self).__init__(self.enum.value, tag)
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
            if type(self.enum) is not self.ENUM_TYPE:
                msg = ErrorStrings.BAD_EXP_RECV
                raise TypeError(msg.format(Enumeration.__name__, 'value',
                                           Enum, type(self.enum)))

    def __repr__(self):
        return '<Enumeration, %s, %d>' % (self.enum.name, self.enum.value)


class Boolean(Base):

    def __init__(self, value=None, tag=Tags.DEFAULT):
        super(Boolean, self).__init__(tag, type=Types.BOOLEAN)
        self.value = value
        self.length = 8

    def read_value(self, istream):
        value = unpack('!Q', str(istream[0:self.length]))[0]

        if value == 1:
            self.value = True
        elif value == 0:
            self.value = False
        else:
            raise errors.ReadValueError(Boolean.__name__, 'value',
                                        value)

        for _ in xrange(self.length):
            istream.pop(0)

    def read(self, istream):
        super(Boolean, self).read(istream)
        self.read_value(istream)

    def write_value(self, ostream):
        if self.value is None:
            raise errors.WriteValueError(Boolean.__name__, 'value',
                                         self.value)

        data_buffer = bytearray()

        if isinstance(self.value, type(True)):
            if self.value:
                data_buffer.extend(pack('!Q', 1))
            else:
                data_buffer.extend(pack('!Q', 0))
        else:
            raise errors.WriteTypeError(Boolean.__name__, 'value',
                                        type(self.value))

        ostream.extend(data_buffer)

    def write(self, ostream):
        super(Boolean, self).write(ostream)
        self.write_value(ostream)

    def validate(self):
        self.__validate()

    def __validate(self):
        pass

    def __repr__(self):
        return '<Boolean, %s>' % (self.value)


class TextString(Base):
    PADDING_SIZE = 8
    BYTE_FORMAT = '!c'

    def __init__(self, value=None, tag=Tags.DEFAULT):
        super(TextString, self).__init__(tag, type=Types.TEXT_STRING)
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
        for _ in xrange(self.length):
            self.value += unpack(self.BYTE_FORMAT, str(istream.read(1)))[0]

        # Read padding and check content
        self.padding_length = self.PADDING_SIZE - (self.length %
                                                   self.PADDING_SIZE)
        if self.padding_length < self.PADDING_SIZE:
            for _ in xrange(self.padding_length):
                pad = unpack('!B', str(istream.read(1)))[0]
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
            ostream.write(pack(self.BYTE_FORMAT, char))

        # Write padding to stream
        for _ in xrange(self.padding_length):
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
        return '<TextString, %s>' % (self.value)


class ByteString(Base):
    PADDING_SIZE = 8
    BYTE_FORMAT = '!B'

    def __init__(self, value=None, tag=Tags.DEFAULT):
        super(ByteString, self).__init__(tag, type=Types.BYTE_STRING)
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
        # Read bytes into bytearray
        self.value = bytearray()
        for _ in xrange(self.length):
            self.value.append(istream.read(1))

        # Read padding and check content
        self.padding_length = self.PADDING_SIZE - (self.length %
                                                   self.PADDING_SIZE)
        if self.padding_length == self.PADDING_SIZE:
            self.padding_length = 0

        if self.padding_length < self.PADDING_SIZE:
            for _ in xrange(self.padding_length):
                pad = unpack('!B', str(istream.read(1)))[0]
                if pad is not 0:
                    raise errors.ReadValueError(TextString.__name__, 'pad', 0,
                                                pad)

    def read(self, istream):
        super(ByteString, self).read(istream)
        self.read_value(istream)

    def write_value(self, ostream):
        # Write bytes to stream
        for byte in self.value:
            ostream.write(pack(self.BYTE_FORMAT, byte))

        # Write padding to stream
        for _ in xrange(self.padding_length):
            ostream.write(pack('!B', 0))

    def write(self, ostream):
        super(ByteString, self).write(ostream)
        self.write_value(ostream)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.value is not None:
            data_type = type(self.value)
            if data_type is not bytearray:
                msg = ErrorStrings.BAD_EXP_RECV
                raise TypeError(msg.format('ByteString', 'value', bytearray,
                                           data_type))

    def __repr__(self):
        return '<Integer, %s>' % (self.value)


class DateTime(LongInteger):

    def __init__(self, value=None, tag=Tags.DEFAULT):
        super(DateTime, self).__init__(value, tag)
        self.type = Types.DATE_TIME


class Interval(Integer):

    def __init__(self, value=None, tag=Tags.DEFAULT):
        super(Interval, self).__init__(value, tag)
        self.type = Types.INTERVAL
