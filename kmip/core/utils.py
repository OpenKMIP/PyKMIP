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

from binascii import hexlify
import io

from kmip.core import exceptions

def bit_length(num):
    s = bin(num)
    s = s.lstrip('0b')
    return len(s)

def count_bytes(num):
    bits = bit_length(num)
    num_bytes = int(bits / 8)
    if bits == 0 or bits % 8:
        num_bytes += 1
    return num_bytes

def print_bytearray(array):
    sbuffer = hexlify_bytearray(array)
    print('buffer: {0}'.format(sbuffer))

def hexlify_bytearray(array):
    sbuffer = bytes(array[0:])
    return hexlify(sbuffer)

def is_stream_empty(stream):
    if len(stream.peek(1)) > 0:
        return False
    else:
        return True

def build_er_error(class_object, descriptor, expected, received,
                   attribute=None):
    msg = exceptions.ErrorStrings.BAD_EXP_RECV

    if attribute is None:
        class_string = '{0}'.format(class_object.__name__)
    else:
        class_string = '{0}.{1}'.format(class_object.__name__, attribute)

    return msg.format(class_string, descriptor, expected, received)

class BytearrayStream(io.RawIOBase):
    def __init__(self, data=None):
        if data is None:
            self.buffer = bytes()
        else:
            self.buffer = bytes(data)

    def read(self, n=None):
        if n is None or n == -1:
            return self.readall()
        length = len(self.buffer)
        if n > length:
            n = length
        data = self.buffer[0:n]
        self.buffer = self.buffer[n:]
        return data

    def readall(self):
        data = self.buffer
        self.buffer = bytes()
        return data

    # TODO (peter-hamilton) Unused, add documentation or cut.
    def readinto(self, b):
        if len(b) <= len(self.buffer):
            num_bytes_to_read = len(b)
        else:
            num_bytes_to_read = len(self.buffer)
        b[:num_bytes_to_read] = self.buffer[:num_bytes_to_read]
        self.buffer = self.buffer[num_bytes_to_read:]
        return num_bytes_to_read

    def peek(self, n=None):
        length = len(self.buffer)
        if n is None or n > length:
            n = length
        return self.buffer[0:n]

    def write(self, b):
        prev_bytes = len(self.buffer)
        self.buffer += b
        return len(self.buffer) - prev_bytes

    def length(self):
        return len(self.buffer)

    def __str__(self):
        sbuffer = bytes(self.buffer[0:])
        return str(hexlify(sbuffer))

    def __len__(self):
        return len(self.buffer)

    def __eq__(self, other):
        if isinstance(other, BytearrayStream):
            if len(self.buffer) != len(other.buffer):
                return False
            elif self.buffer != other.buffer:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, BytearrayStream):
            return not (self == other)
        else:
            return NotImplemented
