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

from kmip.core.errors import ErrorStrings


def bit_length(num):
    s = bin(num)
    s = s.lstrip('0b')
    return len(s)


def count_bytes(num):
    bits = bit_length(num)
    num_bytes = bits / 8
    if bits == 0 or bits % 8:
        num_bytes += 1
    return num_bytes


def print_bytearray(array):
    sbuffer = hexlify_bytearray(array)
    print 'buffer: {0}'.format(sbuffer)


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
    msg = ErrorStrings.BAD_EXP_RECV

    class_string = ''
    if attribute is None:
        class_string = '{0}'.format(class_object.__name__)
    else:
        class_string = '{0}.{1}'.format(class_object.__name__, attribute)

    return msg.format(class_string, descriptor, expected, received)


class BytearrayStream(object):
    def __init__(self, data=None):
        if data is None:
            self.buffer = bytearray()
        else:
            self.buffer = bytearray(data)

    def read(self, n=None):
        if n is None:
            return str(self.buffer[0:])

        length = len(self.buffer)
        if n > length:
            n = length

        data = self.buffer[0:n]
        for _ in xrange(n):
            self.buffer.pop(0)
        return str(data)

    def peek(self, n=None):
        length = len(self.buffer)
        if n is None or n > length:
            n = length
        return str(self.buffer[0:n])

    def write(self, b):
        prev_bytes = len(self.buffer)
        self.buffer.extend(b)
        return len(self.buffer) - prev_bytes

    def length(self):
        return len(self.buffer)
