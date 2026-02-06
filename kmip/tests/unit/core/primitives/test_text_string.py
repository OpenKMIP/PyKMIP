# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
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

import testtools

from kmip.core import exceptions
from kmip.core import primitives
from kmip.core import utils

class TestTextString(testtools.TestCase):

    def setUp(self):
        super(TestTextString, self).setUp()
        self.stream = utils.BytearrayStream()
        self.bad_type = exceptions.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.TextString.{0}', 'type', '{1}', '{2}')
        self.bad_value = exceptions.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.TextString.{0}', 'value', '{1}', '{2}')
        self.bad_read = exceptions.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.TextString.{0}', '', '{1}', '{2}')
        self.bad_write = exceptions.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.TextString.{0}', 'write', '{1}', '{2}')
        self.bad_encoding = exceptions.ErrorStrings.BAD_ENCODING.format(
            'primitives.TextString', '')
        self.bad_length = exceptions.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.TextString', 'length', '{0} bytes', '{1} bytes')

    def tearDown(self):
        super(TestTextString, self).tearDown()

    def test_init(self):
        value = 'Hello World'
        ts = primitives.TextString(value)

        self.assertIsInstance(ts.value, str,
                              self.bad_type.format('value', str,
                                                   type(ts.value)))
        self.assertEqual(value, ts.value,
                         self.bad_value.format('value', value, ts.value))

    def test_init_unset(self):
        text_string = primitives.TextString()

        expected = str
        observed = text_string.value

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertIsInstance(observed, expected, msg)

        expected = ''

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_validate_on_valid(self):
        ts = primitives.TextString()
        ts.value = 'Hello World'

        # Check no exception thrown.
        ts.validate()

    def test_validate_on_valid_unset(self):
        ts = primitives.TextString()

        # Check no exception thrown.
        ts.validate()

    def test_validate_on_invalid_type(self):
        ts = primitives.TextString()
        ts.value = 0

        self.assertRaises(TypeError, ts.validate)

    def test_read_value(self):
        encoding = (
            b'\x48\x65\x6C\x6C\x6F\x20\x57\x6F\x72\x6C\x64\x00\x00\x00\x00'
            b'\x00')
        self.stream = utils.BytearrayStream(encoding)
        ts = primitives.TextString()
        ts.length = 0x0B
        ts.read_value(self.stream)

        expected = 'Hello World'
        self.assertEqual(expected, ts.value,
                         self.bad_read.format('value', expected, ts.value))

    def test_read_value_no_padding(self):
        encoding = (b'\x48\x65\x6C\x6C\x6F\x20\x57\x6F')
        self.stream = utils.BytearrayStream(encoding)
        ts = primitives.TextString()
        ts.length = 0x08
        ts.read_value(self.stream)

        expected = 'Hello Wo'
        self.assertEqual(expected, ts.value,
                         self.bad_read.format('value', expected, ts.value))

    def test_read_value_max_padding(self):
        encoding = (b'\x48\x00\x00\x00\x00\x00\x00\x00')
        self.stream = utils.BytearrayStream(encoding)
        ts = primitives.TextString()
        ts.length = 0x01
        ts.read_value(self.stream)

        expected = 'H'
        self.assertEqual(expected, ts.value,
                         self.bad_read.format('value', expected, ts.value))

    def test_read(self):
        encoding = (
            b'\x42\x00\x00\x07\x00\x00\x00\x0B\x48\x65\x6C\x6C\x6F\x20\x57'
            b'\x6F\x72\x6C\x64\x00\x00\x00\x00\x00')
        self.stream = utils.BytearrayStream(encoding)
        ts = primitives.TextString()
        ts.read(self.stream)

        expected = 'Hello World'
        self.assertEqual(expected, ts.value,
                         self.bad_read.format('value', expected, ts.value))

    def test_read_on_invalid_padding(self):
        encoding = (
            b'\x42\x00\x00\x07\x00\x00\x00\x0B\x48\x65\x6C\x6C\x6F\x20\x57'
            b'\x6F\x72\x6C\x64\xff\xff\xff\xff\xff')
        self.stream = utils.BytearrayStream(encoding)
        ts = primitives.TextString()

        self.assertRaises(exceptions.ReadValueError, ts.read, self.stream)

    def test_write_value(self):
        encoding = (
            b'\x48\x65\x6C\x6C\x6F\x20\x57\x6F\x72\x6C\x64\x00\x00\x00\x00'
            b'\x00')
        self.stream = utils.BytearrayStream()
        value = 'Hello World'
        ts = primitives.TextString(value)
        ts.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_no_padding(self):
        encoding = (b'\x48\x65\x6C\x6C\x6F\x20\x57\x6F')
        self.stream = utils.BytearrayStream()
        value = 'Hello Wo'
        ts = primitives.TextString(value)
        ts.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_value_max_padding(self):
        encoding = (b'\x48\x00\x00\x00\x00\x00\x00\x00')
        self.stream = utils.BytearrayStream()
        value = 'H'
        ts = primitives.TextString(value)
        ts.write_value(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write(self):
        encoding = (
            b'\x42\x00\x00\x07\x00\x00\x00\x0B\x48\x65\x6C\x6C\x6F\x20\x57'
            b'\x6F\x72\x6C\x64\x00\x00\x00\x00\x00')
        self.stream = utils.BytearrayStream()
        value = 'Hello World'
        ts = primitives.TextString(value)
        ts.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv,
                         self.bad_length.format(len_exp, len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)
