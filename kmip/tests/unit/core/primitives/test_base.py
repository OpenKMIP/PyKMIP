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

import testtools

from kmip.core import exceptions
from kmip.core import primitives
from kmip.core import utils

class TestBase(testtools.TestCase):

    def setUp(self):
        super(TestBase, self).setUp()
        self.stream = utils.BytearrayStream()
        self.bad_init = 'Bad Base initialization: attribute {0} missing'
        self.bad_write = exceptions.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.Base.{0}', 'write', '{1}', '{2}')
        self.bad_encoding = exceptions.ErrorStrings.BAD_ENCODING.format(
            'primitives.Base.{0}', 'write')
        self.bad_match = exceptions.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.Base.{0}', 'comparison', '{1}', '{2}')

    def tearDown(self):
        super(TestBase, self).tearDown()

    def test_is_oversized(self):
        base = primitives.Base()
        base.is_oversized(self.stream)

    def test_is_oversized_error(self):
        self.stream.write(b'\x00')
        base = primitives.Base()
        self.assertRaises(
            exceptions.StreamNotEmptyError,
            base.is_oversized,
            self.stream
        )

    def test_read_tag(self):
        encoding = (b'\x42\x00\x00')
        base = primitives.Base()
        self.stream = utils.BytearrayStream(encoding)
        base.read_tag(self.stream)

    def test_read_tag_invalid(self):
        encoding = (b'\x42\x00\x01')
        base = primitives.Base()
        self.stream = utils.BytearrayStream(encoding)
        self.assertRaises(
            exceptions.ReadValueError,
            base.read_tag,
            self.stream
        )

    def test_read_type(self):
        self.stream.write(b'\x00')
        base = primitives.Base()
        base.read_type(self.stream)

    def test_read_type_error(self):
        self.stream.write(b'\x01')
        base = primitives.Base()
        self.assertRaises(
            exceptions.ReadValueError,
            base.read_type,
            self.stream
        )

    def test_read_type_underflow(self):
        base = primitives.Base()
        self.assertRaises(
            exceptions.ReadValueError,
            base.read_type,
            self.stream
        )

    def test_read_type_overflow(self):
        self.stream.write(b'\x00\x00')
        base = primitives.Base()
        base.read_type(self.stream)

    def test_read_length(self):
        self.stream.write(b'\x00\x00\x00\x04')
        base = primitives.Base()
        base.length = 4
        base.read_length(self.stream)

    def test_read_length_underflow(self):
        self.stream.write(b'\x00')
        base = primitives.Base()
        base.length = 4
        self.assertRaises(
            exceptions.ReadValueError,
            base.read_length,
            self.stream
        )

    def test_read_length_overflow(self):
        self.stream.write(b'\x00\x00\x00\x04\x00')
        base = primitives.Base()
        base.length = 4
        base.read_length(self.stream)

    def test_read_value(self):
        base = primitives.Base()
        self.assertRaises(
            NotImplementedError, base.read_value, self.stream)

    def test_read(self):
        self.stream.write(b'\x42\x00\x00\x00\x00\x00\x00\x04')
        base = primitives.Base()
        base.length = 4
        base.read(self.stream)

    def test_write_tag(self):
        encoding = (b'\x42\x00\x00')
        base = primitives.Base()
        base.write_tag(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(
            len_exp, len_rcv,
            self.bad_write.format(
                'tag', '{0} bytes'.format(len_exp),
                '{0} bytes'.format(len_rcv)))
        self.assertEqual(encoding, result, self.bad_encoding.format('tag'))

    def test_write_type(self):
        encoding = b'\x00'
        base = primitives.Base()
        base.write_type(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(
            len_exp, len_rcv,
            self.bad_write.format(
                'type', '{0} bytes'.format(len_exp),
                '{0} bytes'.format(len_rcv)))
        self.assertEqual(encoding, result, self.bad_encoding.format('type'))

    def test_write_type_invalid(self):
        base = primitives.Base()
        base.type = ''
        self.assertRaises(TypeError, base.write_type, self.stream)

    def test_write_length(self):
        encoding = b'\x00\x00\x00\x04'
        base = primitives.Base()
        base.length = 4
        base.write_length(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(
            len_exp, len_rcv,
            self.bad_write.format(
                'length', '{0} bytes'.format(len_exp),
                '{0} bytes'.format(len_rcv)))
        self.assertEqual(encoding, result, self.bad_encoding.format('length'))

    def test_write_length_invalid(self):
        base = primitives.Base()
        base.length = ''
        self.assertRaises(TypeError, base.write_length, self.stream)

    def test_write_length_overflow(self):
        self.skipTest(
            'No easy way to test with a number requiring more than '
            '2 ** 0xffffffff bytes for representation. Test preserved '
            'for completeness.'
        )

    def test_write_value(self):
        base = primitives.Base()
        self.assertRaises(
            NotImplementedError, base.write_value, self.stream)

    def test_write(self):
        encoding = b'\x42\x00\x00\x00\x00\x00\x00\x04'
        base = primitives.Base()
        base.length = 4
        base.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(
            len_exp, len_rcv,
            self.bad_write.format(
                'type/length', '{0} bytes'.format(len_exp),
                '{0} bytes'.format(len_rcv)))
        self.assertEqual(
            encoding, result, self.bad_encoding.format('type/length'))

    def test_is_tag_next(self):
        encoding = (b'\x42\x00\x00')
        base = primitives.Base()
        self.stream = utils.BytearrayStream(encoding)

        self.assertTrue(
            base.is_tag_next(base.tag, self.stream),
            self.bad_match.format('tag', 'match', 'mismatch'))

    def test_is_tag_next_invalid(self):
        encoding = (b'\x42\x00\x01')
        base = primitives.Base()
        self.stream = utils.BytearrayStream(encoding)

        self.assertFalse(
            base.is_tag_next(base.tag, self.stream),
            self.bad_match.format('tag', 'mismatch', 'match'))
